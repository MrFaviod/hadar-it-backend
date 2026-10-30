"""Guarded production upgrade: preflight, verified backup, migrate, verify.

The runner never downgrades. On any failure it stops, keeps the database as it
is, records the outcome and reports the exact command that restores the
pre-upgrade backup. A failed upgrade process therefore blocks the API start
instead of leaving an unknown schema behind.
"""

from __future__ import annotations

import shlex
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from alembic import command
from alembic.script import ScriptDirectory
from sqlalchemy import text

from itsm.database import (
    DatabaseUnavailable,
    alembic_config,
    create_engine_from_settings,
)
from itsm.ops import engines, service, store
from itsm.ops.engines import DatabaseTarget, OpsError

MIN_FREE_BYTES = service.MIN_FREE_BYTES
SOURCE_SPACE_MULTIPLIER = service.SOURCE_SPACE_MULTIPLIER


@dataclass(frozen=True)
class UpgradeOutcome:
    """Machine-readable outcome plus the process exit code."""

    payload: dict[str, Any]
    exit_code: int


def _script(settings: Any) -> ScriptDirectory:
    return ScriptDirectory.from_config(alembic_config(settings))


def _reachable(script: ScriptDirectory, head: str) -> set[str]:
    return {revision.revision for revision in script.iterate_revisions(head, "base")}


def _preflight(
    context: service.OpsContext, target: DatabaseTarget, script: ScriptDirectory
) -> tuple[str | None, str | None, str | None]:
    """Return ``(current, head, error)`` without changing anything."""
    head = script.get_current_head()
    if head is None:  # pragma: no cover - defensive
        return None, head, "the code has no Alembic head revision"
    if target.engine == "sqlite" and not Path(target.database).is_file():
        return None, head, f"database file not found: {target.describe()}"
    if target.engine == "sqlite":
        current = service.try_revision(context.settings, target)
    else:
        try:
            current = service.database_revision(context.settings)
        except OpsError as exc:
            return None, head, f"database preflight failed for {target.describe()}: {exc}"
    if current is None:
        return current, head, f"no applied Alembic revision in {target.describe()}"
    try:
        known = script.get_revision(current) is not None
        reachable = _reachable(script, head) if known else set()
    except Exception:
        known, reachable = False, set()
    if not known:
        return (
            current,
            head,
            f"applied revision {current} is unknown to this code; the database may be newer",
        )
    if current not in reachable:
        return (
            current,
            head,
            f"applied revision {current} is not an ancestor of head {head}; "
            "the database may be newer than this code",
        )
    return current, head, None


def _disk_space(context: service.OpsContext, target: DatabaseTarget) -> str | None:
    root = context.backup_root
    try:
        free = shutil.disk_usage(root).free
    except OSError as exc:
        return f"cannot inspect free space for {root}: {exc}"
    required = max(MIN_FREE_BYTES, service.source_size(target) * SOURCE_SPACE_MULTIPLIER)
    if free < required:
        return (
            f"insufficient free space for a verified backup: {free} bytes available, "
            f"{required} bytes required"
        )
    return None


def restore_command(context: service.OpsContext, artifact: store.BackupArtifact) -> str:
    """Build the exact command that restores this backup."""
    identifier = artifact.manifest.id
    parts = [
        "python -m itsm.ops restore",
        identifier,
        "--backup-root",
        str(context.backup_root),
    ]
    target = engines.database_target(context.settings.database_url)
    if target.engine == "sqlite":
        live = Path(Path(target.database)).resolve()
        parts += ["--target-file", str(live), "--replace-live", "--confirm", identifier]
    elif target.engine == "postgresql":
        parts += ["--replace-live", "--confirm", identifier]
    else:
        parts += ["--target-database", f"{target.database}_restore"]
    return shlex.join(parts)


def _smoke(context: service.OpsContext) -> dict[str, int]:
    """Prove the upgraded schema is readable through the application engine."""
    engine = create_engine_from_settings(context.settings)
    try:
        with engine.connect() as connection:
            return {
                "identityIdentities": int(
                    connection.execute(
                        text("SELECT COUNT(*) FROM identity_identities")
                    ).scalar_one()
                ),
                "assets": int(connection.execute(text("SELECT COUNT(*) FROM assets")).scalar_one()),
            }
    except Exception as exc:
        raise OpsError(f"post-upgrade smoke read failed: {exc}") from exc
    finally:
        engine.dispose()


def _fail(
    context: service.OpsContext,
    target: DatabaseTarget,
    payload: dict[str, Any],
    *,
    secrets: tuple[str, ...],
) -> UpgradeOutcome:
    store.record_upgrade(
        context.backup_root, payload, engine=target.engine, database=target.describe()
    )
    store.record_failure(
        context.backup_root,
        operation="upgrade",
        reason=str(payload.get("error", "upgrade failed")),
        engine=target.engine,
        database=target.describe(),
        secrets=secrets,
    )
    return UpgradeOutcome(payload=payload, exit_code=1)


def run_upgrade(
    context: service.OpsContext,
    *,
    apply_migrations: Callable[[], None] | None = None,
    now: datetime | None = None,
) -> UpgradeOutcome:
    """Run the guarded upgrade, or report that the database is already current."""
    target = context.target()
    secrets = (target.password,) if target.password else ()
    try:
        lock = store.acquire_lock(context.backup_root, now=now)
    except store.UpgraderBusy as exc:
        store.record_failure(
            context.backup_root,
            operation="upgrade",
            reason=str(exc),
            engine=target.engine,
            database=target.describe(),
            secrets=secrets,
        )
        return UpgradeOutcome(payload={"status": "refused", "error": str(exc)}, exit_code=3)
    except OpsError as exc:
        return UpgradeOutcome(
            payload={
                "status": "failed",
                "stage": "preflight",
                "error": f"backup root is not usable: {exc}",
                "message": "no migration was attempted; data preserved",
            },
            exit_code=1,
        )
    try:
        return _upgrade_locked(context, target, apply_migrations=apply_migrations)
    finally:
        store.release_lock(lock)


def _upgrade_locked(
    context: service.OpsContext,
    target: DatabaseTarget,
    *,
    apply_migrations: Callable[[], None] | None,
) -> UpgradeOutcome:
    root = context.backup_root
    secrets = (target.password,) if target.password else ()
    script = _script(context.settings)
    current, head, error = _preflight(context, target, script)
    if error is not None:
        return _fail(
            context,
            target,
            {
                "status": "failed",
                "stage": "preflight",
                "currentRevision": current,
                "headRevision": head,
                "error": error,
                "message": "no migration was attempted; data preserved",
            },
            secrets=secrets,
        )
    if current == head:
        payload = {
            "status": "up to date",
            "currentRevision": current,
            "headRevision": head,
            "backupId": None,
            "restoreCommand": None,
        }
        store.record_upgrade(root, payload, engine=target.engine, database=target.describe())
        return UpgradeOutcome(payload=payload, exit_code=0)

    space_error = _disk_space(context, target)
    if space_error is not None:
        return _fail(
            context,
            target,
            {
                "status": "failed",
                "stage": "preflight",
                "currentRevision": current,
                "headRevision": head,
                "error": space_error,
                "message": "no migration was attempted; data preserved",
            },
            secrets=secrets,
        )

    try:
        artifact = service.backup(context)
    except OpsError as exc:
        return _fail(
            context,
            target,
            {
                "status": "failed",
                "stage": "backup",
                "currentRevision": current,
                "headRevision": head,
                "error": store.sanitize(str(exc), secrets),
                "message": "no migration was attempted; data preserved",
            },
            secrets=secrets,
        )
    verification = service.verify(context, artifact.manifest.id)
    restore = restore_command(context, artifact)
    if not verification["verified"]:
        return _fail(
            context,
            target,
            {
                "status": "failed",
                "stage": "backup",
                "currentRevision": current,
                "headRevision": head,
                "backupId": artifact.manifest.id,
                "backupPath": str(artifact.directory),
                "restoreCommand": restore,
                "error": f"pre-upgrade backup failed verification: {verification['error']}",
                "message": "no migration was attempted; data preserved",
            },
            secrets=secrets,
        )

    try:
        if apply_migrations is None:
            command.upgrade(alembic_config(context.settings), "head")
        else:
            apply_migrations()
    except Exception as exc:
        observed = service.try_revision(context.settings, target)
        return _fail(
            context,
            target,
            {
                "status": "failed",
                "stage": "migration",
                "fromRevision": current,
                "observedRevision": observed,
                "headRevision": head,
                "backupId": artifact.manifest.id,
                "backupPath": str(artifact.directory),
                "restoreCommand": restore,
                "error": store.sanitize(f"migration failed: {exc}", secrets),
                "message": (
                    "upgrade stopped; no automatic downgrade was attempted; data preserved"
                ),
            },
            secrets=secrets,
        )

    observed = service.try_revision(context.settings, target)
    if observed != head:
        return _fail(
            context,
            target,
            {
                "status": "failed",
                "stage": "verification",
                "fromRevision": current,
                "observedRevision": observed,
                "headRevision": head,
                "backupId": artifact.manifest.id,
                "backupPath": str(artifact.directory),
                "restoreCommand": restore,
                "error": f"migration left revision {observed} instead of head {head}",
                "message": "upgrade stopped; data preserved",
            },
            secrets=secrets,
        )
    try:
        smoke = _smoke(context)
    except (OpsError, DatabaseUnavailable, OSError) as exc:
        return _fail(
            context,
            target,
            {
                "status": "failed",
                "stage": "smoke",
                "fromRevision": current,
                "observedRevision": observed,
                "headRevision": head,
                "backupId": artifact.manifest.id,
                "backupPath": str(artifact.directory),
                "restoreCommand": restore,
                "error": store.sanitize(str(exc), secrets),
                "message": "upgrade reached head but the smoke read failed; data preserved",
            },
            secrets=secrets,
        )

    payload = {
        "status": "upgraded",
        "fromRevision": current,
        "toRevision": observed,
        "headRevision": head,
        "backupId": artifact.manifest.id,
        "backupPath": str(artifact.directory),
        "restoreCommand": restore,
        "smoke": smoke,
    }
    store.record_upgrade(root, payload, engine=target.engine, database=target.describe())
    return UpgradeOutcome(payload=payload, exit_code=0)
