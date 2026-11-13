"""Explicit mode preparation and periodic backups; never invoked by API startup."""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import secrets
import time
from pathlib import Path

from sqlalchemy import func, inspect, select
from sqlalchemy.orm import Session

from itsm.config import get_settings
from itsm.database import create_engine_from_settings
from itsm.devtools.database import migrate_to_head
from itsm.identity.models import Identity
from itsm.logging import log_event
from itsm.ops import service, upgrade
from itsm.ops.engines import OpsError
from itsm.release_identity import (
    DeploymentIdentityError,
    enforce_startup,
)
from itsm.release_mode import read_release_mode

logger = logging.getLogger(__name__)


def prepare() -> dict:
    """Prepare one installation before API/worker; never migrate foreign ownership."""
    mode = read_release_mode()
    settings = get_settings()
    engine = create_engine_from_settings(settings)
    try:
        # Check ownership before any migration or seed writes.
        enforce_startup(settings, engine=engine)
        if mode == "dev":
            from itsm.devtools.operations import initialize

            password = os.environ.get("ITSM_DEV_ADMIN_PASSWORD", "")
            if password:
                initialize(settings, "dev.admin", password, password_source="environment")
            else:
                # No seed password: migrate and claim the empty database only. The
                # instance stays ownerless so the setup wizard can create its owner.
                migrate_to_head(settings)
                log_event(
                    logger,
                    "deployment.dev.ownerless_setup_wizard",
                    level=logging.WARNING,
                    hint=(
                        "instance is unclaimed; finish onboarding in the setup wizard "
                        "(set ITSM_DEV_ADMIN_PASSWORD only for headless seeding)"
                    ),
                )
        else:
            tables = inspect(engine).get_table_names()
            if tables:
                context = service.OpsContext(
                    settings, Path(os.environ.get("ITSM_OPS_BACKUP_ROOT", "/data/backups"))
                )
                outcome = upgrade.run_upgrade(context)
                if outcome.exit_code:
                    raise DeploymentIdentityError(
                        "guarded upgrade failed; inspect ops status and backup artifacts"
                    )
            else:
                migrate_to_head(settings)
            enforce_startup(settings, engine=engine, require_identity=True)
            if mode == "demo":
                from itsm.demo.cycle import cycle_status
                from itsm.demo.reset import validate_reset_paths
                from itsm.demo.seed import seed

                validate_reset_paths(settings)
                with Session(engine) as session:
                    if not session.scalar(select(func.count()).select_from(Identity)):
                        seed(session, settings, "admin", secrets.token_urlsafe(32))
                    cycle_status(session)
        enforce_startup(settings, engine=engine, require_identity=True)
        return {"status": "ready", "mode": mode}
    finally:
        engine.dispose()


def _ops_status_path() -> Path | None:
    """Optional external copy of the published summary; absolute and pre-provisioned."""
    raw = os.environ.get("ITSM_OPS_STATUS_PATH", "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        raise DeploymentIdentityError("ITSM_OPS_STATUS_PATH must be an absolute path")
    return path


def backup_cycle() -> dict:
    """Produce and verify a recoverable artifact, apply retention and publish."""
    if read_release_mode() != "prod":
        raise DeploymentIdentityError("scheduled backups require RELEASE_MODE=prod")
    settings = get_settings()
    enforce_startup(settings, require_identity=True)
    context = service.OpsContext(
        settings,
        Path(os.environ.get("ITSM_OPS_BACKUP_ROOT", "/data/backups")),
        status_path=_ops_status_path(),
    )
    try:
        artifact = service.backup(context)
    except OpsError:
        # Record the failure and publish the last healthy artifact's real state.
        with contextlib.suppress(OpsError, OSError):
            service.publish_status(context)
        raise
    verified = service.verify(context, artifact.manifest.id)
    if not verified["verified"]:
        with contextlib.suppress(OpsError, OSError):
            service.publish_status(context)
        raise DeploymentIdentityError("backup verification failed; retention not applied")
    service.prune(
        context,
        keep=int(os.environ.get("ITSM_OPS_RETENTION_KEEP", "7")),
        max_age_days=None,
        dry_run=False,
    )
    service.publish_status(context)
    return {"status": "ok", "backupId": artifact.manifest.id}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "backup-loop"))
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            print(json.dumps(prepare()))
            return 0
        interval = int(os.environ.get("ITSM_OPS_BACKUP_INTERVAL_SECONDS", "86400"))
        if interval < 60:
            raise ValueError("backup interval must be at least 60 seconds")
        while True:
            print(json.dumps(backup_cycle()), flush=True)
            time.sleep(interval)
    except Exception:
        # Never leak SQL URLs, passwords or tool stderr from an automation wrapper.
        print(
            json.dumps(
                {
                    "status": "failed",
                    "message": "mode preparation or backup failed; inspect scoped ops status",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
