"""``python -m itsm.ops`` command line for backup, restore and guarded upgrade.

All output is one JSON object per invocation. Credentials are read from the
process environment (``PGPASSWORD``, ``MYSQL_PWD`` semantics through a private
option file, ``SQLCMDPASSWORD``) and never appear on argv or in output; the
database locator is always redacted.

Operator settings for this tool (documented in ``docs/ops-backup-restore.md``):
``ITSM_OPS_BACKUP_ROOT``, ``ITSM_OPS_RETENTION_KEEP`` and
``ITSM_OPS_RETENTION_MAX_AGE_DAYS``. The database URL itself comes from the
application settings authority, ``ITSM_DATABASE_URL``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from itsm.config import get_settings
from itsm.ops import service, store, upgrade
from itsm.ops.engines import OpsError
from itsm.ops.service import OpsContext, RestoreRefused, UsageError

DEFAULT_BACKUP_ROOT = Path("/data/backups")
ENV_BACKUP_ROOT = "ITSM_OPS_BACKUP_ROOT"
ENV_RETENTION_KEEP = "ITSM_OPS_RETENTION_KEEP"
ENV_RETENTION_MAX_AGE_DAYS = "ITSM_OPS_RETENTION_MAX_AGE_DAYS"


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--backup-root",
        type=Path,
        default=None,
        help=f"artifact directory (default: ${ENV_BACKUP_ROOT} or {DEFAULT_BACKUP_ROOT})",
    )
    parser = argparse.ArgumentParser(
        prog="python -m itsm.ops",
        description="Backup, verify, restore, prune and guarded upgrade for ITSM databases.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("backup", parents=[common], help="create a new backup artifact")

    verify = commands.add_parser("verify", parents=[common], help="check one backup artifact")
    verify.add_argument("backup_id")

    restore = commands.add_parser(
        "restore", parents=[common], help="restore one verified backup into a new target"
    )
    restore.add_argument("backup_id")
    restore.add_argument("--target-file", default=None, help="new SQLite file to create")
    restore.add_argument("--target-database", default=None, help="new database to restore into")
    restore.add_argument(
        "--replace-live",
        action="store_true",
        help="replace the live database; requires --confirm <backup id>",
    )
    restore.add_argument("--confirm", default=None, help="backup id repeated as consent token")

    prune = commands.add_parser("prune", parents=[common], help="apply the retention policy")
    prune.add_argument("--keep", type=int, default=None, help="keep the last N backups")
    prune.add_argument(
        "--max-age-days", type=int, default=None, help="delete backups older than this many days"
    )
    prune.add_argument("--dry-run", action="store_true", help="report without deleting")

    commands.add_parser("status", parents=[common], help="report backup and upgrade status")
    commands.add_parser("upgrade", parents=[common], help="guarded upgrade to the code head")
    return parser


def _emit(payload: dict[str, Any], exit_code: int) -> int:
    stream = sys.stdout if exit_code == 0 else sys.stderr
    stream.write(json.dumps(payload, sort_keys=True) + "\n")
    return exit_code


def _env_int(name: str) -> int | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise UsageError(f"{name} must be an integer") from exc


def _resolve_root(argument: Path | None) -> Path:
    if argument is not None:
        return argument
    configured = os.environ.get(ENV_BACKUP_ROOT, "").strip()
    return Path(configured) if configured else DEFAULT_BACKUP_ROOT


def _dispatch(args: argparse.Namespace, context: OpsContext) -> tuple[dict[str, Any], int]:
    if args.command == "backup":
        artifact = service.backup(context)
        return (
            {
                "status": "ok",
                "backup": artifact.manifest.as_dict(),
                "path": str(artifact.directory),
            },
            0,
        )
    if args.command == "verify":
        payload = service.verify(context, args.backup_id)
        return payload, 0 if payload["verified"] else 1
    if args.command == "restore":
        payload = service.restore(
            context,
            args.backup_id,
            target_file=args.target_file,
            target_database=args.target_database,
            replace_live=args.replace_live,
            confirm=args.confirm,
        )
        return payload, 0
    if args.command == "prune":
        keep = args.keep if args.keep is not None else _env_int(ENV_RETENTION_KEEP)
        max_age = (
            args.max_age_days
            if args.max_age_days is not None
            else _env_int(ENV_RETENTION_MAX_AGE_DAYS)
        )
        return service.prune(context, keep=keep, max_age_days=max_age, dry_run=args.dry_run), 0
    if args.command == "status":
        return service.status(context), 0
    outcome = upgrade.run_upgrade(context)
    return outcome.payload, outcome.exit_code


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = get_settings()
    except Exception:
        return _emit({"status": "error", "error": "invalid ITSM_ configuration"}, 2)
    context = OpsContext(settings=settings, backup_root=_resolve_root(args.backup_root))
    try:
        payload, exit_code = _dispatch(args, context)
    except UsageError as exc:
        return _emit({"status": "error", "error": str(exc)}, 2)
    except (RestoreRefused, store.UpgraderBusy) as exc:
        return _emit({"status": "refused", "error": str(exc)}, 3)
    except OpsError as exc:
        return _emit(
            {"status": "failed", "error": store.sanitize(str(exc), settings.sensitive_values())}, 1
        )
    except Exception as exc:
        return _emit(
            {
                "status": "failed",
                "error": store.sanitize(
                    f"unexpected ops failure: {exc}", settings.sensitive_values()
                ),
            },
            1,
        )
    return _emit(payload, exit_code)


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
