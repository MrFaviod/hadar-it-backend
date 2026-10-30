"""``python -m itsm.credentials``: key-ring status and rotation.

The command prints one JSON object per invocation. It reads the ring from the
process environment (``ITSM_AI_CREDENTIAL_KEYS`` and the legacy
``ITSM_AI_CREDENTIAL_KEY``) and the database through the application settings
authority. No key, plaintext credential or ciphertext is ever written to
stdout, stderr or a file.

Exit codes: ``0`` everything readable with the primary key, ``1`` at least one
stored credential is not readable (rotation reports it and leaves it untouched),
``2`` the command could not run (no ring, invalid configuration, database
unavailable).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from itsm.agent_integrations.providers import CredentialUnavailable
from itsm.config import get_settings
from itsm.credentials import service
from itsm.database import create_engine_from_settings, create_session_factory

EXIT_OK = 0
EXIT_UNREADABLE = 1
EXIT_FAILED = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m itsm.credentials",
        description="Report and rotate the AI provider credential key ring.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="count readable, older-key and unreadable ciphertext")
    rotate = commands.add_parser("rotate", help="re-encrypt every ciphertext with the primary key")
    rotate.add_argument("--dry-run", action="store_true", help="report without writing")
    return parser


def _emit(payload: dict[str, Any], stream: Any) -> None:
    stream.write(json.dumps(payload, sort_keys=True) + "\n")
    stream.flush()


def _fail(code: str, message: str) -> int:
    _emit({"status": "error", "code": code, "message": message}, sys.stderr)
    return EXIT_FAILED


def _dispatch(args: argparse.Namespace, session: Any, settings: Any) -> tuple[dict[str, Any], int]:
    if args.command == "status":
        payload = service.status(session, settings)
    else:
        payload = service.rotate(session, settings, dry_run=args.dry_run)
    return payload, EXIT_OK if payload["status"] == "ok" else EXIT_UNREADABLE


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = get_settings()
    except Exception:
        return _fail("configuration_invalid", "invalid ITSM_ configuration")
    engine = None
    try:
        engine = create_engine_from_settings(settings)
        with create_session_factory(engine)() as session:
            payload, exit_code = _dispatch(args, session, settings)
    except CredentialUnavailable as exc:
        return _fail("credential_storage_unavailable", str(exc))
    except SQLAlchemyError:
        return _fail(
            "database_unavailable",
            "database unavailable or schema not migrated; run 'alembic upgrade head' first",
        )
    finally:
        if engine is not None:
            engine.dispose()
    _emit(payload, sys.stdout)
    return exit_code


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
