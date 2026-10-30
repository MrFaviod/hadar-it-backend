"""``python -m itsm.devtools <command>``: init, status and safe dev resets.

Every command fails with exit code 1 and one actionable ``error:`` line when it
is refused; ``--verbose`` adds the traceback for an unexpected failure. The
successful payload is JSON on stdout so operators and tests read the same
interface.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import traceback
from typing import Any

from itsm.config import get_settings
from itsm.devtools import operations
from itsm.devtools.guard import PASSWORD_ENV, DevToolsRefused, dev_data_dir

DEFAULT_ADMIN_USERNAME = "dev.admin"
GENERATED_PASSWORD_BYTES = 24


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line surface."""
    verbose = argparse.ArgumentParser(add_help=False)
    verbose.add_argument(
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="print the traceback of a refusal or failure",
    )
    parser = argparse.ArgumentParser(
        prog="python -m itsm.devtools",
        description="Create, inspect and safely reset a development database (RELEASE_MODE=dev).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print the traceback of a refusal or failure",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser(
        "init",
        parents=[verbose],
        help="Migrate a new dev database, claim it for dev, create the admin and seed data",
    )
    init.add_argument("--username", default=DEFAULT_ADMIN_USERNAME, help="Dev superadmin username")

    commands.add_parser(
        "status",
        parents=[verbose],
        help="Report mode, database, identity, schema, counts and reset decision as JSON",
    )

    reset = commands.add_parser(
        "reset",
        parents=[verbose],
        help="Delete the dev data and reseed it; --regenerate recreates the SQLite file",
    )
    reset.add_argument("--username", default=DEFAULT_ADMIN_USERNAME, help="Dev superadmin username")
    reset.add_argument(
        "--regenerate",
        action="store_true",
        help="Recreate the whole SQLite file (or drop reflected tables) before seeding",
    )
    reset.add_argument(
        "--yes-reset-dev-database",
        action="store_true",
        help="Required: confirm that deleting this development database is intended",
    )
    reset.add_argument(
        "--confirm",
        default=None,
        metavar="NAME",
        help="Required: repeat the database name or SQLite file basename",
    )
    return parser


def _password() -> tuple[str, str]:
    """Return the admin password and where it came from."""
    provided = os.environ.get(PASSWORD_ENV, "").strip()
    if provided:
        return provided, "environment"
    return secrets.token_urlsafe(GENERATED_PASSWORD_BYTES), "generated"


def main(argv: list[str] | None = None) -> int:
    """Run one command and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    verbose = bool(getattr(args, "verbose", False))
    settings = get_settings()
    try:
        payload: dict[str, Any]
        if args.command == "status":
            payload = operations.inspect_database(settings)
        else:
            password, password_source = _password()
            if args.command == "init":
                payload = operations.initialize(
                    settings,
                    args.username,
                    password,
                    password_source=password_source,
                )
            else:
                payload = operations.reset(
                    settings,
                    args.username,
                    password,
                    password_source=password_source,
                    confirm=args.confirm,
                    regenerate=args.regenerate,
                    reset_flag=args.yes_reset_dev_database,
                    data_dir=dev_data_dir(),
                )
    except DevToolsRefused as exc:
        if verbose:
            traceback.print_exc()
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # unexpected failure: one actionable line, no stack by default
        if verbose:
            traceback.print_exc()
        print(
            f"error: unexpected {type(exc).__name__}; next: re-run with --verbose to see "
            "where the development command stopped",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
