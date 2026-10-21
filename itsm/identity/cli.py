"""Installation CLI for the identity module.

The CLI is the only supported way to create the first administrator and to
issue machine credentials. It never accepts a password as an argument, never
falls back to a default credential and never prints a password or a stored
hash. Passwords come from ``getpass`` on an interactive terminal or from the
``ITSM_BOOTSTRAP_PASSWORD`` process variable for unattended installations.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from getpass import getpass
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from itsm.config import Settings, get_settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.permissions import MACHINE_ACTOR_KINDS
from itsm.identity.service import (
    BootstrapRefused,
    Conflict,
    IdentityError,
    IdentityService,
    NotFound,
    PermissionDenied,
    ValidationFailed,
)

PASSWORD_VARIABLE = "ITSM_BOOTSTRAP_PASSWORD"
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def _emit(payload: dict[str, Any], *, ok: bool) -> None:
    stream = sys.stdout if ok else sys.stderr
    stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
    stream.flush()


def _fail(code: str, message: str, exit_code: int = EXIT_FAILED) -> int:
    _emit({"status": "error", "code": code, "message": message}, ok=False)
    return exit_code


def _read_password() -> str | None:
    """Password from the process environment or an interactive prompt."""
    from_env = os.environ.get(PASSWORD_VARIABLE)
    if from_env is not None:
        return from_env
    if not sys.stdin.isatty():
        return None
    first = getpass("Password: ")
    second = getpass("Repeat password: ")
    if first != second:
        return ""
    return first


def _open_service(settings: Settings) -> tuple[Any, IdentityService]:
    engine = create_engine_from_settings(settings)
    session = create_session_factory(engine)()
    return session, IdentityService(session, settings)


def _command_bootstrap_admin(args: argparse.Namespace, settings: Settings) -> int:
    password = _read_password()
    if password is None:
        return _fail(
            "password_required",
            f"set {PASSWORD_VARIABLE} or run this command on an interactive terminal",
            EXIT_USAGE,
        )
    if not password:
        return _fail("password_mismatch", "the two passwords do not match", EXIT_USAGE)

    session, service = _open_service(settings)
    try:
        view = service.bootstrap_admin(args.username, args.name, password)
    finally:
        session.close()

    _emit(
        {
            "status": "created",
            "action": "bootstrap-admin",
            "identity": {
                "id": view.id,
                "username": view.username,
                "name": view.name,
                "roleId": view.role_id,
                "active": view.active,
            },
        },
        ok=True,
    )
    return EXIT_OK


def _command_create_machine(args: argparse.Namespace, settings: Settings) -> int:
    session, service = _open_service(settings)
    try:
        identity = service.bootstrap_machine(
            username=args.username,
            name=args.name,
            actor_kind=args.actor_kind,
            role_id=args.role,
        )
        credential = service.issue_machine_credential(identity.username, args.label)
    finally:
        session.close()

    _emit(
        {
            "status": "created",
            "action": "create-machine-identity",
            "identity": {
                "id": identity.id,
                "username": identity.username,
                "roleId": identity.role_id,
                "actorKind": identity.actor_kind,
            },
            "token": credential.token,
            "tokenNotice": "store this token now; it is not recoverable",
        },
        ok=True,
    )
    return EXIT_OK


def _command_revoke_machine(args: argparse.Namespace, settings: Settings) -> int:
    session, service = _open_service(settings)
    try:
        revoked = service.revoke_machine_credentials(args.username)
    finally:
        session.close()

    _emit(
        {
            "status": "revoked",
            "action": "revoke-machine-token",
            "username": args.username,
            "revoked": revoked,
        },
        ok=True,
    )
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m itsm.identity.cli",
        description="Identity installation commands (they never store plaintext secrets).",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    bootstrap = commands.add_parser(
        "bootstrap-admin",
        help="create the first administrator; refused once a human identity exists",
    )
    bootstrap.add_argument("--username", required=True)
    bootstrap.add_argument("--name", required=True)
    bootstrap.set_defaults(handler=_command_bootstrap_admin)

    machine = commands.add_parser(
        "create-machine-identity",
        help="create a machine identity and print its bearer token exactly once",
    )
    machine.add_argument("--username", required=True)
    machine.add_argument("--name", required=True)
    machine.add_argument("--actor-kind", required=True, choices=list(MACHINE_ACTOR_KINDS))
    machine.add_argument("--role", required=True)
    machine.add_argument("--label", default="installation")
    machine.set_defaults(handler=_command_create_machine)

    revoke = commands.add_parser(
        "revoke-machine-token",
        help="revoke every active bearer credential of a machine identity",
    )
    revoke.add_argument("--username", required=True)
    revoke.set_defaults(handler=_command_revoke_machine)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "bootstrap-admin" and not (args.username and args.name):
        return _fail("invalid_arguments", "--username and --name are required", EXIT_USAGE)

    settings = get_settings()
    try:
        return int(args.handler(args, settings))
    except BootstrapRefused as exc:
        return _fail("bootstrap_refused", str(exc))
    except ValidationFailed as exc:
        return _fail("invalid_request", str(exc), EXIT_USAGE)
    except (Conflict, NotFound, PermissionDenied) as exc:
        return _fail(type(exc).__name__.lower(), str(exc))
    except IdentityError as exc:
        return _fail("identity_error", str(exc))
    except SQLAlchemyError:
        return _fail(
            "database_unavailable",
            "database unavailable or schema not migrated; run 'alembic upgrade head' first",
        )


if __name__ == "__main__":
    raise SystemExit(main())
