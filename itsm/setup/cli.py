"""Operator CLI for the setup service.

The three commands are the only way to enable setup, rotate the one-time claim
credential and re-authorize a claimed installation:

``python -m itsm.setup.cli enable-claim``
``python -m itsm.setup.cli rotate-claim``
``python -m itsm.setup.cli recover``

The credential is printed once to the invoking terminal's stdout. It is never
written to the journal, never logged and never returned by an HTTP status.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from itsm.setup.store import (
    AlreadyClaimed,
    NotClaimed,
    SetupConfigurationError,
    SetupError,
    SetupSettings,
    SetupStore,
)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def _emit(payload: dict[str, Any], *, ok: bool) -> None:
    stream = sys.stdout if ok else sys.stderr
    stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
    stream.flush()


def _error(code: str, message: str, exit_code: int = EXIT_FAILED) -> int:
    _emit({"status": "error", "code": code, "message": message}, ok=False)
    return exit_code


def _store(args: argparse.Namespace, settings: SetupSettings) -> SetupStore:
    state_dir = args.state_dir or settings.state_dir
    store = SetupStore(state_dir, release_mode=settings.release_mode)
    store.ensure_ready()
    return store


def _command_enable_claim(args: argparse.Namespace, settings: SetupSettings) -> int:
    credential = _store(args, settings).enable_claim()
    _emit(
        {"status": "ok", "action": "enable-claim", "state": "unclaimed", "credential": credential},
        ok=True,
    )
    return EXIT_OK


def _command_rotate_claim(args: argparse.Namespace, settings: SetupSettings) -> int:
    credential = _store(args, settings).rotate_claim()
    _emit(
        {"status": "ok", "action": "rotate-claim", "state": "unclaimed", "credential": credential},
        ok=True,
    )
    return EXIT_OK


def _command_recover(args: argparse.Namespace, settings: SetupSettings) -> int:
    credential = _store(args, settings).issue_recovery()
    _emit(
        {"status": "ok", "action": "recover", "state": "claimed", "credential": credential},
        ok=True,
    )
    return EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m itsm.setup.cli")
    parser.add_argument(
        "--state-dir",
        default=None,
        help="private setup state directory (default: ITSM_SETUP_STATE_DIR)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    helps = {
        "enable-claim": "enable setup and print a one-time claim credential",
        "rotate-claim": "invalidate the claim credential and print a new one",
        "recover": "re-authorize a claimed setup without resetting it",
    }
    for name, help_text in helps.items():
        command = commands.add_parser(name, help=help_text)
        command.add_argument(
            "--state-dir",
            default=argparse.SUPPRESS,
            help="private setup state directory (default: ITSM_SETUP_STATE_DIR)",
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        settings = SetupSettings.from_environ()
        if args.command == "enable-claim":
            return _command_enable_claim(args, settings)
        if args.command == "rotate-claim":
            return _command_rotate_claim(args, settings)
        if args.command == "recover":
            return _command_recover(args, settings)
        return _error("unknown_command", "the requested command does not exist", EXIT_USAGE)
    except SetupConfigurationError as exc:
        return _error(exc.code, str(exc), EXIT_USAGE)
    except (AlreadyClaimed, NotClaimed) as exc:
        return _error(exc.code, str(exc))
    except SetupError as exc:
        return _error(exc.code, str(exc))
    except OSError as exc:
        return _error("state_directory_unavailable", str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
