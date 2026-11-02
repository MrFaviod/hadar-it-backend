"""Explicit demo initializer and telemetry launcher; never an existing database."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

from itsm.database import create_engine_from_settings, create_session_factory
from itsm.demo import exporter, telemetry
from itsm.demo.lock import DemoDirectoryLock, DemoProcessConflict
from itsm.demo.reset import recover_demo
from itsm.demo.seed import seed
from itsm.demo.telemetry import demo_settings
from itsm.identity.service import IdentityError
from itsm.release_identity import enforce_startup, has_demo_marker, read_identity
from itsm.release_mode import RELEASE_MODE_ENV

DemoRefused = telemetry.DemoRefused


_FAILURES = {
    "init": "demo initialization failed; inspect owned directory",
    "setup": "demo telemetry setup failed; inspect the demo database",
    "exporter": "demo exporter failed; inspect the demo database",
    "recover": "demo recovery failed; inspect owned directory and demo.log",
}


def initialize(directory: Path, username: str) -> dict:
    if os.environ.get("ITSM_ENVIRONMENT", "development").lower() == "production":
        raise DemoRefused("demo initialization is forbidden in production")
    password = os.environ.get("ITSM_BOOTSTRAP_PASSWORD", "")
    if not password:
        raise DemoRefused("ITSM_BOOTSTRAP_PASSWORD is required")
    # Validate before reserving the directory; never inherit a configured database.
    directory = directory.absolute()
    with demo_settings(directory) as settings:
        pass  # Built without ambient ITSM_* values; keeps working after the scope exits.
    try:
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError:
        raise DemoRefused("demo directory must not already exist") from None
    env = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    env.update(ITSM_ENVIRONMENT="development", ITSM_DATABASE_URL=settings.database_url)
    migration = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if migration.returncode:
        # Leave owned state for diagnosis; never delete or reuse a partial install.
        raise DemoRefused("demo migration failed; use a new directory after diagnosis")
    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            # Seeding is a demo-mode write that also configures the first generation's
            # synthetic node monitoring, so it needs the owned directory in settings.
            payload = seed(
                session,
                settings.model_copy(update={"demo_data_directory": directory}),
                username,
                password,
            )
    finally:
        engine.dispose()
    return {
        **payload,
        "directory": str(directory),
        "databaseUrl": settings.database_url,
        "username": username,
    }


@contextlib.contextmanager
def _demo_release_mode() -> Iterator[None]:
    """Recovery is a demo-only operation; the database owner still has to agree."""
    previous = os.environ.get(RELEASE_MODE_ENV)
    os.environ[RELEASE_MODE_ENV] = "demo"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(RELEASE_MODE_ENV, None)
        else:
            os.environ[RELEASE_MODE_ENV] = previous


def recover(directory: Path) -> dict:
    """Clear a stuck reset flag and reseed; refuse anything that is not a demo.

    A failed reset persists ``resetting`` on purpose so a crash cannot resume on a
    partially deleted dataset. This command is the explicit maintainer recovery:
    it clears that flag, then reseeds through the same guarded reset the scheduler
    uses, so the demo serves again with a new generation.
    """
    directory = directory.absolute()
    if not (directory / "demo.db").is_file():
        raise DemoRefused("demo database does not exist")
    with demo_settings(directory) as base:
        settings = base.model_copy(
            update={
                "demo_data_directory": directory,
                "task_sqlite_path": directory / "tasks" / "huey.db",
                "attachment_storage_path": directory / "attachments",
            }
        )
    lock = DemoDirectoryLock(directory)
    try:
        lock.acquire()
    except DemoProcessConflict as conflict:
        raise DemoRefused(str(conflict)) from None
    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            owner = read_identity(session)
            marked = has_demo_marker(session)
        if owner is not None and owner.release_mode != "demo":
            raise DemoRefused("demo database belongs to another release mode")
        # A failed reset deletes the marker before it reseeds, so a claimed demo
        # owner is enough; a never-started installation is recognized by its marker.
        if owner is None and not marked:
            raise DemoRefused("demo database is not marked as a demonstration installation")
        # Claim or verify the demo owner, exactly like the API start does. An
        # installation created by `init` has no identity until its first start.
        enforce_startup(settings, engine=engine, environ={RELEASE_MODE_ENV: "demo"})
        with _demo_release_mode():
            payload = recover_demo(settings, engine)
    finally:
        engine.dispose()
        lock.release()
    return {"status": "recovered", "directory": str(directory), **payload}


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be a number") from None
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return port


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    command = subcommands.add_parser(
        "init", help="Create fictional data in a NEW private directory"
    )
    command.add_argument(
        "--directory",
        required=True,
        type=Path,
        help="New directory; existing paths are always refused",
    )
    command.add_argument("--username", required=True, help="Explicit first demo owner username")
    setup = subcommands.add_parser(
        "setup",
        help="Configure the demo exporter and node checks; optionally write scrape YAML",
    )
    setup.add_argument(
        "--directory", required=True, type=Path, help="Directory created by the init command"
    )
    setup.add_argument("--username", required=True, help="Existing demo owner username")
    setup.add_argument(
        "--output",
        type=Path,
        help="New file for the generated Prometheus configuration; existing files are refused",
    )
    setup.add_argument(
        "--exporter-port",
        type=_port,
        default=telemetry.DEFAULT_EXPORTER_PORT,
        help=f"Loopback port of the demo exporter (default {telemetry.DEFAULT_EXPORTER_PORT})",
    )
    serve = subcommands.add_parser(
        "exporter", help="Expose synthetic node metrics on 127.0.0.1 for a marked demo"
    )
    serve.add_argument(
        "--directory", required=True, type=Path, help="Directory created by the init command"
    )
    serve.add_argument(
        "--port",
        type=_port,
        default=telemetry.DEFAULT_EXPORTER_PORT,
        help="Loopback port to bind; 0 selects a free port and reports it",
    )
    recovered = subcommands.add_parser(
        "recover",
        help="Clear a reset that failed halfway and reseed a marked demo",
    )
    recovered.add_argument(
        "--directory", required=True, type=Path, help="Directory created by the init command"
    )
    args = parser.parse_args()
    try:
        if args.command == "init":
            payload = initialize(args.directory, args.username)
        elif args.command == "setup":
            password = os.environ.get("ITSM_BOOTSTRAP_PASSWORD", "")
            if not password:
                raise DemoRefused("ITSM_BOOTSTRAP_PASSWORD is required")
            payload = telemetry.configure(
                args.directory, args.username, password, args.output, args.exporter_port
            )
        elif args.command == "recover":
            payload = recover(args.directory)
        else:
            return exporter.serve(args.directory, args.port)
    except (DemoRefused, IdentityError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        message = str(exc) if isinstance(exc, DemoRefused) else _FAILURES[args.command]
        print(
            json.dumps({"status": "error", "code": "demo_refused", "message": message}),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
