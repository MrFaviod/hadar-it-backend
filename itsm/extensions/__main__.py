"""Offline extension SDK CLI: generate, pack, inspect and validate."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from itsm.extensions.sdk.contract import ManifestError
from itsm.extensions.sdk.generator import generate_package, write_package
from itsm.extensions.sdk.package import PackageError, build_package, parse_package, read_workspace
from itsm.extensions.validator import ContainerValidator, ValidatorUnavailable, serve_validator


def _known_core() -> tuple[str, ...]:
    from itsm.identity.permissions import PERMISSION_CODES

    return tuple(sorted(PERMISSION_CODES))


def _emit(value: Any) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")


def _generate(args: argparse.Namespace) -> int:
    package = generate_package(
        extension_id=args.id,
        name=args.name,
        description=args.description,
        version=args.version,
        known_core_permissions=_known_core(),
    )
    target = Path(args.target)
    write_package(target, package)
    _emit(
        {
            "id": package.manifest["id"],
            "version": package.manifest["version"],
            "digest": package.digest,
            "files": sorted(package.files),
            "target": str(target),
        }
    )
    return 0


def _pack(args: argparse.Namespace) -> int:
    files = read_workspace(Path(args.target))
    built = build_package(files, known_core_permissions=_known_core())
    output = Path(args.output)
    if output.exists():
        raise PackageError(f"output already exists: {output}")
    output.write_bytes(built.data)
    _emit(
        {
            "digest": built.digest,
            "bytes": len(built.data),
            "files": sorted(files),
            "output": str(output),
        }
    )
    return 0


def _inspect(args: argparse.Namespace) -> int:
    data = Path(args.archive).read_bytes()
    built = parse_package(data, known_core_permissions=_known_core())
    _emit(
        {
            "digest": built.digest,
            "manifest": built.manifest,
            "files": sorted(built.files),
        }
    )
    return 0


def _validate(args: argparse.Namespace) -> int:
    data = Path(args.archive).read_bytes()
    validator = ContainerValidator(
        core_permissions=_known_core(),
        image=args.image,
    )
    report = validator.validate(data)
    _emit(report)
    return 0 if report.get("status") == "passed" else 1


def _serve(args: argparse.Namespace) -> int:
    token = os.environ.get("ITSM_EXTENSION_VALIDATOR_BROKER_TOKEN", "")
    validator = ContainerValidator(
        core_permissions=_known_core(), image=args.image,
        timeout=args.timeout,
    )
    serve_validator(
        validator=validator, token=token, host=args.listen, port=args.port,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m itsm.extensions",
        description=(
            "Generate, pack, inspect and validate trusted native ITMS extensions. "
            "Validation uses the fixed offline container; serve-validator exposes "
            "only its authenticated fixed protocol and never installs a package."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("generate", help="write the working example package")
    generate.add_argument("target")
    generate.add_argument("--id", required=True, dest="id")
    generate.add_argument("--name", required=True)
    generate.add_argument("--description", required=True)
    generate.add_argument("--version", default="1.0.0")
    generate.set_defaults(handler=_generate)

    pack = commands.add_parser("pack", help="build an immutable package archive")
    pack.add_argument("target")
    pack.add_argument("--output", required=True)
    pack.set_defaults(handler=_pack)

    inspect = commands.add_parser("inspect", help="print a package manifest and digest")
    inspect.add_argument("archive")
    inspect.set_defaults(handler=_inspect)

    validate = commands.add_parser(
        "validate", help="run the fixed offline validator container"
    )
    validate.add_argument("archive")
    validate.add_argument("--image", default="itsm-extension-validator:1")
    validate.set_defaults(handler=_validate)

    serve = commands.add_parser(
        "serve-validator", help="serve the fixed authenticated host validation broker"
    )
    serve.add_argument("--listen", default="127.0.0.1", help="trusted bind address (default: loopback)")
    serve.add_argument("--port", type=int, default=8766)
    serve.add_argument("--image", default="itsm-extension-validator:1")
    serve.add_argument("--timeout", type=float, default=60)
    serve.set_defaults(handler=_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except ValidatorUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except (ManifestError, PackageError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
