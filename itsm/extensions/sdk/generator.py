"""Generate working SDK v2 extension packages.

Two real templates are rendered: a sandboxed module with operations, a
collection, a schema migration, declarative host-rendered views and Python
tests, and a declarative module with no executable code at all. Neither carries
license or product-specific behavior.
"""

from __future__ import annotations

import json
import re
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contract import ID_PATTERN, VERSION_PATTERN, validate_manifest
from .package import PackageError, build_package

TEMPLATE_ROOT = Path(__file__).resolve().parent / "templates"
TEMPLATES = {
    "sandboxed": TEMPLATE_ROOT / "record_registry",
    "declarative": TEMPLATE_ROOT / "notes_declarative",
}
RUNTIMES = tuple(TEMPLATES)


@dataclass(frozen=True)
class GeneratedPackage:
    files: dict[str, str]
    manifest: dict[str, Any]
    digest: str


def _clean(value: str, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field} is required")
    if len(cleaned) > maximum:
        raise ValueError(f"{field} must be at most {maximum} characters")
    if any(ord(character) < 32 for character in cleaned):
        raise ValueError(f"{field} must not contain control characters")
    return cleaned


def _json_fragment(value: str) -> str:
    """Escape a value for a JSON or YAML double-quoted string."""
    return json.dumps(value, ensure_ascii=False)[1:-1]


def generate_package(
    *,
    extension_id: str,
    name: str,
    description: str,
    version: str = "1.0.0",
    runtime: str = "sandboxed",
    known_core_permissions: Collection[str] = (),
) -> GeneratedPackage:
    """Render a complete package, validating it before returning any bytes."""
    if runtime not in TEMPLATES:
        raise ValueError(f"runtime must be one of {', '.join(RUNTIMES)}")
    template = TEMPLATES[runtime]
    if not isinstance(extension_id, str) or not ID_PATTERN.fullmatch(extension_id):
        raise ValueError("extension id must be lowercase words joined by hyphens")
    if len(extension_id) < 2 or len(extension_id) > 48:
        raise ValueError("extension id must be between 2 and 48 characters")
    clean_name = _clean(name, "name", 120)
    clean_description = _clean(description, "description", 1024)
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        raise ValueError("version must be strict X.Y.Z")

    substitutions = {
        "{{EXT_ID}}": extension_id,
        "{{EXT_NAME}}": _json_fragment(clean_name),
        "{{EXT_DESCRIPTION}}": _json_fragment(clean_description),
        "{{EXT_VERSION}}": version,
        "{{PERMISSION_PREFIX}}": f"ext_{extension_id.replace('-', '_')}.",
    }
    files: dict[str, str] = {}
    for source in sorted(template.rglob("*")):
        if not source.is_file():
            continue
        relative = source.relative_to(template).as_posix()
        if relative.startswith("skills/"):
            # Every template skill directory becomes the module's own skill.
            relative = f"skills/{extension_id}/" + relative.rsplit("/", 1)[-1]
        content = source.read_text(encoding="utf-8")
        for token, value in substitutions.items():
            content = content.replace(token, value)
        files[relative] = content

    manifest = json.loads(files["extension.json"])
    validate_manifest(manifest, known_core_permissions=known_core_permissions)
    built = build_package(files, known_core_permissions=known_core_permissions)
    return GeneratedPackage(files=files, manifest=manifest, digest=built.digest)


def write_package(target: Path, package: GeneratedPackage) -> list[str]:
    """Write a generated package once; never merge into an existing target."""
    target = Path(target)
    if target.exists():
        raise PackageError(f"target already exists: {target}")
    target.mkdir(parents=True, exist_ok=False)
    try:
        for relative in sorted(package.files):
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(package.files[relative], encoding="utf-8")
    except Exception:
        for child in sorted(target.rglob("*"), reverse=True):
            if child.is_file() or child.is_symlink():
                child.unlink(missing_ok=True)
            elif child.is_dir():
                child.rmdir()
        target.rmdir()
        raise
    return sorted(package.files)


def package_id(extension_id: str) -> str:
    """Return the exact permission prefix used by generated packages."""
    return f"ext_{extension_id.replace('-', '_')}."


def is_valid_id(extension_id: str) -> bool:
    return (
        isinstance(extension_id, str)
        and 2 <= len(extension_id) <= 48
        and re.fullmatch(ID_PATTERN.pattern, extension_id) is not None
    )
