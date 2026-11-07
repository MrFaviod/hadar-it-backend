"""Single JSON Schema and semantic contract for extension manifest v1.

The schema is a package resource so the host and the fixed validator container
load exactly the same bytes. This module depends only on ``jsonschema`` and the
standard library; it never imports host services.
"""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SDK_VERSION = 1
MAX_ERRORS = 40
ID_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
HANDLER_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
COMPONENT_PATTERN = re.compile(r"^[A-Z][A-Za-z0-9]{1,63}$")
PERMISSION_SUFFIX_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SKILL_PATH_PATTERN = re.compile(r"^skills/([a-z][a-z0-9]*(?:-[a-z0-9]+)*)/SKILL\.md$")


class ManifestError(ValueError):
    """A bounded set of manifest contract violations."""

    def __init__(self, errors: Collection[str]) -> None:
        self.errors = tuple(dict.fromkeys(str(error) for error in errors))[:MAX_ERRORS]
        super().__init__("; ".join(self.errors))


class ArgumentError(ValueError):
    """Operation arguments do not match the declared JSON parameter schema."""


def schema_path() -> Path:
    return Path(__file__).resolve().parent / "schema" / "extension.schema.json"


def load_schema() -> dict[str, Any]:
    with schema_path().open(encoding="utf-8") as handle:
        schema = json.load(handle)
    if not isinstance(schema, dict):
        raise RuntimeError("extension schema resource is not an object")
    return schema


def permission_prefix(extension_id: str) -> str:
    return f"ext_{extension_id.replace('-', '_')}."


def _path(error: Any) -> str:
    parts = [str(part) for part in error.absolute_path]
    return ".".join(parts) if parts else "<manifest>"


def _schema_errors(manifest: Any) -> list[str]:
    errors: list[str] = []
    validator = Draft202012Validator(load_schema())
    for error in sorted(validator.iter_errors(manifest), key=lambda item: list(item.absolute_path)):
        if error.validator == "additionalProperties":
            errors.append(f"{_path(error)}: unknown field ({error.message})")
        else:
            errors.append(f"{_path(error)}: {error.message}")
        if len(errors) >= MAX_ERRORS:
            break
    return errors


def _text(value: Any, label: str, *, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    if len(value) > max_length:
        raise ValueError(f"{label} must be at most {max_length} characters")
    if "\x00" in value:
        raise ValueError(f"{label} must not contain NUL")
    return value


def _unique(values: list[str], label: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"duplicate {label}: {value}")
        seen.add(value)


def _validate_parameters(parameters: Mapping[str, Any], operation: str) -> None:
    properties = parameters.get("properties", {})
    required = parameters.get("required", [])
    if not isinstance(properties, Mapping):
        raise ValueError(f"operation {operation}: properties must be an object")
    if not isinstance(required, list):
        raise ValueError(f"operation {operation}: required must be an array")
    for name in required:
        if name not in properties:
            raise ValueError(
                f"operation {operation}: required argument {name!r} is not declared"
            )
    if parameters.get("additionalProperties", False) is not True:
        if len(required) != len(set(required)):
            raise ValueError(f"operation {operation}: required arguments must be unique")


def _semantic_errors(
    manifest: Mapping[str, Any], known_core_permissions: Collection[str]
) -> list[str]:
    errors: list[str] = []
    try:
        extension_id = manifest["id"]
        prefix = permission_prefix(extension_id)
        permissions = manifest["permissions"]
        codes = [item["code"] for item in permissions]
        _unique(codes, "permission code")
        for item in permissions:
            code = item["code"]
            label = _text(item["label"], f"permission {code} label", max_length=120)
            _text(item["description"], f"permission {code} description", max_length=512)
            if not code.startswith(prefix):
                errors.append(
                    f"permission {code}: must start with declared namespace {prefix}"
                )
            suffix = code[len(prefix) :] if code.startswith(prefix) else ""
            if not PERMISSION_SUFFIX_PATTERN.fullmatch(suffix):
                errors.append(
                    f"permission {code}: suffix must match {PERMISSION_SUFFIX_PATTERN.pattern}"
                )
            if not label:
                errors.append(f"permission {code}: label is required")

        known = set(known_core_permissions)
        for code in manifest["corePermissions"]:
            if code not in known:
                errors.append(f"core permission {code}: unknown core permission")
            if code.startswith("ext_") or code.startswith(prefix):
                errors.append(f"core permission {code}: cannot shadow an extension permission")
        _unique(list(manifest["corePermissions"]), "core permission")

        operation_names: list[str] = []
        for operation in manifest["operations"]:
            name = operation["name"]
            operation_names.append(name)
            _text(operation["description"], f"operation {name} description", max_length=1024)
            if operation["permission"] not in codes:
                errors.append(
                    f"operation {name}: permission {operation['permission']} is not declared permission"
                )
            try:
                _validate_parameters(operation["parameters"], name)
            except ValueError as exc:
                errors.append(str(exc))
        _unique(operation_names, "operation name")

        collection_names: list[str] = []
        for collection in manifest["collections"]:
            collection_names.append(collection["name"])
            _text(
                collection["description"],
                f"collection {collection['name']} description",
                max_length=512,
            )
        _unique(collection_names, "collection name")

        schedule_names: list[str] = []
        handler_names: list[str] = []
        for schedule in manifest["schedules"]:
            schedule_names.append(schedule["name"])
            handler_names.append(schedule["handler"])
            if schedule["permission"] not in codes:
                errors.append(
                    f"schedule {schedule['name']}: permission "
                    f"{schedule['permission']} is not declared permission"
                )
        _unique(schedule_names, "schedule name")
        _unique(handler_names, "schedule handler")

        schema_version = manifest["schemaVersion"]
        compatible = manifest["compatibleSchemaVersions"]
        _unique([str(item) for item in compatible], "compatible schema version")
        if schema_version not in compatible:
            errors.append("schemaVersion must be listed in compatibleSchemaVersions")
        if min(compatible) > schema_version:
            errors.append("compatibleSchemaVersions cannot start above schemaVersion")

        migrations = manifest["migrations"]
        ordered = sorted(migrations, key=lambda item: item["from"])
        if migrations != ordered:
            errors.append("migration revisions must be ordered by from")
        migration_handlers: list[str] = []
        for migration in migrations:
            migration_handlers.append(migration["handler"])
            if migration["from"] >= migration["to"]:
                errors.append(
                    f"migration {migration['handler']}: from must be lower than to"
                )
            if migration["from"] not in compatible:
                errors.append(
                    f"migration {migration['handler']}: from {migration['from']} "
                    "is not a compatible schema version"
                )
        _unique([str(item["from"]) for item in migrations], "migration from")
        _unique(migration_handlers, "migration handler")
        if migrations:
            if migrations[0]["from"] != min(compatible):
                errors.append("first migration must start at the earliest compatible version")
            if migrations[-1]["to"] != schema_version:
                errors.append("last migration must reach schemaVersion")

        frontend = manifest["frontend"]
        contribution_ids: list[str] = []
        for collection_name, key in (("page", "pages"), ("asset panel", "assetPanels")):
            for contribution in frontend[key]:
                contribution_ids.append(contribution["id"])
                if contribution["permission"] not in codes:
                    errors.append(
                        f"{collection_name} {contribution['id']}: permission "
                        f"{contribution['permission']} is not declared permission"
                    )
                if not COMPONENT_PATTERN.fullmatch(contribution["component"]):
                    errors.append(
                        f"{collection_name} {contribution['id']}: invalid component name"
                    )
                _text(
                    contribution["label"],
                    f"{collection_name} {contribution['id']} label",
                    max_length=120,
                )
        _unique(contribution_ids, "frontend contribution id")

        skill_names: list[str] = []
        skill_paths: list[str] = []
        for skill in manifest["skills"]:
            skill_names.append(skill["name"])
            skill_paths.append(skill["path"])
            match = SKILL_PATH_PATTERN.fullmatch(skill["path"])
            if match is None or match.group(1) != skill["name"]:
                errors.append(
                    f"skill {skill['name']}: path must be skills/{skill['name']}/SKILL.md"
                )
            _text(
                skill["description"],
                f"skill {skill['name']} description",
                max_length=1024,
            )
        _unique(skill_names, "skill name")
        _unique(skill_paths, "skill path")

        for key in ("name", "description"):
            _text(manifest[key], key, max_length=1024 if key == "description" else 120)
        if not VERSION_PATTERN.fullmatch(manifest["version"]):
            errors.append("version must be strict X.Y.Z")
        if not ID_PATTERN.fullmatch(extension_id):
            errors.append("id is invalid")
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"manifest semantic error: {exc}")
    return errors


def validate_manifest(
    manifest: Any,
    *,
    known_core_permissions: Collection[str],
) -> dict[str, Any]:
    """Validate shape and cross-field semantics, raising a bounded ManifestError."""
    if not isinstance(manifest, Mapping):
        raise ManifestError(["manifest must be a JSON object"])
    errors = _schema_errors(manifest)
    if not errors:
        errors.extend(_semantic_errors(manifest, known_core_permissions))
    if errors:
        raise ManifestError(errors)
    return dict(manifest)


def _matches(kind: str, value: Any) -> bool:
    if kind == "string":
        return isinstance(value, str)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "array":
        return isinstance(value, list)
    if kind == "object":
        return isinstance(value, Mapping)
    return False


def validate_arguments(
    parameters: Mapping[str, Any],
    arguments: Mapping[str, Any],
) -> None:
    """Validate operation arguments against the bounded v1 parameter contract."""
    if not isinstance(arguments, Mapping):
        raise ArgumentError("arguments must be an object")
    properties = parameters.get("properties", {})
    required = parameters.get("required", [])
    missing = [name for name in required if name not in arguments]
    if missing:
        raise ArgumentError(f"missing required arguments: {', '.join(sorted(missing))}")
    additional = parameters.get("additionalProperties", False) is True
    for name, value in arguments.items():
        declaration = properties.get(name)
        if declaration is None:
            if not additional:
                raise ArgumentError(f"unknown argument: {name}")
            continue
        kind = declaration.get("type")
        if not _matches(str(kind), value):
            raise ArgumentError(f"argument {name} must be {kind}")
