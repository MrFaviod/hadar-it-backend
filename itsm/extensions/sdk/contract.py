"""Single JSON Schema and semantic contract for extension manifest v2.

The schema is a package resource so the host, the generator and the fixed
validator container load exactly the same bytes. This module depends only on
``jsonschema`` and the standard library; it never imports host services.

SDK v2 adds the runtime split (declarative host-side collections vs sandboxed
``backend.py``), the capability allowlist, the collection schema subset and
declarative operation kinds.  Cross-field rules stay here so every door reports
the same bounded, actionable error list.
"""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Mapping
from datetime import date, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from jsonschema import Draft202012Validator

SDK_VERSION = 2
MAX_ERRORS = 40
ID_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
HANDLER_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
COLLECTION_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
FIELD_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
COMPONENT_PATTERN = re.compile(r"^[A-Z][A-Za-z0-9]{1,63}$")
PERMISSION_SUFFIX_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SKILL_PATH_PATTERN = re.compile(r"^skills/([a-z][a-z0-9]*(?:-[a-z0-9]+)*)/SKILL\.md$")

RUNTIMES = ("declarative", "sandboxed")
CAPABILITIES = ("assets.read", "assets.write", "incidents.read", "incidents.write", "notify")
OPERATION_KINDS = ("handler", "list", "get", "put", "delete")
DECLARATIVE_KINDS = ("list", "get", "put", "delete")
CONTRIBUTION_MODES = ("add", "hide", "replace")
SUBSCRIPTION_EVENTS = (
    "asset.created",
    "asset.updated",
    "asset.archived",
    "asset.restored",
    "asset.deleted",
    "incident.created",
    "incident.updated",
)
COLLECTION_TYPES = ("string", "number", "integer", "boolean", "null")
COLLECTION_FORMATS = ("date", "date-time", "uuid")
PROPERTY_KEYWORDS = frozenset({"type", "enum", "format", "maxLength", "minimum", "maximum"})
SCHEMA_KEYWORDS = frozenset({"type", "properties", "required", "additionalProperties"})
DECLARATIVE_ARGUMENTS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "list": (frozenset({"limit", "offset", "filters"}), frozenset()),
    "get": (frozenset({"record_id"}), frozenset({"record_id"})),
    "put": (
        frozenset({"record_id", "data", "expected_version"}),
        frozenset({"data"}),
    ),
    "delete": (
        frozenset({"record_id", "expected_version"}),
        frozenset({"record_id"}),
    ),
}


class ManifestError(ValueError):
    """A bounded set of manifest contract violations."""

    def __init__(self, errors: Collection[str]) -> None:
        self.errors = tuple(dict.fromkeys(str(error) for error in errors))[:MAX_ERRORS]
        super().__init__("; ".join(self.errors))


class ArgumentError(ValueError):
    """Operation arguments do not match the declared JSON parameter schema."""


class CollectionError(ValueError):
    """A declarative record does not match its declared collection schema."""


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


def operation_kind(operation: Mapping[str, Any]) -> str:
    kind = operation.get("kind", "handler")
    return str(kind)


def _path(error: Any) -> str:
    parts = [str(part) for part in error.absolute_path]
    return ".".join(parts) if parts else "<manifest>"


def _schema_errors(manifest: Any) -> list[str]:
    errors: list[str] = []
    validator = Draft202012Validator(load_schema())
    for error in sorted(validator.iter_errors(manifest), key=lambda item: list(item.absolute_path)):
        if error.validator == "additionalProperties":
            errors.append(f"{_path(error)}: unknown field ({error.message})")
        elif error.validator == "enum" and list(error.absolute_path)[:1] == ["capabilities"]:
            requested = error.instance
            errors.append(
                "contract_gap_required: capability "
                f"{requested} is not part of the public SDK; declare a public capability "
                "or record the gap with extension_contract_gap instead of reaching "
                "private core structures"
            )
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


def _unique(values: Collection[Any], label: str) -> None:
    seen: set[Any] = set()
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
            raise ValueError(f"operation {operation}: required argument {name!r} is not declared")
    if parameters.get("additionalProperties", False) is not True and len(required) != len(
        set(required)
    ):
        raise ValueError(f"operation {operation}: required arguments must be unique")


# --------------------------------------------------------------- collections


def collection_schema_errors(name: str, schema: Any) -> list[str]:
    """Validate the accepted JSON-Schema subset for one declared collection."""
    errors: list[str] = []
    label = f"collection {name} schema"
    if not isinstance(schema, Mapping):
        return [f"{label}: must be an object"]
    unknown = sorted(set(schema) - SCHEMA_KEYWORDS)
    if unknown:
        errors.append(f"{label}: unsupported keyword {', '.join(unknown)}")
    if schema.get("type") != "object":
        errors.append(f"{label}: type must be object")
    if "additionalProperties" in schema and schema["additionalProperties"] is not False:
        errors.append(f"{label}: additionalProperties must be false")
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        return [*errors, f"{label}: properties must be an object"]
    for field, declaration in properties.items():
        field_label = f"{label} field {field}"
        if not FIELD_PATTERN.fullmatch(str(field)):
            errors.append(f"{field_label}: invalid field name")
            continue
        if not isinstance(declaration, Mapping):
            errors.append(f"{field_label}: must be an object")
            continue
        unsupported = sorted(set(declaration) - PROPERTY_KEYWORDS)
        if unsupported:
            errors.append(f"{field_label}: unsupported keyword {', '.join(unsupported)}")
        kind = declaration.get("type")
        if kind not in COLLECTION_TYPES:
            errors.append(f"{field_label}: type must be one of {', '.join(COLLECTION_TYPES)}")
            continue
        if "format" in declaration and (
            kind != "string" or declaration["format"] not in COLLECTION_FORMATS
        ):
            errors.append(
                f"{field_label}: format must be one of {', '.join(COLLECTION_FORMATS)} on a string"
            )
        if "enum" in declaration:
            values = declaration["enum"]
            if not isinstance(values, list) or not values:
                errors.append(f"{field_label}: enum must be a non-empty array")
            else:
                for value in values:
                    if not _matches(kind, value):
                        errors.append(f"{field_label}: enum value {value!r} must be {kind}")
        if "maxLength" in declaration and kind != "string":
            errors.append(f"{field_label}: maxLength applies to strings")
        if (
            kind == "string"
            and isinstance(declaration.get("maxLength"), int)
            and not 1 <= declaration["maxLength"] <= 4000
        ):
            errors.append(f"{field_label}: maxLength must be between 1 and 4000")
        for bound in ("minimum", "maximum"):
            if bound in declaration and kind not in ("number", "integer"):
                errors.append(f"{field_label}: {bound} applies to numbers")
    required = schema.get("required", [])
    if not isinstance(required, list):
        errors.append(f"{label}: required must be an array")
    else:
        for field in required:
            if field not in properties:
                errors.append(f"{label}: required field {field} is not declared")
        _unique(required, f"required field in {name}")
    return errors


def validate_collection_value(name: str, schema: Any, value: Any) -> dict[str, Any]:
    """Validate one declarative record against the accepted schema subset."""
    if not isinstance(value, Mapping):
        raise CollectionError("record must be an object")
    if not isinstance(schema, Mapping) or not schema.get("properties"):
        return dict(value)
    properties = schema.get("properties") or {}
    required = schema.get("required") or []
    for field in required:
        if field not in value:
            raise CollectionError(f"missing required field: {field}")
    for field, item in value.items():
        declaration = properties.get(field)
        if declaration is None:
            raise CollectionError(f"unknown field: {field}")
        kind = declaration.get("type")
        if not _matches(str(kind), item):
            raise CollectionError(f"field {field} must be {kind}")
        enum = declaration.get("enum")
        if isinstance(enum, list) and item not in enum:
            raise CollectionError(f"field {field} must be one of the declared values")
        if kind == "string":
            max_length = declaration.get("maxLength")
            if isinstance(max_length, int) and len(item) > max_length:
                raise CollectionError(f"field {field} exceeds {max_length} characters")
            fmt = declaration.get("format")
            try:
                if fmt == "date":
                    date.fromisoformat(item)
                elif fmt == "date-time":
                    datetime.fromisoformat(item.replace("Z", "+00:00"))
                elif fmt == "uuid":
                    UUID(item)
            except ValueError:
                raise CollectionError(f"field {field} is not a valid {fmt}") from None
        if kind in ("number", "integer"):
            if "minimum" in declaration and item < declaration["minimum"]:
                raise CollectionError(f"field {field} is below the declared minimum")
            if "maximum" in declaration and item > declaration["maximum"]:
                raise CollectionError(f"field {field} is above the declared maximum")
    return dict(value)


# ----------------------------------------------------------------- semantics


def _validate_runtime(manifest: Mapping[str, Any], collection_names: Collection[str]) -> list[str]:
    errors: list[str] = []
    runtime = manifest["runtime"]
    operations = manifest["operations"]
    for operation in operations:
        name = operation.get("name", "<operation>")
        kind = operation_kind(operation)
        if runtime == "declarative":
            if kind not in DECLARATIVE_KINDS:
                errors.append(
                    f"operation {name}: declarative runtime requires a declarative kind "
                    f"({', '.join(DECLARATIVE_KINDS)}), not {kind}"
                )
                continue
            collection = operation.get("collection")
            if not collection:
                errors.append(
                    f"operation {name}: declarative kind {kind} requires a declared collection"
                )
            elif collection not in collection_names:
                errors.append(f"operation {name}: collection {collection} is not declared")
            allowed, required = DECLARATIVE_ARGUMENTS[kind]
            declared = set((operation.get("parameters") or {}).get("properties") or {})
            extra = sorted(declared - allowed)
            if extra:
                errors.append(
                    f"operation {name}: declarative kind {kind} accepts only "
                    f"{', '.join(sorted(allowed))} (unexpected {', '.join(extra)})"
                )
            missing = sorted(required - declared)
            if missing:
                errors.append(
                    f"operation {name}: declarative kind {kind} must declare {', '.join(missing)}"
                )
        else:
            if kind != "handler":
                errors.append(
                    f"operation {name}: sandboxed runtime requires kind handler, not {kind}"
                )
            if operation.get("collection") is not None:
                errors.append(f"operation {name}: kind handler cannot target a collection")
    if runtime == "declarative":
        if manifest.get("migrations"):
            errors.append(
                "declarative runtime cannot declare migrations; use the sandboxed runtime"
            )
        if manifest.get("schedules"):
            errors.append("declarative runtime cannot declare schedules; use the sandboxed runtime")
        if manifest.get("subscriptions"):
            errors.append(
                "declarative runtime cannot declare subscriptions; use the sandboxed runtime"
            )
        if manifest.get("reconcile"):
            errors.append("declarative runtime cannot declare reconcile; use the sandboxed runtime")
        if manifest["frontend"].get("entry"):
            errors.append(
                "declarative runtime cannot declare frontend.entry; isolated views need the sandboxed runtime"
            )
    return errors


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
                errors.append(f"permission {code}: must start with declared namespace {prefix}")
            suffix = code[len(prefix) :] if code.startswith(prefix) else ""
            if not PERMISSION_SUFFIX_PATTERN.fullmatch(suffix):
                errors.append(
                    f"permission {code}: suffix must match {PERMISSION_SUFFIX_PATTERN.pattern}"
                )
            if not label:
                errors.append(f"permission {code}: label is required")

        known = set(known_core_permissions)
        for code in manifest.get("corePermissions", []):
            if code not in known:
                errors.append(f"core permission {code}: unknown core permission")
            if code.startswith("ext_") or code.startswith(prefix):
                errors.append(f"core permission {code}: cannot shadow an extension permission")
        _unique(list(manifest.get("corePermissions", [])), "core permission")

        for capability in manifest.get("capabilities", []):
            if capability not in CAPABILITIES:
                errors.append(
                    "contract_gap_required: capability "
                    f"{capability} is not part of the public SDK; declare a public "
                    "capability or record the gap with extension_contract_gap instead "
                    "of reaching private core structures"
                )
        _unique(list(manifest.get("capabilities", [])), "capability")

        collection_names: list[str] = []
        for collection in manifest["collections"]:
            name = collection["name"]
            collection_names.append(name)
            if not COLLECTION_PATTERN.fullmatch(name):
                errors.append(f"collection {name}: invalid collection name")
            _text(collection["description"], f"collection {name} description", max_length=512)
            schema = collection.get("schema")
            if schema is not None:
                errors.extend(collection_schema_errors(name, schema))
            for reference in collection.get("references", []):
                field = reference["field"]
                properties = (schema or {}).get("properties") or {}
                if field not in properties:
                    errors.append(f"collection {name} reference: field {field} is not declared")
        _unique(collection_names, "collection name")

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
        errors.extend(_validate_runtime(manifest, collection_names))

        schedule_names: list[str] = []
        handler_names: list[str] = []
        for schedule in manifest.get("schedules", []):
            schedule_names.append(schedule["name"])
            handler_names.append(schedule["handler"])
            if schedule["permission"] not in codes:
                errors.append(
                    f"schedule {schedule['name']}: permission "
                    f"{schedule['permission']} is not declared permission"
                )
        _unique(schedule_names, "schedule name")
        _unique(handler_names, "schedule handler")

        subscription_names: list[str] = []
        for subscription in manifest.get("subscriptions", []):
            subscription_names.append(subscription["event"])
            if subscription["event"] not in SUBSCRIPTION_EVENTS:
                errors.append(f"subscription {subscription['event']}: unknown event")
        _unique(subscription_names, "subscription event")
        reconcile = manifest.get("reconcile")
        if reconcile is not None and reconcile["intervalSeconds"] < 300:
            errors.append("reconcile intervalSeconds must be at least 300")

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
                errors.append(f"migration {migration['handler']}: from must be lower than to")
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
        isolated = False
        views: list[tuple[str, Mapping[str, Any]]] = []
        for label, key in (
            ("page", "pages"),
            ("asset panel", "assetPanels"),
            ("widget", "widgets"),
        ):
            for view in frontend.get(key, []):
                views.append((label, view))
        for label, view in views:
            contribution_ids.append(view["id"])
            if view["permission"] not in codes:
                errors.append(
                    f"{label} {view['id']}: permission {view['permission']} is not declared permission"
                )
            _text(view["label"], f"{label} {view['id']} label", max_length=120)
            if view.get("component") is not None:
                isolated = True
                if not COMPONENT_PATTERN.fullmatch(view["component"]):
                    errors.append(f"{label} {view['id']}: invalid component name")
            declaration = view.get("view")
            if declaration is None and view.get("component") is None:
                errors.append(f"{label} {view['id']}: a declarative view is required")
            if declaration and "isolated" in declaration:
                isolated = True
                if manifest["runtime"] == "declarative":
                    errors.append(
                        f"{label} {view['id']}: isolated views need the sandboxed runtime"
                    )
        for action in frontend.get("actions", []):
            contribution_ids.append(action["id"])
            if action["permission"] not in codes:
                errors.append(
                    f"action {action['id']}: permission {action['permission']} is not declared permission"
                )
            if action["target"] != "asset.action":
                errors.append(f"action {action['id']}: target must be asset.action")
            if action["operation"] not in operation_names:
                errors.append(
                    f"action {action['id']}: operation {action['operation']} is not declared"
                )
        for contribution in frontend.get("contributions", []):
            # Contributions stay declarative slot changes: hide a core surface or
            # add one rendered from an isolated component. They never inject code
            # into the host document.
            contribution_ids.append(contribution["id"])
            if contribution["mode"] not in CONTRIBUTION_MODES:
                errors.append(
                    f"contribution {contribution['id']}: mode must be add, hide or replace"
                )
            if contribution["permission"] not in codes:
                errors.append(
                    f"contribution {contribution['id']}: permission "
                    f"{contribution['permission']} is not declared permission"
                )
            _text(
                contribution["label"],
                f"contribution {contribution['id']} label",
                max_length=120,
            )
            if contribution["mode"] == "hide" and contribution.get("component"):
                errors.append(
                    f"contribution {contribution['id']}: hide contributions take no component"
                )
            if contribution["mode"] != "hide":
                component = contribution.get("component")
                if not component or not COMPONENT_PATTERN.fullmatch(component):
                    errors.append(f"contribution {contribution['id']}: component name is required")
                else:
                    isolated = True
        _unique(contribution_ids, "frontend contribution id")
        if isolated and not frontend.get("entry"):
            errors.append("frontend.entry is required when a view renders isolated module code")

        skill_names: list[str] = []
        skill_paths: list[str] = []
        for skill in manifest.get("skills", []):
            skill_names.append(skill["name"])
            skill_paths.append(skill["path"])
            match = SKILL_PATH_PATTERN.fullmatch(skill["path"])
            if match is None or match.group(1) != skill["name"]:
                errors.append(
                    f"skill {skill['name']}: path must be skills/{skill['name']}/SKILL.md"
                )
            _text(skill["description"], f"skill {skill['name']} description", max_length=1024)
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
    if manifest.get("sdkVersion") != SDK_VERSION:
        raise ManifestError(
            [
                f"sdkVersion must be {SDK_VERSION}; SDK v1 packages are not admitted. "
                "Rebuild the module against SDK v2 and copy legacy rows with "
                "`python -m itsm.extensions relocate-legacy`."
            ]
        )
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
    if kind == "null":
        return value is None
    if kind == "array":
        return isinstance(value, list)
    if kind == "object":
        return isinstance(value, Mapping)
    return False


def validate_arguments(
    parameters: Mapping[str, Any],
    arguments: Mapping[str, Any],
) -> None:
    """Validate operation arguments against the bounded parameter contract."""
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
