"""SDK v2 admission rules, static contract-gap rules and the schema constant."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from itsm.extensions.host import ExtensionValidationFailed
from itsm.extensions.manifest import PackageError, inspect_package
from itsm.extensions.sdk.contract import (
    ArgumentError,
    ManifestError,
    load_schema,
    validate_manifest,
)
from tests.test_extension_runtime_support import (  # noqa: F401 - fixtures
    env,
    PROBE_BACKEND,
    build_package,
    declarative_manifest,
    probe_manifest,
)


def checked(declaration: dict[str, Any]) -> dict[str, Any]:
    return validate_manifest(declaration, known_core_permissions=())


def test_schema_constant_and_v2_manifest_are_accepted() -> None:
    schema = load_schema()
    assert schema["properties"]["sdkVersion"]["const"] == 2
    assert set(schema["properties"]["runtime"]["enum"]) == {"declarative", "sandboxed"}
    manifest = checked(probe_manifest())
    assert manifest["sdkVersion"] == 2
    assert manifest["runtime"] == "sandboxed"
    assert manifest["collections"][0]["schema"]["required"] == ["label"]


def test_declarative_modules_cannot_ship_executable_or_migration_code() -> None:
    declaration = declarative_manifest()
    declaration["backend.py"] = "ignored"
    with pytest.raises(PackageError):
        inspect_package(build_package(declaration))
    declaration = declarative_manifest()
    declaration["migrations"] = [{"from": 1, "to": 2, "handler": "normalize"}]
    with pytest.raises(ManifestError) as failure:
        checked(declaration)
    assert any("declarative" in error for error in failure.value.errors)
    declaration = declarative_manifest()
    declaration["schedules"] = [
        {
            "name": "tick",
            "handler": "tick",
            "intervalSeconds": 600,
            "permission": "ext_declarative_notes.read",
        }
    ]
    with pytest.raises(ManifestError):
        checked(declaration)
    declaration = declarative_manifest()
    declaration["operations"][0]["kind"] = "handler"
    with pytest.raises(ManifestError) as failure:
        checked(declaration)
    assert any("declarative" in error or "kind" in error for error in failure.value.errors)


def test_sandboxed_modules_require_a_backend_and_handler_kinds() -> None:
    with pytest.raises(PackageError, match="backend.py"):
        inspect_package(build_package(probe_manifest(), backend=None))
    declaration = probe_manifest()
    declaration["operations"][1]["kind"] = "list"
    with pytest.raises(ManifestError):
        checked(declaration)


def test_collection_schema_subset_rejects_unsupported_keywords() -> None:
    declaration = probe_manifest()
    declaration["collections"][0]["schema"]["properties"]["label"]["minItems"] = 2
    with pytest.raises(ManifestError) as failure:
        checked(declaration)
    assert any("minItems" in error for error in failure.value.errors)
    declaration = probe_manifest()
    declaration["collections"][0]["schema"]["properties"]["label"]["type"] = "array"
    with pytest.raises(ManifestError) as failure:
        checked(declaration)
    assert any("type" in error for error in failure.value.errors)
    declaration = probe_manifest()
    declaration["collections"][0]["schema"]["required"] = ["missing"]
    with pytest.raises(ManifestError):
        checked(declaration)


def test_declarative_operations_need_a_declared_collection() -> None:
    declaration = declarative_manifest()
    declaration["operations"][0]["collection"] = "unknown"
    with pytest.raises(ManifestError) as failure:
        checked(declaration)
    assert any("collection" in error for error in failure.value.errors)
    declaration = declarative_manifest()
    del declaration["operations"][0]["collection"]
    with pytest.raises(ManifestError):
        checked(declaration)
    declaration = probe_manifest()
    declaration["operations"][0]["collection"] = "records"
    with pytest.raises(ManifestError):
        checked(declaration)


def test_unknown_capabilities_are_rejected_with_the_declared_set() -> None:
    declaration = probe_manifest(capabilities=["assets.read", "root"])
    with pytest.raises(ManifestError) as failure:
        checked(declaration)
    joined = " ".join(failure.value.errors)
    assert "capabilities" in joined and "assets.read" in joined


def test_references_are_validated_against_the_declared_schema() -> None:
    declaration = declarative_manifest()
    declaration["collections"][0]["references"] = [
        {"field": "label", "entity": "asset", "onArchive": "keep", "onDelete": "flag"}
    ]
    assert checked(declaration)["collections"][0]["references"][0]["entity"] == "asset"
    declaration["collections"][0]["references"] = [
        {"field": "missing", "entity": "asset", "onArchive": "keep", "onDelete": "flag"}
    ]
    with pytest.raises(ManifestError):
        checked(declaration)
    declaration = declarative_manifest()
    declaration["collections"][0]["references"] = [
        {"field": "label", "entity": "vault", "onArchive": "keep", "onDelete": "flag"}
    ]
    with pytest.raises(ManifestError):
        checked(declaration)


@pytest.mark.parametrize(
    ("source", "capability"),
    [
        ("import itsm\n", "host capabilities"),
        ("import sqlalchemy\n", "host capabilities"),
        ("import socket\n", "network"),
        ("import subprocess\n", "process execution"),
        ("import ctypes\n", "host capabilities"),
        ("import multiprocessing\n", "process execution"),
        ("import os\nos.system('true')\n", "process execution"),
    ],
)
def test_static_rules_name_the_missing_public_capability(source: str, capability: str) -> None:
    payload = build_package(probe_manifest(), backend=source + PROBE_BACKEND)
    with pytest.raises(PackageError) as failure:
        inspect_package(payload)
    message = str(failure.value)
    assert "contract_gap_required" in message
    assert capability in message


def test_argument_validation_still_rejects_unknown_keys() -> None:
    from itsm.extensions.sdk.contract import validate_arguments

    with pytest.raises(ArgumentError):
        validate_arguments(
            {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
            {"unexpected": True},
        )


def test_candidate_detail_reports_v2_trust_and_runtime(env) -> None:
    candidate = env.candidate(build_package(probe_manifest()))
    assert candidate["manifest"]["sdkVersion"] == 2
    assert candidate["trust"]["sandboxed"] is True
    assert candidate["trust"]["runtime"] == "sandboxed"
    page = env.host.list_candidates(env.owner)
    assert page["items"][0]["id"] == candidate["id"]
    with pytest.raises(ExtensionValidationFailed):
        env.candidate(build_package(probe_manifest(), backend=None))


def test_frontend_entry_is_optional_but_isolated_views_require_it() -> None:
    declaration = probe_manifest()
    declaration["frontend"] = {"pages": [], "assetPanels": [], "contributions": []}
    checked(declaration)
    declaration["frontend"]["pages"] = [
        {
            "id": "panel",
            "label": "Panel",
            "permission": "ext_probe.read",
            "view": {"isolated": {"component": "ProbePanel"}},
        }
    ]
    with pytest.raises(ManifestError) as failure:
        checked(declaration)
    assert any("entry" in error for error in failure.value.errors)
    declaration["frontend"]["entry"] = "frontend.js"
    assert checked(declaration)["frontend"]["entry"] == "frontend.js"


def test_package_digest_rejects_legacy_v1_manifests_before_storage(tmp_path: Path) -> None:
    manifest = probe_manifest()
    manifest["sdkVersion"] = 1
    with pytest.raises(PackageError) as failure:
        inspect_package(build_package(manifest))
    message = str(failure.value)
    assert "sdkVersion" in message and "2" in message
    assert json.dumps(checked(probe_manifest())) != ""
