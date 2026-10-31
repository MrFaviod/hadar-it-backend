"""Generated SDK v2 packages must install and run through the real host.

These tests close the loop between the generator templates and the runtime: a
sandboxed example runs in the isolated runner, and a declarative example runs
host-side with no module code. Both keep their business data in their own SQLite
file and leave the core database untouched.
"""

# ruff: noqa: F811 - the `env` fixture is imported and also named in signatures.

from __future__ import annotations

import sqlite3
from typing import Any

from itsm.extensions.host import ExtensionHostService
from itsm.extensions.sdk.generator import generate_package
from itsm.extensions.sdk.package import build_package
from itsm.extensions.sdk.validator.harness import validate_payload
from itsm.extensions.sdk.validator.protocol import build_frame
from tests.test_extension_runtime_support import (
    core_fingerprint,
    legacy_rows,
    sqlite_master_fingerprint,
)
from tests.test_native_extensions import env  # noqa: F401  (shared host fixture)


def _offline_report(data: bytes, digest: str) -> dict[str, Any]:
    """Validate the package with the fixed offline harness, not a container."""
    report = validate_payload(build_frame(data, digest=digest, known_core_permissions=()))
    assert report["status"] == "passed", report["errors"]
    return report


def _install(environment, package_id: str, *, runtime: str) -> dict[str, Any]:
    generated = generate_package(
        extension_id=package_id,
        name=package_id.title(),
        description=f"Generated {runtime} example for the runtime suite.",
        runtime=runtime,
    )
    built = build_package(generated.files, known_core_permissions=())
    candidate = environment.candidate(built.data)
    validated = environment.host.record_validation_report(
        candidate["id"],
        _offline_report(built.data, built.digest),
        expected_version=candidate["revision"],
    )
    environment.host.approve_candidate(
        environment.owner,
        validated["id"],
        digest=built.digest,
        expected_version=validated["currentRevision"],
    )
    return generated.manifest


def _rows(env, package_id: str) -> list[tuple[str, str, int]]:
    path = env.settings.extension_data_path / package_id / "data.sqlite3"
    with sqlite3.connect(path) as connection:
        return list(
            connection.execute(
                "SELECT collection, record_id, version FROM _itsm_records ORDER BY record_id"
            )
        )


def test_generated_sandboxed_example_installs_and_runs(env) -> None:
    before_tables = core_fingerprint(env.settings)
    before_master = sqlite_master_fingerprint(env.settings)
    manifest = _install(env, "generated-records", runtime="sandboxed")

    item = env.host.discovery(env.owner)["items"][0]
    assert item["runtime"] == "sandboxed"
    assert item["status"] == "ready"
    assert item["frontendUrl"] is None

    created = env.host.invoke(
        env.owner,
        "generated-records",
        "create_record",
        {"title": "Primer registro", "status": "open"},
    )
    assert created["record"]["title"] == "Primer registro"
    listed = env.host.invoke(env.owner, "generated-records", "list_records", {"limit": 10})
    assert [record["title"] for record in listed["items"]] == ["Primer registro"]
    assert _rows(env, "generated-records")
    assert legacy_rows(env.settings) == []

    status = env.host.status(env.owner, "generated-records")
    assert status["status"] == "ready"
    assert status["schemaVersion"] == manifest["schemaVersion"]
    assert status["dataSizeBytes"] > 0

    assert core_fingerprint(env.settings) == before_tables
    assert sqlite_master_fingerprint(env.settings) == before_master
    assert ExtensionHostService is not None


def test_generated_declarative_example_runs_without_module_code(env) -> None:
    _install(env, "generated-notes", runtime="declarative")
    created = env.host.invoke(
        env.owner,
        "generated-notes",
        "put_note",
        {"data": {"title": "Nota declarativa", "status": "open"}},
    )
    assert created["version"] == 1
    listed = env.host.invoke(env.owner, "generated-notes", "list_notes", {})
    assert listed["total"] == 1
    assert listed["items"][0]["data"]["title"] == "Nota declarativa"
    storage = env.settings.extension_data_path / "generated-notes"
    assert not (storage / "backend.py").exists()
    assert (storage / "data.sqlite3").exists()
    assert legacy_rows(env.settings) == []
