"""Boundary rules between the core repository/database and extension packages.

The build environment must be unable to write the core, and static validation
must turn a missing public contract into an actionable ``contract_gap_required``
message instead of letting a module reach private structures.
"""

from __future__ import annotations

import pytest
from itsm.config import BACKEND_ROOT, Settings
from itsm.extensions.manifest import PackageError, inspect_package
from pydantic import ValidationError
from tests.test_extension_runtime_support import (
    PROBE_BACKEND,
    build_package,
    declarative_manifest,
    probe_manifest,
)


def sandboxed_package(source: str = PROBE_BACKEND, **manifest_changes: object) -> bytes:
    declaration = probe_manifest()
    declaration.update(manifest_changes)
    return build_package(declaration, backend=source)


@pytest.mark.parametrize(
    ("statement", "capability"),
    [
        (
            "ATTACH DATABASE '/var/lib/itsm/app.db' AS core",
            "direct core database access",
        ),
        ("SELECT id FROM asset_history", "direct core table access"),
        ("SELECT name FROM sqlite_master", "core schema introspection"),
        ("INSERT INTO entity_change_events (id) VALUES ('x')", "direct core table access"),
    ],
)
def test_sql_text_targeting_core_structures_is_a_contract_gap(
    statement: str, capability: str
) -> None:
    source = PROBE_BACKEND + (
        "\n\ndef forbidden_sql(context):\n"
        f"    context.db.execute({statement!r})\n"
        "    return {'ran': True}\n"
        "\n\n_original_register = register\n"
        "\ndef register(sdk):\n"
        "    _original_register(sdk)\n"
        "    sdk.operation('forbidden_sql', forbidden_sql)\n"
    )
    declaration = probe_manifest()
    declaration["operations"].append(
        {
            "name": "forbidden_sql",
            "description": "Operación que intenta SQL del núcleo",
            "permission": "ext_probe.read",
            "mutation": False,
            "kind": "handler",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
        }
    )
    with pytest.raises(PackageError) as failure:
        inspect_package(build_package(declaration, backend=source))
    message = str(failure.value)
    assert "contract_gap_required" in message
    assert capability in message


def isolated_declaration(component: str = "LicensesPanel") -> dict:
    declaration = probe_manifest()
    declaration["frontend"] = {
        "entry": "frontend.js",
        "pages": [
            {
                "id": "licenses",
                "label": "Licencias",
                "permission": "ext_probe.read",
                "view": {"isolated": {"component": component}},
            }
        ],
        "assetPanels": [],
        "contributions": [],
    }
    return declaration


def test_frontend_view_with_unknown_component_is_refused() -> None:
    frontend = "window.ITSMExtension.register({components: {OtherPanel: {}}});"
    with pytest.raises(PackageError) as failure:
        inspect_package(
            build_package(isolated_declaration(), backend=PROBE_BACKEND, frontend=frontend)
        )
    assert "LicensesPanel" in str(failure.value)


@pytest.mark.parametrize(
    "source",
    [
        "import { api } from '@/services/api';\n"
        "window.ITSMExtension.register({components: {LicensesPanel: {}}});",
        "import core from '../../itsm/client';\n"
        "window.ITSMExtension.register({components: {LicensesPanel: {}}});",
        "const core = require('itsm.core');\n"
        "window.ITSMExtension.register({components: {LicensesPanel: {}}});",
    ],
)
def test_frontend_private_host_imports_are_a_contract_gap(source: str) -> None:
    with pytest.raises(PackageError) as failure:
        inspect_package(
            build_package(isolated_declaration(), backend=PROBE_BACKEND, frontend=source)
        )
    message = str(failure.value)
    assert "contract_gap_required" in message
    assert "frontend" in message


def test_frontend_registered_component_is_accepted() -> None:
    frontend = (
        "(function () { window.ITSMExtension.register({components: {LicensesPanel: {}}}); })();"
    )
    package = inspect_package(
        build_package(isolated_declaration(), backend=PROBE_BACKEND, frontend=frontend)
    )
    assert package.frontend_source.startswith("(function")


def test_collection_references_are_validated_for_both_runtimes() -> None:
    declaration = declarative_manifest()
    declaration["collections"][0]["references"] = [
        {"field": "label", "entity": "asset", "onArchive": "flag", "onDelete": "flag"}
    ]
    inspect_package(build_package(declaration, backend=None))

    sandboxed = probe_manifest()
    sandboxed["collections"][0]["references"] = [
        {"field": "label", "entity": "asset", "onArchive": "flag", "onDelete": "flag"}
    ]
    inspect_package(build_package(sandboxed))

    sandboxed["collections"][0]["references"] = [
        {"field": "undeclared", "entity": "asset", "onArchive": "flag", "onDelete": "flag"}
    ]
    with pytest.raises(PackageError) as failure:
        inspect_package(build_package(sandboxed))
    assert "is not declared" in str(failure.value)


def test_settings_reject_extension_storage_inside_the_backend_source_tree() -> None:
    with pytest.raises(ValidationError) as failure:
        Settings(
            _env_file=None,
            environment="test",
            database_url="sqlite:////tmp/itsm-core.db",
            extension_data_path=BACKEND_ROOT / "itsm" / "state",
        )
    assert "backend source tree" in str(failure.value)

    with pytest.raises(ValidationError) as failure:
        Settings(
            _env_file=None,
            environment="test",
            database_url="sqlite:////tmp/itsm-core.db",
            extension_workspace_path=BACKEND_ROOT,
        )
    assert "backend source tree" in str(failure.value)


def test_settings_reject_extension_storage_overlapping_the_core_database(tmp_path) -> None:
    database = tmp_path / "app.db"
    with pytest.raises(ValidationError) as failure:
        Settings(
            _env_file=None,
            environment="test",
            database_url=f"sqlite:///{database}",
            extension_data_path=tmp_path,
        )
    assert "core SQLite database" in str(failure.value)

    with pytest.raises(ValidationError) as failure:
        Settings(
            _env_file=None,
            environment="test",
            database_url=f"sqlite:///{database}",
            extension_workspace_path=database,
        )
    assert "core SQLite database" in str(failure.value)


def test_settings_accept_isolated_extension_paths(tmp_path) -> None:
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{tmp_path / 'app.db'}",
        extension_data_path=tmp_path / "extensions-data",
        extension_workspace_path=tmp_path / "extensions-work",
    )
    assert settings.extension_data_path == tmp_path / "extensions-data"
