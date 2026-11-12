"""Behavior of the official skill catalog and permission-aware module extensions.

The catalog is inert package metadata: it never writes to an agent profile or a
global skill root. The extension registry is the only path from a module to the
mounted MCP surface and always rechecks the trusted identity service.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools.function_tool import FunctionTool
from itsm.agent_integrations.catalog import (
    CAPABILITIES,
    InvalidSkillPackage,
    ModuleConflict,
    SkillCatalog,
    SkillNotFound,
    UnknownModule,
    package_digest,
)
from itsm.agent_integrations.extensions import (
    ExtensionConflict,
    ExtensionContext,
    ExtensionNotFound,
    ExtensionRegistry,
    InvalidExtension,
    ModuleUnavailable,
    bind_fastmcp_tools,
    load_extension_modules,
)
from itsm.config import Settings
from itsm.identity.permissions import PERMISSION_CATALOG
from itsm.identity.service import IdentityService, PermissionDenied
from itsm.mcp.server import TOOL_NAMES, create_mcp_server
from itsm.operations import tools as operations_tools
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from sqlalchemy.orm import Session
from tests.identity_support import PASSWORD, make_harness

OFFICIAL_SKILLS = (
    "itsm-incidents",
    "itsm-infrastructure",
    "itsm-inventory",
    "itsm-maintenance",
    "itsm-monitoring",
    "itsm-operations",
    "itsm-reporting",
)

METADATA_KEYS = {
    "name",
    "description",
    "version",
    "module",
    "permissions",
    "capabilities",
    "digest",
}

MODULE_SKILL = """---
name: {name}
description: "Trigger: module demonstration. Exercise one module-provided ITSM skill."
license: UNLICENSED
metadata:
  author: "Example module"
  version: "1.2.0"
tools:
  - get_asset
permissions:
  - {permission}
capabilities:
  - {capability}
---
# Module demonstration

## Activation Contract
Load only when the module demonstration behavior is requested.

## Hard Rules
- Read through authorized MCP tools; never fabricate identifiers.

## Decision Gates
| Need | Call |
| --- | --- |
| Known asset | `get_asset` |

## Execution Steps
1. Read the asset with `get_asset`.
2. Report the id and status.

## Output Contract
Return the asset id, current status and nothing else.
"""


def frontmatter(text: str) -> dict[str, Any]:
    """Parse the small YAML subset used by SKILL.md, independently of the product parser."""
    assert text.startswith("---\n")
    closing = text.index("\n---", 4)
    data: dict[str, Any] = {}
    current: str | None = None
    nested: dict[str, str] | None = None
    for raw in text[4:closing].splitlines():
        if not raw.strip():
            continue
        if raw.startswith("  - "):
            assert current is not None
            data[current].append(raw[4:].strip())
        elif raw.startswith("  ") and ":" in raw:
            key, _, value = raw.strip().partition(":")
            if nested is None:
                nested = {}
                data[current] = nested
            nested[key] = value.strip().strip('"')
        else:
            key, _, value = raw.partition(":")
            current = key.strip()
            nested = None
            if value.strip():
                data[current] = value.strip().strip('"')
            else:
                data[current] = []
    return data


def write_skill(
    package: Path,
    *,
    name: str,
    permission: str = "assets.view",
    capability: str = "inventory.read",
) -> None:
    package.mkdir(parents=True)
    (package / "SKILL.md").write_text(
        MODULE_SKILL.format(name=name, permission=permission, capability=capability),
        encoding="utf-8",
    )
    references = package / "references"
    references.mkdir()
    (references / "notes.md").write_text("Local note.\n", encoding="utf-8")


def write_module(
    tmp_path: Path,
    *,
    module_id: str = "vendor.demo",
    skill: str = "demo-skill",
    permissions: tuple[str, ...] = ("assets.view",),
    capabilities: tuple[str, ...] = ("inventory.read",),
    skill_permission: str = "assets.view",
    skill_capability: str = "inventory.read",
    include_skill: bool = True,
) -> tuple[dict[str, Any], Path]:
    root = tmp_path / module_id
    root.mkdir()
    manifest: dict[str, Any] = {
        "id": module_id,
        "name": "Demo module",
        "version": "1.2.0",
        "capabilities": list(capabilities),
        "permissions": list(permissions),
        "skills": [],
    }
    if include_skill:
        write_skill(
            root / "skills" / skill,
            name=skill,
            permission=skill_permission,
            capability=skill_capability,
        )
        manifest["skills"] = [skill]
    return manifest, root


def tools_only_module(tmp_path: Path, *, module_id: str = "vendor.demo") -> SkillCatalog:
    """Register an empty tools-only module and return its catalog."""
    catalog = SkillCatalog()
    root = tmp_path / module_id
    root.mkdir()
    catalog.register_module(
        {
            "id": module_id,
            "name": "Demo module",
            "version": "1.2.0",
            "capabilities": ["inventory.read"],
            "permissions": ["assets.view", "assets.edit"],
            "skills": [],
        },
        root=root,
    )
    return catalog


def files_of(root: Path, relative: str = "skills/demo-skill") -> dict[str, bytes]:
    package = root / relative
    return {
        path.relative_to(package).as_posix(): path.read_bytes()
        for path in sorted(package.rglob("*"))
        if path.is_file()
    }


def echo_handler(context: ExtensionContext, **arguments: Any) -> dict[str, Any]:
    return {"module": "vendor.demo", "arguments": arguments}


CALLS: list[dict[str, Any]] = []


def canonical_views(context: ExtensionContext, **arguments: Any) -> dict[str, Any]:
    """A real module handler must delegate to a canonical service."""
    CALLS.append(arguments)
    return operations_tools.list_saved_views(
        context.session, context.identity, context.principal, source=context.source
    )


def parameters(**properties: str) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {name: {"type": kind} for name, kind in properties.items()},
        "required": list(properties),
        "additionalProperties": False,
    }


def test_official_catalog_lists_seven_metadata_only_skills() -> None:
    catalog = SkillCatalog()

    metadatas = catalog.list_skills()

    assert [item["name"] for item in metadatas] == list(OFFICIAL_SKILLS)
    for item in metadatas:
        assert set(item) == METADATA_KEYS
        assert item["module"] == "itsm"
        assert item["version"] == "1.0.0"
        assert len(item["digest"]) == 64
        assert item["permissions"]
        assert item["capabilities"]
        assert set(item["permissions"]) <= set(PERMISSION_CATALOG)
        assert set(item["capabilities"]) <= CAPABILITIES
        assert "files" not in item

    modules = {module["id"]: module for module in catalog.list_modules()}
    assert modules["itsm"]["official"] is True
    assert modules["itsm"]["enabled"] is True
    assert modules["itsm"]["version"] == "1.0.0"
    assert modules["itsm"]["skills"] == list(OFFICIAL_SKILLS)


def test_official_skills_are_real_packages_with_valid_metadata() -> None:
    catalog = SkillCatalog()

    for name in OFFICIAL_SKILLS:
        package = catalog.get_skill(name)
        assert set(package) == METADATA_KEYS | {"files"}
        assert "SKILL.md" in package["files"]
        for relative, content in package["files"].items():
            assert relative == "SKILL.md" or "/" in relative
            assert not relative.startswith("/")
            assert ".." not in Path(relative).parts
            assert content

        text = package["files"]["SKILL.md"].decode("utf-8")
        front = frontmatter(text)

        assert front["name"] == name
        assert front["description"].startswith("Trigger: ")
        assert len(front["description"]) <= 250
        assert front["license"]
        assert front["metadata"]["version"] == "1.0.0"
        assert front["tools"], name
        assert all(isinstance(tool, str) and tool for tool in front["tools"]), name
        assert set(front["permissions"]) <= set(PERMISSION_CATALOG)
        assert set(front["capabilities"]) <= CAPABILITIES
        assert text.split("\n---", 1)[1].strip(), name
        links = re.findall(r"\(references/[^)]+\)", text)
        assert links, name
        for link in links:
            target = link[1:-1]
            assert target in package["files"], (name, target)


def test_authorized_inventory_workflow_runs_through_real_mcp_server(
    settings_factory: Callable[..., Settings], monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = make_harness(settings_factory)
    # Public MCP and extension services use the real clock, including token expiry.
    harness.clock = datetime.now(UTC)
    try:
        with harness.service() as service:
            service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
            admin = service.login("ana.admin", PASSWORD)
            service.create_user(
                admin.principal,
                username="agent.reader",
                name="Reader agent",
                role_id="user",
                actor_kind="external_agent",
            )
            credential = service.issue_machine_credential("agent.reader")

        monkeypatch.setattr(
            "itsm.mcp.server.get_http_headers",
            lambda **_: {"authorization": f"Bearer {credential.token}"},
        )

        async def workflow() -> Any:
            server = create_mcp_server(harness.settings, lambda: Session(harness.engine))
            token = auth_context_var.set(
                AuthenticatedUser(
                    AccessToken(
                        token=credential.token,
                        client_id="catalog-test",
                        scopes=["assets.view"],
                    )
                )
            )
            try:
                return await server.call_tool("search_assets", {"limit": 1})
            finally:
                auth_context_var.reset(token)

        result = asyncio.run(workflow())
        assert result.structured_content == {"total": 0, "items": []}
    finally:
        harness.close()


def test_configured_external_module_registers_real_tools_and_skills(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "catalog_external_demo"
    package.mkdir()
    write_skill(package / "skills" / "external-skill", name="external-skill")
    (package / "__init__.py").write_text(
        """from pathlib import Path


def register_extensions(catalog, registry):
    catalog.register_module(
        {
            "id": "vendor.external",
            "name": "External demo",
            "version": "2.0.0",
            "capabilities": ["inventory.read"],
            "permissions": ["assets.view"],
            "skills": ["external-skill"],
        },
        root=Path(__file__).parent,
    )
    registry.register_tool(
        "vendor.external",
        name="external_echo",
        description="Echo through the configured extension entry point.",
        permissions=("assets.view",),
        capabilities=("inventory.read",),
        parameters={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        handler=_echo,
    )


def _echo(context, **arguments):
    return {"source": context.source, "arguments": arguments}
""",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    catalog = SkillCatalog()
    registry = ExtensionRegistry(catalog, reserved_names=TOOL_NAMES)

    loaded = load_extension_modules(catalog, registry, ["catalog_external_demo"])

    assert loaded == ("catalog_external_demo",)
    assert catalog.get_module("vendor.external")["enabled"] is True
    assert "external-skill" in {skill["name"] for skill in catalog.list_skills()}
    assert [tool["name"] for tool in registry.list_tools()] == ["external_echo"]

    catalog.set_module_enabled("vendor.external", False)

    assert registry.list_tools() == []
    assert "external-skill" not in {skill["name"] for skill in catalog.list_skills()}


def test_external_module_loader_rejects_bad_or_empty_entry_points(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "catalog_external_empty"
    package.mkdir()
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    catalog = SkillCatalog()
    registry = ExtensionRegistry(catalog)

    with pytest.raises(InvalidExtension):
        load_extension_modules(catalog, registry, "catalog_external_demo")
    with pytest.raises(InvalidExtension):
        load_extension_modules(catalog, registry, ["../escape"])
    with pytest.raises(InvalidExtension):
        load_extension_modules(catalog, registry, ["catalog_missing_module"])
    with pytest.raises(InvalidExtension):
        load_extension_modules(catalog, registry, ["catalog_external_empty"])


def test_skill_digest_is_deterministic_and_covers_every_file() -> None:
    catalog = SkillCatalog()
    package = catalog.get_skill("itsm-inventory")

    expected = hashlib.sha256()
    for name in sorted(package["files"]):
        expected.update(name.encode("utf-8"))
        expected.update(b"\0")
        expected.update(package["files"][name])
        expected.update(b"\0")

    assert package["digest"] == expected.hexdigest()
    assert package_digest(package["files"]) == package["digest"]
    assert SkillCatalog().get_skill("itsm-inventory")["digest"] == package["digest"]

    tampered = dict(package["files"])
    tampered["SKILL.md"] += b"\n"
    assert package_digest(tampered) != package["digest"]


def test_unknown_skill_is_reported_without_a_path() -> None:
    catalog = SkillCatalog()

    with pytest.raises(SkillNotFound) as failure:
        catalog.get_skill("missing-skill")

    assert str(failure.value) == "skill is not in the catalog"


def test_register_module_adds_skills_files_and_metadata(tmp_path: Path) -> None:
    catalog = SkillCatalog()
    manifest, root = write_module(tmp_path)

    catalog.register_module(manifest, root=root)

    listed = {item["name"]: item for item in catalog.list_skills()}
    assert listed["demo-skill"]["module"] == "vendor.demo"
    assert listed["demo-skill"]["version"] == "1.2.0"
    assert listed["demo-skill"]["digest"] == package_digest(files_of(root))

    package = catalog.get_skill("demo-skill")
    assert package["files"]["SKILL.md"].startswith(b"---\n")
    assert package["files"]["references/notes.md"] == b"Local note.\n"

    modules = {module["id"]: module for module in catalog.list_modules()}
    assert modules["vendor.demo"] == {
        "id": "vendor.demo",
        "name": "Demo module",
        "version": "1.2.0",
        "official": False,
        "enabled": True,
        "permissions": ["assets.view"],
        "capabilities": ["inventory.read"],
        "skills": ["demo-skill"],
    }


def test_module_conflicts_are_rejected(tmp_path: Path) -> None:
    catalog = SkillCatalog()
    manifest, root = write_module(tmp_path, module_id="vendor.one")
    catalog.register_module(manifest, root=root)

    with pytest.raises(ModuleConflict):
        catalog.register_module(manifest, root=root)

    collision_manifest, collision_root = write_module(
        tmp_path,
        module_id="vendor.two",
        skill="itsm-inventory",
    )
    with pytest.raises(ModuleConflict):
        catalog.register_module(collision_manifest, root=collision_root)


def test_module_root_containment_and_digest_validation(tmp_path: Path) -> None:
    catalog = SkillCatalog()
    manifest, root = write_module(tmp_path)
    manifest["skillDigests"] = {"demo-skill": "0" * 64}

    with pytest.raises(InvalidSkillPackage) as failure:
        catalog.register_module(manifest, root=root)
    assert "digest" in str(failure.value)
    assert "demo-skill" not in {item["name"] for item in catalog.list_skills()}

    outside = tmp_path / "outside"
    write_skill(outside, name="escape")
    escape_root = tmp_path / "vendor.escape"
    (escape_root / "skills").mkdir(parents=True)
    (escape_root / "skills" / "escape").symlink_to(outside, target_is_directory=True)
    with pytest.raises(InvalidSkillPackage):
        catalog.register_module(
            {
                "id": "vendor.escape",
                "name": "Escape",
                "version": "1.0.0",
                "capabilities": ["inventory.read"],
                "permissions": ["assets.view"],
                "skills": ["escape"],
            },
            root=escape_root,
        )

    traversal = tmp_path / "vendor.traversal"
    traversal.mkdir()
    with pytest.raises(InvalidSkillPackage):
        catalog.register_module(
            {
                "id": "vendor.traversal",
                "name": "Traversal",
                "version": "1.0.0",
                "capabilities": ["inventory.read"],
                "permissions": ["assets.view"],
                "skills": ["../outside"],
            },
            root=traversal,
        )


def test_skill_permissions_beyond_the_module_manifest_are_rejected(tmp_path: Path) -> None:
    catalog = SkillCatalog()
    manifest, root = write_module(
        tmp_path,
        permissions=("assets.view",),
        skill_permission="assets.edit",
    )

    with pytest.raises(InvalidSkillPackage):
        catalog.register_module(manifest, root=root)


def test_disabled_module_immediately_excludes_skills_and_tools(tmp_path: Path) -> None:
    catalog = SkillCatalog()
    manifest, root = write_module(tmp_path)
    catalog.register_module(manifest, root=root)
    registry = ExtensionRegistry(catalog)
    registry.register_tool(
        "vendor.demo",
        name="demo_echo",
        description="Echo one bounded argument through the module.",
        permissions=("assets.view",),
        capabilities=("inventory.read",),
        parameters=parameters(query="string"),
        handler=echo_handler,
    )

    assert [tool["name"] for tool in registry.list_tools()] == ["demo_echo"]
    assert "demo-skill" in {item["name"] for item in catalog.list_skills()}

    catalog.set_module_enabled("vendor.demo", False)

    assert "demo-skill" not in {item["name"] for item in catalog.list_skills()}
    with pytest.raises(SkillNotFound):
        catalog.get_skill("demo-skill")
    assert registry.list_tools() == []
    with pytest.raises(ModuleUnavailable):
        registry.invoke(
            "demo_echo",
            {"query": "x"},
            context=ExtensionContext(
                settings=None, session=None, identity=None, principal=None, source="test"
            ),
        )

    catalog.set_module_enabled("vendor.demo", True)
    assert [tool["name"] for tool in registry.list_tools()] == ["demo_echo"]

    with pytest.raises(UnknownModule):
        catalog.set_module_enabled("vendor.missing", False)


def test_extension_tool_registration_requires_declared_known_capabilities(
    tmp_path: Path,
) -> None:
    catalog = tools_only_module(tmp_path)
    registry = ExtensionRegistry(catalog, reserved_names=TOOL_NAMES)

    with pytest.raises(InvalidExtension):
        registry.register_tool(
            "vendor.missing",
            name="missing_tool",
            description="Not registered.",
            permissions=("assets.view",),
            capabilities=("inventory.read",),
            parameters=parameters(),
            handler=echo_handler,
        )
    with pytest.raises(ExtensionConflict):
        registry.register_tool(
            "vendor.demo",
            name="search_assets",
            description="Shadowing the core tool is forbidden.",
            permissions=("assets.view",),
            capabilities=("inventory.read",),
            parameters=parameters(),
            handler=echo_handler,
        )

    async def async_handler(context: ExtensionContext, **arguments: Any) -> dict[str, Any]:
        return arguments

    with pytest.raises(InvalidExtension):
        registry.register_tool(
            "vendor.demo",
            name="async_tool",
            description="Async handlers would escape the bounded call path.",
            permissions=("assets.view",),
            capabilities=("inventory.read",),
            parameters=parameters(),
            handler=async_handler,
        )


def test_extension_tools_reject_unknown_permissions_and_capabilities(tmp_path: Path) -> None:
    catalog = tools_only_module(tmp_path)
    registry = ExtensionRegistry(catalog, reserved_names=TOOL_NAMES)

    with pytest.raises(InvalidExtension):
        registry.register_tool(
            "vendor.demo",
            name="shell_tool",
            description="Generic execution is not a capability.",
            permissions=("system.shell",),
            capabilities=("inventory.read",),
            parameters=parameters(),
            handler=echo_handler,
        )
    with pytest.raises(InvalidExtension):
        registry.register_tool(
            "vendor.demo",
            name="http_tool",
            description="Generic HTTP is not a capability.",
            permissions=("assets.view",),
            capabilities=("system.http",),
            parameters=parameters(),
            handler=echo_handler,
        )
    with pytest.raises(InvalidExtension):
        registry.register_tool(
            "vendor.demo",
            name="escalated_tool",
            description="A tool cannot exceed its module permissions.",
            permissions=("assets.edit", "reports.share"),
            capabilities=("inventory.read",),
            parameters=parameters(),
            handler=echo_handler,
        )


def test_extension_arguments_are_validated_before_any_handler_or_permission_check(
    tmp_path: Path,
) -> None:
    catalog = tools_only_module(tmp_path)
    registry = ExtensionRegistry(catalog)
    registry.register_tool(
        "vendor.demo",
        name="demo_echo",
        description="Echo one bounded argument.",
        permissions=("assets.view",),
        capabilities=("inventory.read",),
        parameters=parameters(query="string", limit="integer"),
        handler=echo_handler,
    )
    context = ExtensionContext(
        settings=None, session=None, identity=None, principal=object(), source="test"
    )

    with pytest.raises(InvalidExtension):
        registry.invoke("demo_echo", {"query": "x"}, context=context)
    with pytest.raises(InvalidExtension):
        registry.invoke("demo_echo", {"query": "x", "limit": 1, "extra": True}, context=context)
    with pytest.raises(InvalidExtension):
        registry.invoke("demo_echo", {"query": 5, "limit": 1}, context=context)
    with pytest.raises(ExtensionNotFound):
        registry.invoke("missing_tool", {}, context=context)


def test_extension_invocation_enforces_real_machine_identity_permissions(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    harness = make_harness(settings_factory)
    # Public MCP and extension services use the real clock, including token expiry.
    harness.clock = datetime.now(UTC)
    try:
        with harness.service() as service:
            service.bootstrap_superadmin("ana.admin", "Ana Admin", PASSWORD)
            admin = service.login("ana.admin", PASSWORD)
            service.create_user(
                admin.principal,
                username="agent.ops",
                name="Ops agent",
                role_id="operator",
                actor_kind="internal_agent",
            )
            service.create_user(
                admin.principal,
                username="agent.reader",
                name="Reader agent",
                role_id="user",
                actor_kind="external_agent",
            )
            operator_credential = service.issue_machine_credential("agent.ops")
            reader_credential = service.issue_machine_credential("agent.reader")

        catalog = tools_only_module(tmp_path)
        registry = ExtensionRegistry(catalog)
        registry.register_tool(
            "vendor.demo",
            name="demo_saved_views",
            description="Read the caller's own saved views through the canonical service.",
            permissions=("assets.edit",),
            capabilities=("inventory.read",),
            parameters=parameters(),
            handler=canonical_views,
        )

        CALLS.clear()
        with Session(harness.engine) as session:
            identity = IdentityService(session, harness.settings)
            operator = identity.authenticate_token(operator_credential.token)
            result = registry.invoke(
                "demo_saved_views",
                {},
                context=ExtensionContext(
                    settings=harness.settings,
                    session=session,
                    identity=identity,
                    principal=operator.principal,
                ),
            )
        assert result["views"] == []
        assert CALLS == [{}]
        assert [tool["name"] for tool in registry.list_tools(permissions=operator.permissions)] == [
            "demo_saved_views"
        ]

        CALLS.clear()
        with Session(harness.engine) as session:
            identity = IdentityService(session, harness.settings)
            reader = identity.authenticate_token(reader_credential.token)
            assert registry.list_tools(permissions=reader.permissions) == []
            with pytest.raises(PermissionDenied):
                registry.invoke(
                    "demo_saved_views",
                    {},
                    context=ExtensionContext(
                        settings=harness.settings,
                        session=session,
                        identity=identity,
                        principal=reader.principal,
                    ),
                )
        assert CALLS == []
    finally:
        harness.close()


def test_bind_fastmcp_tools_installs_real_callable_tools_and_visibility(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    catalog = tools_only_module(tmp_path)
    registry = ExtensionRegistry(catalog, reserved_names=TOOL_NAMES)
    registry.register_tool(
        "vendor.demo",
        name="demo_echo",
        description="Echo one bounded argument.",
        permissions=("assets.view",),
        capabilities=("inventory.read",),
        parameters=parameters(query="string"),
        handler=echo_handler,
    )
    settings = settings_factory()

    def unused_session() -> Session:
        raise AssertionError("the transport has no trusted bearer")

    async def scenario() -> None:
        server = FastMCP("catalog-test")
        mount = bind_fastmcp_tools(
            server, registry, settings=settings, session_factory=unused_session
        )
        assert mount.tool_names == ("demo_echo",)
        scoped = AuthenticatedUser(
            AccessToken(token="bearer", client_id="test", scopes=["assets.view"])
        )
        token = auth_context_var.set(scoped)
        try:
            assert "demo_echo" in {tool.name for tool in await server.list_tools()}

            catalog.set_module_enabled("vendor.demo", False)
            mount.sync()
            assert "demo_echo" not in {tool.name for tool in await server.list_tools()}

            catalog.set_module_enabled("vendor.demo", True)
            mount.sync()
            assert "demo_echo" in {tool.name for tool in await server.list_tools()}
        finally:
            auth_context_var.reset(token)

        denied = AuthenticatedUser(
            AccessToken(token="bearer", client_id="test", scopes=["people.view"])
        )
        token = auth_context_var.set(denied)
        try:
            assert "demo_echo" not in {tool.name for tool in await server.list_tools()}
        finally:
            auth_context_var.reset(token)

        token = auth_context_var.set(scoped)
        try:
            with pytest.raises(ToolError, match="authentication required"):
                await server.call_tool("demo_echo", {"query": "x"})
        finally:
            auth_context_var.reset(token)

    asyncio.run(scenario())


def test_bind_fastmcp_tools_refuses_to_shadow_an_existing_server_tool(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    catalog = tools_only_module(tmp_path)
    registry = ExtensionRegistry(catalog)
    registry.register_tool(
        "vendor.demo",
        name="demo_echo",
        description="Echo one bounded argument.",
        permissions=("assets.view",),
        capabilities=("inventory.read",),
        parameters=parameters(query="string"),
        handler=echo_handler,
    )
    server = FastMCP("catalog-test")
    server.add_tool(
        FunctionTool(
            name="demo_echo",
            description="Existing tool.",
            parameters=parameters(query="string"),
            fn=lambda **arguments: arguments,
        )
    )

    with pytest.raises(ExtensionConflict):
        bind_fastmcp_tools(
            server,
            registry,
            settings=settings_factory(),
            session_factory=lambda: None,
        )
