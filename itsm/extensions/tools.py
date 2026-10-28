"""Bounded SDK tools shared by native chat and MCP transports.

Transports resolve the principal; handlers never accept actor IDs, approval,
commands, credentials or arbitrary host paths as model arguments.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from pydantic_ai import RunContext

from itsm.identity.service import ValidationFailed

DEVELOPMENT_TOOL_NAMES = (
    "extension_sdk_index",
    "extension_sdk_reference",
    "extension_workspace_create",
    "extension_workspace_files",
    "extension_workspace_read",
    "extension_workspace_write",
    "extension_workspace_validate",
    "extension_workspace_submit",
)
EXTENSION_TOOL_NAMES = (
    *DEVELOPMENT_TOOL_NAMES,
    "extension_list",
    "extension_operations",
    "extension_skill",
    "extension_invoke",
)


def dispatch_extension_tool(
    name: str,
    arguments: Mapping[str, Any],
    *,
    principal: Any,
    host: Any,
    development: Any,
) -> dict[str, Any]:
    """Enter the canonical host/development boundary with transport authority."""
    if name in DEVELOPMENT_TOOL_NAMES:
        return development.dispatch(name, arguments, principal)
    if name == "extension_list":
        if arguments:
            raise ValidationFailed("extension_list accepts no arguments")
        return host.discovery(principal)
    if name == "extension_operations":
        if set(arguments) != {"id"} or not isinstance(arguments["id"], str):
            raise ValidationFailed("extension_operations requires an extension id")
        return {"operations": host.operations(principal, arguments["id"])}
    if name == "extension_skill":
        if (
            set(arguments) != {"id", "name"}
            or not isinstance(arguments["id"], str)
            or not isinstance(arguments["name"], str)
        ):
            raise ValidationFailed("extension_skill requires an extension id and skill name")
        return host.skill(principal, arguments["id"], arguments["name"])
    if name == "extension_invoke":
        if (
            set(arguments) != {"id", "operation", "arguments"}
            or not isinstance(arguments["id"], str)
            or not isinstance(arguments["operation"], str)
            or not isinstance(arguments["arguments"], dict)
        ):
            raise ValidationFailed("extension_invoke requires id, operation and arguments")
        return {"result": host.invoke(principal, arguments["id"], arguments["operation"], arguments["arguments"])}
    raise ValidationFailed("unknown extension tool")


def register_agent_extension_tools(
    toolset: Any,
    execute: Callable[[Any, str, dict[str, Any]], dict[str, Any]],
) -> None:
    """Register typed model-facing contracts without exposing a generic executor."""

    @toolset.tool
    def extension_sdk_index(ctx: RunContext[Any]) -> dict[str, Any]:
        """Discover the extension SDK version, contracts, examples and development steps."""
        return execute(ctx.deps, "extension_sdk_index", {})

    @toolset.tool
    def extension_sdk_reference(ctx: RunContext[Any], name: str) -> dict[str, Any]:
        """Read a named SDK reference from the index; never reads arbitrary host paths."""
        return execute(ctx.deps, "extension_sdk_reference", {"name": name})

    @toolset.tool
    def extension_workspace_create(ctx: RunContext[Any], id: str, name: str, description: str) -> dict[str, Any]:
        """Generate an owned, independent native extension workspace from the working example."""
        return execute(ctx.deps, "extension_workspace_create", {"id": id, "name": name, "description": description})

    @toolset.tool
    def extension_workspace_files(ctx: RunContext[Any], workspace_id: str) -> dict[str, Any]:
        """List bounded package files in your own extension development workspace."""
        return execute(ctx.deps, "extension_workspace_files", {"workspace_id": workspace_id})

    @toolset.tool
    def extension_workspace_read(ctx: RunContext[Any], workspace_id: str, path: str) -> dict[str, Any]:
        """Read one relative package file in your owned workspace, not the core repository."""
        return execute(ctx.deps, "extension_workspace_read", {"workspace_id": workspace_id, "path": path})

    @toolset.tool
    def extension_workspace_write(ctx: RunContext[Any], workspace_id: str, path: str, content: str) -> dict[str, Any]:
        """Write bounded source in your workspace; editing invalidates previous validation."""
        return execute(ctx.deps, "extension_workspace_write", {"workspace_id": workspace_id, "path": path, "content": content})

    @toolset.tool
    def extension_workspace_validate(ctx: RunContext[Any], workspace_id: str) -> dict[str, Any]:
        """Validate the exact workspace package in the fixed offline isolated container."""
        return execute(ctx.deps, "extension_workspace_validate", {"workspace_id": workspace_id})

    @toolset.tool
    def extension_workspace_submit(ctx: RunContext[Any], workspace_id: str) -> dict[str, Any]:
        """Submit the validated immutable artifact for human review; cannot approve or install."""
        return execute(ctx.deps, "extension_workspace_submit", {"workspace_id": workspace_id})

    @toolset.tool
    def extension_list(ctx: RunContext[Any]) -> dict[str, Any]:
        """Discover installed native modules visible to your current permissions."""
        return execute(ctx.deps, "extension_list", {})

    @toolset.tool
    def extension_operations(ctx: RunContext[Any], id: str) -> dict[str, Any]:
        """Read parameter schemas and permissions for an installed module's authorized operations."""
        return execute(ctx.deps, "extension_operations", {"id": id})

    @toolset.tool
    def extension_skill(ctx: RunContext[Any], id: str, name: str) -> dict[str, Any]:
        """Read an enabled module's declared skill with current authorization."""
        return execute(ctx.deps, "extension_skill", {"id": id, "name": name})

    @toolset.tool
    def extension_invoke(ctx: RunContext[Any], id: str, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke one installed declared operation through live host authorization, never raw code."""
        return execute(ctx.deps, "extension_invoke", {"id": id, "operation": operation, "arguments": arguments})


def register_mcp_extension_tools(
    server: Any,
    execute: Callable[[str, dict[str, Any]], dict[str, Any]],
) -> None:
    """Expose the same bounded contracts through the authenticated MCP transport."""

    @server.tool
    def extension_sdk_index() -> dict[str, Any]:
        """Discover the native extension SDK, references, examples and development workflow."""
        return execute("extension_sdk_index", {})

    @server.tool
    def extension_sdk_reference(name: str) -> dict[str, Any]:
        """Read one named SDK reference, never an arbitrary filesystem path."""
        return execute("extension_sdk_reference", {"name": name})

    @server.tool
    def extension_workspace_create(id: str, name: str, description: str) -> dict[str, Any]:
        """Generate an actor-owned independent extension workspace."""
        return execute("extension_workspace_create", {"id": id, "name": name, "description": description})

    @server.tool
    def extension_workspace_files(workspace_id: str) -> dict[str, Any]:
        """List source files in your own bounded development workspace."""
        return execute("extension_workspace_files", {"workspace_id": workspace_id})

    @server.tool
    def extension_workspace_read(workspace_id: str, path: str) -> dict[str, Any]:
        """Read one relative package source file in your workspace."""
        return execute("extension_workspace_read", {"workspace_id": workspace_id, "path": path})

    @server.tool
    def extension_workspace_write(workspace_id: str, path: str, content: str) -> dict[str, Any]:
        """Write bounded module source; any edit invalidates the previous validation."""
        return execute("extension_workspace_write", {"workspace_id": workspace_id, "path": path, "content": content})

    @server.tool
    def extension_workspace_validate(workspace_id: str) -> dict[str, Any]:
        """Run the fixed offline validator with no host mounts or credentials."""
        return execute("extension_workspace_validate", {"workspace_id": workspace_id})

    @server.tool
    def extension_workspace_submit(workspace_id: str) -> dict[str, Any]:
        """Submit exact validated bytes for human approval; never installs automatically."""
        return execute("extension_workspace_submit", {"workspace_id": workspace_id})

    @server.tool
    def extension_list() -> dict[str, Any]:
        """List native modules visible to the authenticated machine's current grants."""
        return execute("extension_list", {})

    @server.tool
    def extension_operations(id: str) -> dict[str, Any]:
        """List authorized declared operation schemas for a native module."""
        return execute("extension_operations", {"id": id})

    @server.tool
    def extension_skill(id: str, name: str) -> dict[str, Any]:
        """Read an installed module skill with live module and identity checks."""
        return execute("extension_skill", {"id": id, "name": name})

    @server.tool
    def extension_invoke(id: str, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke a declared module operation through the canonical live permission boundary."""
        return execute("extension_invoke", {"id": id, "operation": operation, "arguments": arguments})
