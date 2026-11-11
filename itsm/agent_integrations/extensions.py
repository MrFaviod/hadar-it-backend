"""Permission-aware tool extensions supplied by ITSM modules.

A module cannot expose a tool by declaration alone: it registers a real sync
callable, and every listing and invocation re-reads the module state and the
trusted identity service. Handlers receive the already-resolved session,
``IdentityService`` and principal, so they call canonical domain services
instead of re-implementing business rules or shelling out.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from itsm.agent_integrations.catalog import (
    CAPABILITIES,
    SkillCatalog,
    UnknownModule,
)
from itsm.identity.permissions import is_known_permission
from itsm.identity.service import (
    AuthenticationFailed,
    IdentityService,
    PermissionDenied,
    Principal,
)

logger = logging.getLogger("itsm.agent_integrations")

TOOL_NAME: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
ARGUMENT_NAME: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")
MODULE_PATH: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
)

MAX_DESCRIPTION: Final[int] = 1024
_ARGUMENT_TYPES: Final[dict[str, Any]] = {
    "array": list,
    "boolean": bool,
    "number": (int, float),
    "object": dict,
    "string": str,
}
_SCHEMA_TYPES: Final[frozenset[str]] = frozenset(
    {"array", "boolean", "integer", "number", "object", "string"}
)


class ExtensionError(Exception):
    """Base class for module extension registration and invocation errors."""


class ExtensionConflict(ExtensionError):
    """The tool name is already registered or reserved by the core surface."""


class ExtensionNotFound(ExtensionError):
    """No extension tool is registered under that name."""


class ModuleUnavailable(ExtensionError):
    """The module that owns the tool is disabled or no longer registered."""


class InvalidExtension(ExtensionError):
    """A module tool declaration is invalid or escapes its declared authority."""


@dataclass(frozen=True)
class ExtensionContext:
    """Trusted server-side context; never populated from model arguments."""

    settings: Any
    session: Any
    identity: IdentityService
    principal: Principal
    source: str = "mcp"


@dataclass(frozen=True)
class _Tool:
    name: str
    description: str
    module_id: str
    permissions: tuple[str, ...]
    capabilities: tuple[str, ...]
    parameters: dict[str, Any]
    handler: Callable[..., Any]


def _declared(values: Sequence[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, str) or not isinstance(values, Sequence) or not values:
        raise InvalidExtension(f"{field_name} must be a non-empty list")
    items: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise InvalidExtension(f"{field_name} must contain non-empty strings")
        normalized = value.strip()
        if normalized in items:
            raise InvalidExtension(f"{field_name} must not repeat values")
        items.append(normalized)
    return tuple(sorted(items))


def _validate_parameters(schema: Any) -> dict[str, Any]:
    if not isinstance(schema, Mapping) or schema.get("type") != "object":
        raise InvalidExtension("parameters must be a JSON object schema")
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        raise InvalidExtension("parameters.properties must be a map")
    checked_properties: dict[str, dict[str, Any]] = {}
    for name, declaration in properties.items():
        if not isinstance(name, str) or not ARGUMENT_NAME.fullmatch(name):
            raise InvalidExtension("parameter names must be bounded identifiers")
        if not isinstance(declaration, Mapping):
            raise InvalidExtension("parameter declarations must be maps")
        kind = declaration.get("type")
        if kind not in _SCHEMA_TYPES:
            raise InvalidExtension(f"unsupported parameter type for {name}")
        checked_properties[name] = {"type": kind}
    required = schema.get("required", [])
    if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
        raise InvalidExtension("parameters.required must be a list of names")
    if not set(required) <= set(checked_properties):
        raise InvalidExtension("parameters.required must name a declared property")
    additional = schema.get("additionalProperties", False)
    if not isinstance(additional, bool):
        raise InvalidExtension("parameters.additionalProperties must be a boolean")
    return {
        "type": "object",
        "properties": checked_properties,
        "required": list(required),
        "additionalProperties": additional,
    }


def _matches(value: Any, kind: str) -> bool:
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "boolean":
        return isinstance(value, bool)
    return isinstance(value, _ARGUMENT_TYPES[kind])


def _check_arguments(parameters: Mapping[str, Any], arguments: Mapping[str, Any]) -> None:
    if not isinstance(arguments, Mapping):
        raise InvalidExtension("arguments must be an object")
    properties: Mapping[str, Any] = parameters["properties"]
    unknown = sorted(set(arguments) - set(properties))
    if unknown and not parameters["additionalProperties"]:
        raise InvalidExtension("unknown arguments: " + ", ".join(unknown))
    missing = [name for name in parameters["required"] if name not in arguments]
    if missing:
        raise InvalidExtension("missing arguments: " + ", ".join(sorted(missing)))
    for name, value in arguments.items():
        declaration = properties.get(name)
        if declaration is None:
            continue
        if not _matches(value, declaration["type"]):
            raise InvalidExtension(f"argument {name} must be {declaration['type']}")


class ExtensionRegistry:
    """Registers module tools and rechecks authority on every use."""

    def __init__(
        self,
        catalog: SkillCatalog,
        *,
        reserved_names: Iterable[str] = (),
    ) -> None:
        self._catalog = catalog
        self._reserved = frozenset(reserved_names)
        self._tools: dict[str, _Tool] = {}

    def register_tool(
        self,
        module_id: str,
        *,
        name: str,
        description: str,
        permissions: Sequence[str],
        capabilities: Sequence[str],
        parameters: Mapping[str, Any],
        handler: Callable[..., Any],
    ) -> None:
        """Bind one real callable to a module and its declared authority."""
        if not isinstance(name, str) or not TOOL_NAME.fullmatch(name):
            raise InvalidExtension("tool name must be a bounded lowercase identifier")
        if name in self._reserved:
            raise ExtensionConflict("tool name is reserved by the core MCP surface")
        if name in self._tools:
            raise ExtensionConflict("tool name is already registered")
        if not isinstance(description, str):
            raise InvalidExtension("description must be text")
        normalized_description = description.strip()
        if not 1 <= len(normalized_description) <= MAX_DESCRIPTION:
            raise InvalidExtension(f"description must be 1-{MAX_DESCRIPTION} characters")

        try:
            module = self._catalog.get_module(module_id)
        except UnknownModule:
            raise InvalidExtension("module is not registered") from None

        declared_permissions = _declared(permissions, "permissions")
        unknown_permissions = [
            code for code in declared_permissions if not is_known_permission(code)
        ]
        if unknown_permissions:
            raise InvalidExtension("unknown permissions: " + ", ".join(unknown_permissions))
        if not set(declared_permissions) <= set(module["permissions"]):
            raise InvalidExtension("tool permissions exceed the module manifest")

        declared_capabilities = _declared(capabilities, "capabilities")
        unknown_capabilities = [code for code in declared_capabilities if code not in CAPABILITIES]
        if unknown_capabilities:
            raise InvalidExtension("unknown capabilities: " + ", ".join(unknown_capabilities))
        if not set(declared_capabilities) <= set(module["capabilities"]):
            raise InvalidExtension("tool capabilities exceed the module manifest")

        if not callable(handler):
            raise InvalidExtension("handler must be callable")
        if inspect.iscoroutinefunction(handler):
            raise InvalidExtension("handler must be synchronous")

        self._tools[name] = _Tool(
            name=name,
            description=normalized_description,
            module_id=module_id,
            permissions=declared_permissions,
            capabilities=declared_capabilities,
            parameters=_validate_parameters(parameters),
            handler=handler,
        )

    def list_tools(self, *, permissions: Iterable[str] | None = None) -> list[dict[str, Any]]:
        """List enabled tools, optionally restricted to permissions the caller holds."""
        granted = None if permissions is None else frozenset(permissions)
        items: list[dict[str, Any]] = []
        for name in sorted(self._tools):
            tool = self._tools[name]
            if not self._module_enabled(tool.module_id):
                continue
            if granted is not None and not set(tool.permissions) <= granted:
                continue
            items.append(
                {
                    "name": tool.name,
                    "description": tool.description,
                    "module": tool.module_id,
                    "permissions": list(tool.permissions),
                    "capabilities": list(tool.capabilities),
                }
            )
        return items

    def invoke(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        context: ExtensionContext,
    ) -> Any:
        """Recheck module state and permissions, then call the canonical handler."""
        tool = self._tools.get(name)
        if tool is None:
            raise ExtensionNotFound("tool is not registered")
        if not self._module_enabled(tool.module_id):
            raise ModuleUnavailable("module is disabled")
        _check_arguments(tool.parameters, arguments)
        for permission in tool.permissions:
            context.identity.authorize(context.principal, permission)
        return tool.handler(context, **dict(arguments))

    def _module_enabled(self, module_id: str) -> bool:
        try:
            return bool(self._catalog.get_module(module_id)["enabled"])
        except UnknownModule:
            return False

    def _descriptors(self) -> list[_Tool]:
        return [self._tools[name] for name in sorted(self._tools)]


def load_extension_modules(
    catalog: SkillCatalog,
    registry: ExtensionRegistry,
    module_names: Iterable[str],
) -> tuple[str, ...]:
    """Load explicitly configured, pre-installed module entry points in order.

    There is no upload, directory scan or network discovery: operators install
    a trusted Python distribution in the backend environment and configure its
    dotted module name. Each module exposes a synchronous
    ``register_extensions(catalog, registry)`` function that registers exactly
    one module manifest and its real tool handlers. The function fails startup
    when a configured module is missing, does not expose the entry point, or
    registers no module manifest.
    """
    if isinstance(module_names, (str, bytes)):
        raise InvalidExtension("module names must be an iterable of dotted names")
    loaded: list[str] = []
    for name in module_names:
        if not isinstance(name, str) or not MODULE_PATH.fullmatch(name):
            raise InvalidExtension("module names must be dotted Python identifiers")
        if name in loaded:
            raise InvalidExtension("module names must not repeat")
        before = {module["id"] for module in catalog.list_modules()}
        try:
            module = importlib.import_module(name)
        except ImportError as exc:
            raise InvalidExtension(f"module {name} cannot be imported") from exc
        entry = getattr(module, "register_extensions", None)
        if not callable(entry) or inspect.iscoroutinefunction(entry):
            raise InvalidExtension(
                f"module {name} must define a synchronous register_extensions(catalog, registry)"
            )
        entry(catalog, registry)
        added = {item["id"] for item in catalog.list_modules()} - before
        if not added:
            raise InvalidExtension(f"module {name} registered no module manifest")
        loaded.append(name)
    return tuple(loaded)


class ExtensionToolMount:
    """Keeps FastMCP visibility in step with the catalog's module state."""

    def __init__(
        self,
        server: Any,
        registry: ExtensionRegistry,
        tool_names: tuple[str, ...],
    ) -> None:
        self._server = server
        self._registry = registry
        self._tool_names = tool_names
        self._disabled: set[str] = set()

    @property
    def tool_names(self) -> tuple[str, ...]:
        return self._tool_names

    def sync(self) -> None:
        """Apply enable/disable visibility after a module state transition."""
        target = {
            name
            for name in self._tool_names
            if not self._registry._module_enabled(self._registry._tools[name].module_id)
        }
        newly_disabled = target - self._disabled
        newly_enabled = self._disabled - target
        if newly_disabled:
            self._server.disable(names=newly_disabled)
        if newly_enabled:
            self._server.enable(names=newly_enabled)
        self._disabled = target


def _scope_gate(required: tuple[str, ...]) -> Callable[[Any], bool]:
    """List-time gate for a bearer token's effective permissions."""

    def allowed(context: Any) -> bool:
        token = getattr(context, "token", None)
        scopes = set(getattr(token, "scopes", None) or ())
        return set(required) <= scopes

    return allowed


def _server_has_tool(server: Any, name: str) -> bool:
    """Check FastMCP 4.1.3 local components without its async ``get_tool`` API.

    ``create_mcp_server`` builds the server synchronously, while ``get_tool`` is
    a coroutine method. The pinned FastMCP release stores added tools in the
    local provider's component map; reading that map keeps binding synchronous
    and fails closed when the internal shape is unavailable.
    """
    provider = getattr(server, "_local_provider", None)
    components = getattr(provider, "_components", None)
    if not isinstance(components, dict):
        return False
    prefix = f"tool:{name}@"
    return any(str(key).startswith(prefix) for key in components)


def bind_fastmcp_tools(
    server: Any,
    registry: ExtensionRegistry,
    *,
    settings: Any,
    session_factory: Callable[[], Any],
) -> ExtensionToolMount:
    """Mount every registered extension tool on the existing FastMCP server."""
    from fastmcp.exceptions import ToolError
    from fastmcp.server.dependencies import get_http_headers
    from fastmcp.tools.function_tool import FunctionTool

    descriptors = registry._descriptors()
    for tool in descriptors:
        if _server_has_tool(server, tool.name):
            raise ExtensionConflict(f"tool name is already registered: {tool.name}")

    def wrapper(tool: _Tool) -> Callable[..., Any]:
        def call(**arguments: Any) -> Any:
            try:
                headers = get_http_headers(include={"authorization"})
            except Exception:
                headers = {}
            scheme, _, token = str(headers.get("authorization", "")).partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                raise ToolError("authentication required")
            with session_factory() as session:
                identity = IdentityService(session, settings)
                try:
                    authenticated = identity.authenticate_token(token.strip())
                except AuthenticationFailed, PermissionDenied:
                    raise ToolError("authentication required") from None
                context = ExtensionContext(
                    settings=settings,
                    session=session,
                    identity=identity,
                    principal=authenticated.principal,
                    source="mcp",
                )
                try:
                    return registry.invoke(tool.name, arguments, context=context)
                except PermissionDenied:
                    raise ToolError("permission denied") from None
                except ModuleUnavailable:
                    raise ToolError("tool is not available") from None
                except ExtensionError as exc:
                    raise ToolError(str(exc)) from None
                except ToolError:
                    raise
                except Exception as exc:
                    logger.warning("extension tool failed: %s (%s)", tool.name, type(exc).__name__)
                    raise ToolError("tool failed") from None

        return call

    names: list[str] = []
    for tool in descriptors:
        server.add_tool(
            FunctionTool(
                name=tool.name,
                description=tool.description,
                parameters=tool.parameters,
                fn=wrapper(tool),
                auth=_scope_gate(tool.permissions),
            )
        )
        names.append(tool.name)

    mount = ExtensionToolMount(server, registry, tuple(names))
    mount.sync()
    return mount


__all__ = [
    "ExtensionConflict",
    "ExtensionContext",
    "ExtensionError",
    "ExtensionNotFound",
    "ExtensionRegistry",
    "ExtensionToolMount",
    "InvalidExtension",
    "ModuleUnavailable",
    "bind_fastmcp_tools",
    "load_extension_modules",
]
