"""The fixed typed system tools shared by the integrated agent and MCP."""

from __future__ import annotations

SYSTEM_TOOL_NAMES: tuple[str, ...] = (
    "get_system_status",
    "get_system_configuration",
    "list_system_providers",
    "configure_system_provider",
    "list_system_modules",
    "set_system_module",
    "prepare_system_update",
    "create_system_backup",
)

__all__ = ["SYSTEM_TOOL_NAMES"]
