"""Plain documentation tools, ready for one registration in the agent and MCP runtimes.

The functions take no principal and touch no database: they read the generated pack
through :class:`ProjectContextService` and return bounded plain dictionaries. T4b
registers them beside the core tools in ``itsm/agents/runtime.py`` and
``itsm/mcp/server.py``; nothing here registers itself.
"""

from __future__ import annotations

from typing import Any

from itsm.project_context.service import (
    InvalidArgument,
    InvalidCapability,
    InvalidQuery,
    ProjectContextError,
    ProjectContextService,
    ProjectContextUnavailable,
    SectionNotFound,
    UnknownDocument,
)

MAX_TOOL_MESSAGE = 200
MAX_TOOL_CAPABILITY_NAME = 64

_service: ProjectContextService | None = None


def _context() -> ProjectContextService:
    global _service
    if _service is None:
        _service = ProjectContextService()
    return _service


def _ok(payload: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, **payload}


def _failed(error: ProjectContextError) -> dict[str, Any]:
    return {"ok": False, "error": _error_code(error), "message": str(error)[:MAX_TOOL_MESSAGE]}


def _error_code(error: ProjectContextError) -> str:
    if isinstance(error, UnknownDocument):
        return "unknown_document"
    if isinstance(error, SectionNotFound):
        return "section_not_found"
    if isinstance(error, InvalidQuery):
        return "invalid_query"
    if isinstance(error, InvalidCapability):
        return "invalid_capability"
    if isinstance(error, InvalidArgument):
        return "invalid_argument"
    if isinstance(error, ProjectContextUnavailable):
        return "unavailable"
    return "project_context_error"


def get_project_context(capabilities: dict[str, str] | None = None) -> dict[str, Any]:
    """Report the documentation pack versions, digest, documents and capability flags.

    ``capabilities`` maps a capability name to one of ``installed``, ``configured``,
    ``available`` or ``wip``; the caller owns that state and this tool never guesses it.
    """
    try:
        view = _context().get_project_context(capabilities=capabilities)
    except ProjectContextError as error:
        return _failed(error)
    return _ok(view.model_dump(mode="json"))


def list_project_capabilities(capabilities: dict[str, str] | None = None) -> dict[str, Any]:
    """Group caller-supplied capability flags by installed, configured, available and wip."""
    try:
        summary = _context().list_project_capabilities(capabilities)
    except ProjectContextError as error:
        return _failed(error)
    return _ok(summary.model_dump(mode="json"))


def search_project_docs(query: str, limit: int = 10, offset: int = 0) -> dict[str, Any]:
    """Search the allowlisted product documentation and return ranked section matches.

    Each match carries the document path, section title, anchor and a snippet of at
    most 400 characters. ``limit`` is capped at 20 and ``offset`` pages the ranking.
    """
    try:
        result = _context().search_project_docs(query, limit=limit, offset=offset)
    except ProjectContextError as error:
        return _failed(error)
    return _ok(result.model_dump(mode="json"))


def read_project_doc(
    path: str,
    section: str | None = None,
    offset: int = 0,
    limit: int = 4_000,
) -> dict[str, Any]:
    """Read one allowlisted document or section, at most 8,000 characters per page.

    ``path`` must be a document in the pack; any other path is refused without touching
    the filesystem. ``section`` accepts a section title or its anchor.
    """
    try:
        result = _context().read_project_doc(path, section=section, offset=offset, limit=limit)
    except ProjectContextError as error:
        return _failed(error)
    return _ok(result.model_dump(mode="json"))
