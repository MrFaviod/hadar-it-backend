"""Offline project documentation: search, section reading and staleness reporting.

The service never reads the repository at request time. It loads one generated JSON
pack (``itsm/project_context/pack.json`` by default) and answers from memory, so a
question about the product documentation cannot reach the filesystem beyond that file.
Every answer is bounded: search snippets stop at 400 characters and document reads at
8,000 characters per page.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from itsm.project_context.schemas import (
    CAPABILITY_STATES,
    MAX_CAPABILITY_NAME,
    MAX_READ_CHARACTERS,
    MAX_SEARCH_QUERY,
    MAX_SEARCH_RESULTS,
    MAX_SNIPPET,
    CapabilityFlag,
    CapabilityState,
    CapabilitySummary,
    DocMatch,
    DocReadResult,
    DocSearchResult,
    DocSection,
    DocumentEntry,
    DocumentSummary,
    ProjectContextPack,
    ProjectContextView,
)

DEFAULT_PACK_PATH = Path(__file__).with_name("pack.json")
DEFAULT_SEARCH_LIMIT = 10
DEFAULT_READ_LIMIT = 4_000
SNIPPET_LEAD = 80
TOKEN = re.compile(r"[^\W_]+", re.UNICODE)


class ProjectContextError(Exception):
    """Base class for a pack or argument the documentation service refuses."""


class ProjectContextUnavailable(ProjectContextError):
    """The pack is missing, unreadable or does not validate."""


class InvalidArgument(ProjectContextError):
    """A caller-supplied argument is outside the documented bounds."""


class InvalidQuery(InvalidArgument):
    """A search query is empty, too long or carries no usable word."""


class InvalidCapability(InvalidArgument):
    """A capability name or state is outside the four known states."""


class UnknownDocument(ProjectContextError):
    """The requested path is not in the pack; nothing else is opened."""


class SectionNotFound(ProjectContextError):
    """The document exists but carries no section with that title or anchor."""


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidArgument(f"{field} must be an integer")
    return value


def _words(text: str) -> list[str]:
    return TOKEN.findall(text.casefold())


def _query_tokens(query: Any) -> list[str]:
    if not isinstance(query, str):
        raise InvalidQuery("query must be text")
    text = query.strip()
    if not text or len(text) > MAX_SEARCH_QUERY:
        raise InvalidQuery(f"query must be 1-{MAX_SEARCH_QUERY} characters")
    tokens = list(dict.fromkeys(token for token in _words(text) if len(token) >= 2))
    if not tokens:
        raise InvalidQuery("query must contain a word of at least two characters")
    return tokens


def _snippet(text: str, tokens: list[str]) -> str:
    """Return a deterministic window around the first hit, at most 400 characters."""
    lowered = text.casefold()
    hits = [position for token in tokens if (position := lowered.find(token)) >= 0]
    start = max(0, min(hits) - SNIPPET_LEAD) if hits else 0
    window = " ".join(text[start : start + MAX_SNIPPET].split())
    return window[:MAX_SNIPPET]


def _section(document: DocumentEntry, name: str) -> DocSection:
    if not isinstance(name, str):
        raise InvalidArgument("section must be text or null")
    needle = name.strip().casefold()
    if not needle:
        raise SectionNotFound("section must not be empty")
    for section in document.sections:
        if section.anchor.casefold() == needle:
            return section
    for section in document.sections:
        if section.title.casefold() == needle:
            return section
    raise SectionNotFound(f"no section named {name.strip()[:80]} in {document.path}")


def _document_text(document: DocumentEntry) -> str:
    return "\n\n".join(section.text for section in document.sections)


def capability_summary(capabilities: Mapping[str, str] | None = None) -> CapabilitySummary:
    """Group caller-supplied capability states; pure, and never guesses a state."""
    if capabilities is None:
        capabilities = {}
    if not isinstance(capabilities, Mapping):
        raise InvalidCapability("capabilities must map a name to one known state")
    entries: list[tuple[str, str]] = []
    for name, state in capabilities.items():
        if not isinstance(name, str) or not isinstance(state, str):
            raise InvalidCapability("capability names and states must be text")
        normalized = name.strip()
        if not normalized or len(normalized) > MAX_CAPABILITY_NAME:
            raise InvalidCapability(f"capability name must be 1-{MAX_CAPABILITY_NAME} characters")
        if state not in CAPABILITY_STATES:
            raise InvalidCapability(f"unknown capability state: {state.strip()[:32]}")
        entries.append((normalized, state))
    entries.sort()
    counts = dict.fromkeys(CAPABILITY_STATES, 0)
    for _, state in entries:
        counts[state] += 1
    return CapabilitySummary(
        flags=[
            CapabilityFlag(name=name, state=cast(CapabilityState, state)) for name, state in entries
        ],
        counts=counts,
    )


class ProjectContextService:
    """Read the generated pack and answer documentation questions without a database."""

    def __init__(self, pack_path: str | Path | None = None) -> None:
        self._explicit_path = pack_path is not None
        self._requested_path = Path(pack_path) if pack_path is not None else None
        self._pack: ProjectContextPack | None = None
        self._index: dict[str, DocumentEntry] | None = None

    @property
    def pack_path(self) -> Path:
        return self._requested_path if self._requested_path is not None else DEFAULT_PACK_PATH

    @property
    def pack(self) -> ProjectContextPack:
        """Load and validate the pack once, then keep it in memory."""
        if self._pack is None:
            self._pack = self._load()
            self._index = {document.path: document for document in self._pack.documents}
        return self._pack

    @property
    def fixture(self) -> bool:
        return self.pack.fixture

    @property
    def documents(self) -> list[DocumentEntry]:
        return sorted(self.pack.documents, key=lambda document: document.path)

    def _load(self) -> ProjectContextPack:
        path = self.pack_path
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as error:
            raise ProjectContextUnavailable("the project context pack is unavailable") from error
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ProjectContextUnavailable("the project context pack is not valid JSON") from error
        if not isinstance(payload, dict):
            raise ProjectContextUnavailable("the project context pack must be a JSON object")
        try:
            pack = ProjectContextPack.model_validate(payload)
        except ValidationError as error:
            raise ProjectContextUnavailable(
                f"the project context pack is invalid ({error.error_count()} problem(s))"
            ) from error
        if pack.fixture and not self._explicit_path:
            raise ProjectContextUnavailable("the installed project context pack is a test fixture")
        return pack

    def _document(self, path: Any) -> DocumentEntry:
        _ = self.pack
        if not isinstance(path, str):
            raise UnknownDocument("path must be text")
        document = (self._index or {}).get(path)
        if document is None:
            raise UnknownDocument(
                f"no document named {path.strip()[:120]} in the project context pack"
            )
        return document

    def get_project_context(
        self,
        runtime_digest: str | None = None,
        capabilities: Mapping[str, str] | None = None,
    ) -> ProjectContextView:
        """Report pack identity, documents and capability flags, and detect drift."""
        if runtime_digest is not None and not isinstance(runtime_digest, str):
            raise InvalidArgument("runtime_digest must be text or null")
        pack = self.pack
        return ProjectContextView(
            pack_schema_version=pack.schema_version,
            source_digest=pack.source_digest,
            runtime_digest=runtime_digest,
            stale=runtime_digest is not None and runtime_digest != pack.source_digest,
            fixture=pack.fixture,
            generated_by=pack.generated_by,
            component_versions=dict(sorted(pack.components.items())),
            documents=[
                DocumentSummary(
                    path=document.path,
                    title=document.title,
                    sha256=document.sha256,
                    sections=len(document.sections),
                    characters=sum(len(section.text) for section in document.sections),
                )
                for document in self.documents
            ],
            capabilities=capability_summary(capabilities),
        )

    def list_project_capabilities(
        self, capabilities: Mapping[str, str] | None = None
    ) -> CapabilitySummary:
        """Group installed, configured, available and work-in-progress flags."""
        return capability_summary(capabilities)

    def search_project_docs(
        self, query: str, limit: int = DEFAULT_SEARCH_LIMIT, offset: int = 0
    ) -> DocSearchResult:
        """Rank sections by title and body hits; ties follow path and section order."""
        tokens = _query_tokens(query)
        page_limit = max(1, min(_integer(limit, "limit"), MAX_SEARCH_RESULTS))
        start = max(0, _integer(offset, "offset"))
        ranked: list[tuple[int, str, int, DocSection]] = []
        for document in self.documents:
            for index, section in enumerate(document.sections):
                title = section.title.casefold()
                body = section.text.casefold()
                title_hits = sum(title.count(token) for token in tokens)
                body_hits = sum(body.count(token) for token in tokens)
                if not title_hits and not body_hits:
                    continue
                score = min(title_hits, 3) * 6 + min(body_hits, 10)
                ranked.append((-score, document.path, index, section))
        ranked.sort(key=lambda item: (item[0], item[1], item[2]))
        selected = ranked[start : start + page_limit]
        return DocSearchResult(
            query=query.strip(),
            total=len(ranked),
            offset=start,
            limit=page_limit,
            truncated=start + len(selected) < len(ranked),
            matches=[
                DocMatch(
                    path=path,
                    section=section.title,
                    anchor=section.anchor,
                    score=-negative_score,
                    snippet=_snippet(section.text, tokens),
                )
                for negative_score, path, _, section in selected
            ],
        )

    def read_project_doc(
        self,
        path: str,
        section: str | None = None,
        offset: int = 0,
        limit: int = DEFAULT_READ_LIMIT,
    ) -> DocReadResult:
        """Read one allowlisted document or section, paginated by characters."""
        document = self._document(path)
        start = max(0, _integer(offset, "offset"))
        page_limit = max(1, min(_integer(limit, "limit"), MAX_READ_CHARACTERS))
        if section is None:
            text = _document_text(document)
            section_title = None
            anchor = None
        else:
            entry = _section(document, section)
            text = entry.text
            section_title = entry.title
            anchor = entry.anchor
        total = len(text)
        chunk = text[start : start + page_limit]
        next_offset = start + len(chunk)
        truncated = next_offset < total
        return DocReadResult(
            path=document.path,
            title=document.title,
            section=section_title,
            anchor=anchor,
            offset=start,
            limit=page_limit,
            total_chars=total,
            next_offset=next_offset if truncated else None,
            truncated=truncated,
            text=chunk,
        )
