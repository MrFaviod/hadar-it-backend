"""Validated shapes of the offline documentation pack and its service answers."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PACK_SCHEMA = "project-context-pack"
PACK_SCHEMA_VERSION = 1
CAPABILITY_STATES: tuple[str, ...] = ("installed", "configured", "available", "wip")
CapabilityState = Literal["installed", "configured", "available", "wip"]

MAX_SNIPPET = 400
MAX_SEARCH_RESULTS = 20
MAX_SEARCH_QUERY = 200
MAX_READ_CHARACTERS = 8_000
MAX_PATH = 300
MAX_TITLE = 300
MAX_CAPABILITY_NAME = 64
MAX_COMPONENT_VERSION = 64

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value: str, field: str, maximum: int) -> str:
    """Reject empty, oversized or control-bearing text from a pack."""
    text = value.strip()
    if not text:
        raise ValueError(f"{field} must not be empty")
    if len(text) > maximum:
        raise ValueError(f"{field} must be at most {maximum} characters")
    if _CONTROL.search(text):
        raise ValueError(f"{field} must not contain control characters")
    return text


class DocSection(BaseModel):
    """One heading-delimited section; ``text`` keeps its heading line."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str = Field(max_length=MAX_TITLE)
    anchor: str = Field(max_length=MAX_TITLE)
    level: int = Field(ge=0, le=6)
    text: str

    @field_validator("title", "anchor")
    @classmethod
    def _title(cls, value: str) -> str:
        return _clean(value, "section title", MAX_TITLE)


class DocumentEntry(BaseModel):
    """One allowlisted document with a content digest and its sections."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(max_length=MAX_PATH)
    title: str = Field(max_length=MAX_TITLE)
    sha256: str
    bytes: int = Field(ge=0)
    sections: list[DocSection] = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        text = _clean(value, "path", MAX_PATH)
        if text.startswith("/") or "\\" in text:
            raise ValueError("path must be relative POSIX")
        parts = text.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise ValueError("path must not traverse")
        return text

    @field_validator("title")
    @classmethod
    def _title(cls, value: str) -> str:
        return _clean(value, "document title", MAX_TITLE)

    @field_validator("sha256")
    @classmethod
    def _digest(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
        return value

    @model_validator(mode="after")
    def _unique_anchors(self) -> DocumentEntry:
        anchors = [section.anchor for section in self.sections]
        if len(set(anchors)) != len(anchors):
            raise ValueError("section anchors must be unique within a document")
        return self


class ProjectContextPack(BaseModel):
    """The generated pack: the only documentation source the service reads."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["project-context-pack"] = Field(default=PACK_SCHEMA, alias="schema")
    schema_version: int = Field(ge=1)
    fixture: bool = False
    generated_by: str = Field(max_length=200)
    source_digest: str
    components: dict[str, str]
    documents: list[DocumentEntry]

    @field_validator("schema_version")
    @classmethod
    def _version(cls, value: int) -> int:
        if value != PACK_SCHEMA_VERSION:
            raise ValueError(f"unsupported pack schema version: {value}")
        return value

    @field_validator("source_digest")
    @classmethod
    def _digest(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("source_digest must be 64 lowercase hexadecimal characters")
        return value

    @field_validator("components")
    @classmethod
    def _components(cls, value: dict[str, str]) -> dict[str, str]:
        if not value:
            raise ValueError("components must not be empty")
        cleaned: dict[str, str] = {}
        for name, version in value.items():
            key = _clean(name, "component name", MAX_CAPABILITY_NAME)
            cleaned[key] = _clean(version, "component version", MAX_COMPONENT_VERSION)
        return cleaned

    @model_validator(mode="after")
    def _unique_paths(self) -> ProjectContextPack:
        paths = [document.path for document in self.documents]
        if len(set(paths)) != len(paths):
            raise ValueError("document paths must be unique")
        return self


class _Answer(BaseModel):
    """Read-only service answers: immutable and closed to extra fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class DocumentSummary(_Answer):
    path: str
    title: str
    sha256: str
    sections: int = Field(ge=0)
    characters: int = Field(ge=0)


class CapabilityFlag(_Answer):
    name: str
    state: CapabilityState


class CapabilitySummary(_Answer):
    flags: list[CapabilityFlag]
    counts: dict[str, int]


class ProjectContextView(_Answer):
    pack_schema_version: int
    source_digest: str
    runtime_digest: str | None
    stale: bool
    fixture: bool
    generated_by: str
    component_versions: dict[str, str]
    documents: list[DocumentSummary]
    capabilities: CapabilitySummary


class DocMatch(_Answer):
    path: str
    section: str
    anchor: str
    score: int
    snippet: str = Field(max_length=MAX_SNIPPET)


class DocSearchResult(_Answer):
    query: str
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1)
    truncated: bool
    matches: list[DocMatch]


class DocReadResult(_Answer):
    path: str
    title: str
    section: str | None
    anchor: str | None
    offset: int = Field(ge=0)
    limit: int = Field(ge=1)
    total_chars: int = Field(ge=0)
    next_offset: int | None
    truncated: bool
    text: str
