"""Offline project documentation: pack contract, search, pagination and refusals.

Every service test runs against a minimal pack written to a temporary directory and
marked ``"fixture": true``. The last test loads the committed pack and asserts its
shape and that no forbidden path or secret-bearing document slipped in.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any

import pytest
from itsm.project_context import ProjectContextService
from itsm.project_context import service as project_context_service
from itsm.project_context import tools as project_context_tools
from itsm.project_context.service import (
    InvalidCapability,
    InvalidQuery,
    ProjectContextError,
    SectionNotFound,
    UnknownDocument,
)

FIXTURE_TEXT = "documentation " + "lorem ipsum " * 750
FORBIDDEN_NAMES = frozenset({"AGENTS.md", "SYSTEM.md", "IDEA.md", "AGENTS.local.md"})
FORBIDDEN_PREFIXES = ("odd/", "docs/reviews/", ".git/", "backend/", "frontend/")
FORBIDDEN_SUFFIXES = frozenset(
    {".log", ".bak", ".dump", ".sql", ".db", ".sqlite", ".pem", ".key", ".p12", ".zip"}
)


def _section(title: str, anchor: str, text: str, level: int = 2) -> dict[str, Any]:
    return {"title": title, "anchor": anchor, "level": level, "text": text}


def _document(path: str, title: str, sections: list[dict[str, Any]]) -> dict[str, Any]:
    body = "\n\n".join(section["text"] for section in sections)
    return {
        "path": path,
        "title": title,
        "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "bytes": len(body.encode("utf-8")),
        "sections": sections,
    }


def _fixture_documents() -> list[dict[str, Any]]:
    large = [
        _section(
            f"Part {index}", f"part-{index}", f"## Part {index}\n\ndocumentation for part {index}."
        )
        for index in range(1, 26)
    ]
    return [
        _document(
            "README.md",
            "Hadar IT",
            [
                _section(
                    "Installation",
                    "installation",
                    "## Installation\n\n"
                    "Run `docker compose up`; the installation documentation starts here.",
                ),
                _section(
                    "Backup and restore",
                    "backup-and-restore",
                    "## Backup and restore\n\nExport the backup volume before an upgrade.",
                ),
            ],
        ),
        _document(
            "docs/operations.md",
            "Operations",
            [
                _section(
                    "Backups",
                    "backups",
                    "## Backups\n\nA daily backup runs at 02:00 and keeps seven copies.",
                ),
                _section(
                    "Monitoring",
                    "monitoring",
                    "## Monitoring\n\n"
                    "The documentation of monitoring lives next to the dashboards.",
                ),
            ],
        ),
        _document(
            "docs/technical-guide.md",
            "Technical guide",
            [
                _section(
                    "Architecture",
                    "architecture",
                    "## Architecture\n\n"
                    "The backup writer, backup reader and backup scheduler share "
                    "one lock; documentation belongs with the code.",
                ),
                _section("Appendix", "appendix", "## Appendix\n\n" + FIXTURE_TEXT),
            ],
        ),
        _document(
            "docs/user-operations.md",
            "User operations",
            [
                _section("Overview", "overview", "This guide is for operators.", level=0),
                _section(
                    "Restore",
                    "restore",
                    "## Restore\n\nRestore the backup named in the backup catalog; documentation "
                    "for operators stays short.",
                ),
            ],
        ),
        _document("docs/large.md", "Large", large),
    ]


def _write_fixture(tmp_path: Path, *, fixture: bool = True) -> Path:
    path = tmp_path / "pack.json"
    payload = {
        "schema": "project-context-pack",
        "schema_version": 1,
        "fixture": fixture,
        "generated_by": "tests/test_project_context.py",
        "source_digest": hashlib.sha256(b"fixture-source").hexdigest(),
        "components": {"backend": "9.9.9", "frontend": "8.8.8"},
        "documents": _fixture_documents(),
    }
    serialized = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.write_text(serialized, encoding="utf-8")
    return path


@pytest.fixture
def pack_path(tmp_path: Path) -> Path:
    return _write_fixture(tmp_path)


@pytest.fixture
def context(pack_path: Path) -> ProjectContextService:
    return ProjectContextService(pack_path)


def test_fixture_pack_is_loaded_and_marked(context: ProjectContextService) -> None:
    assert context.fixture is True
    view = context.get_project_context()
    assert view.fixture is True
    assert view.pack_schema_version == 1


def test_project_context_reports_versions_digest_and_documents(
    context: ProjectContextService, pack_path: Path
) -> None:
    view = context.get_project_context()

    assert view.component_versions == {"backend": "9.9.9", "frontend": "8.8.8"}
    assert view.source_digest == hashlib.sha256(b"fixture-source").hexdigest()
    assert view.runtime_digest is None
    assert view.stale is False
    paths = [document.path for document in view.documents]
    assert paths == sorted(paths)
    assert "README.md" in paths
    by_path = {document.path: document for document in view.documents}
    assert by_path["README.md"].sections == 2
    assert by_path["README.md"].characters > 0
    assert by_path["docs/large.md"].sections == 25


def test_capability_flags_cover_the_four_states_and_stay_pure(
    context: ProjectContextService,
) -> None:
    capabilities = {
        "workflows": "wip",
        "inventory": "installed",
        "search": "available",
        "ai": "configured",
    }
    first = context.list_project_capabilities(capabilities)
    second = context.list_project_capabilities(capabilities)

    assert first == second
    assert capabilities["inventory"] == "installed"
    assert [flag.name for flag in first.flags] == ["ai", "inventory", "search", "workflows"]
    assert first.counts == {"installed": 1, "configured": 1, "available": 1, "wip": 1}

    view = context.get_project_context(capabilities=capabilities)
    assert view.capabilities == first
    assert view.capabilities.flags[2].state == "available"

    with pytest.raises(InvalidCapability):
        context.list_project_capabilities({"inventory": "ready"})
    with pytest.raises(InvalidCapability):
        context.list_project_capabilities({"": "installed"})


def test_staleness_only_reports_when_runtime_digest_differs(
    context: ProjectContextService,
) -> None:
    matching = context.get_project_context(
        runtime_digest=hashlib.sha256(b"fixture-source").hexdigest()
    )
    assert matching.stale is False
    assert matching.runtime_digest == hashlib.sha256(b"fixture-source").hexdigest()

    stale = context.get_project_context(runtime_digest="0" * 64)
    assert stale.stale is True
    assert stale.source_digest == hashlib.sha256(b"fixture-source").hexdigest()
    assert stale.runtime_digest == "0" * 64


def test_search_ranks_titles_above_body_hits_and_is_deterministic(
    context: ProjectContextService,
) -> None:
    first = context.search_project_docs("backup")
    second = context.search_project_docs("backup")

    assert first == second
    assert first.total == 4
    assert [match.path for match in first.matches] == [
        "README.md",
        "docs/operations.md",
        "docs/technical-guide.md",
        "docs/user-operations.md",
    ]
    assert [match.anchor for match in first.matches] == [
        "backup-and-restore",
        "backups",
        "architecture",
        "restore",
    ]
    scores = [match.score for match in first.matches]
    assert scores == sorted(scores, reverse=True)
    assert all(len(match.snippet) <= 400 for match in first.matches)


def test_search_paginates_and_caps_the_page_size(context: ProjectContextService) -> None:
    page = context.search_project_docs("documentation", limit=2, offset=0)
    assert page.total == 30
    assert page.limit == 2
    assert len(page.matches) == 2
    assert page.truncated is True

    tail = context.search_project_docs("documentation", limit=2, offset=28)
    assert len(tail.matches) == 2
    assert tail.truncated is False
    assert [match.path for match in page.matches] == [
        "README.md",
        "docs/large.md",
    ]

    capped = context.search_project_docs("documentation", limit=1000)
    assert capped.limit == 20
    assert len(capped.matches) == 20
    assert capped.truncated is True
    assert all(len(match.snippet) <= 400 for match in capped.matches)

    beyond = context.search_project_docs("documentation", offset=10_000)
    assert beyond.matches == []
    assert beyond.truncated is False


def test_search_rejects_empty_or_oversized_queries(context: ProjectContextService) -> None:
    with pytest.raises(InvalidQuery):
        context.search_project_docs("   ")
    with pytest.raises(InvalidQuery):
        context.search_project_docs("a")
    with pytest.raises(InvalidQuery):
        context.search_project_docs("x" * 201)


def test_read_whole_document_and_named_sections(context: ProjectContextService) -> None:
    whole = context.read_project_doc("README.md", limit=8000)
    assert whole.path == "README.md"
    assert whole.section is None
    assert whole.anchor is None
    assert whole.text.startswith("## Installation")
    assert "## Backup and restore" in whole.text
    assert whole.total_chars == len(whole.text)
    assert whole.truncated is False
    assert whole.next_offset is None

    by_anchor = context.read_project_doc("README.md", section="installation")
    assert by_anchor.text.startswith("## Installation")
    assert by_anchor.anchor == "installation"
    by_title = context.read_project_doc("README.md", section="Installation")
    assert by_title.text == by_anchor.text

    preamble = context.read_project_doc("docs/user-operations.md", section="overview")
    assert preamble.text == "This guide is for operators."

    with pytest.raises(SectionNotFound):
        context.read_project_doc("README.md", section="no-such-section")


def test_read_paginates_and_caps_characters(context: ProjectContextService) -> None:
    head = context.read_project_doc("docs/technical-guide.md", section="appendix", limit=10)
    assert len(head.text) == 10
    assert head.offset == 0
    assert head.limit == 10
    assert head.truncated is True
    assert head.next_offset == 10
    assert head.total_chars > 8_000

    next_page = context.read_project_doc(
        "docs/technical-guide.md", section="appendix", offset=head.next_offset, limit=10
    )
    assert next_page.offset == 10
    assert len(next_page.text) == 10
    assert next_page.text != head.text

    capped = context.read_project_doc(
        "docs/technical-guide.md", section="appendix", limit=1_000_000
    )
    assert capped.limit == 8_000
    assert len(capped.text) == 8_000
    assert capped.next_offset == 8_000
    assert capped.truncated is True

    beyond = context.read_project_doc(
        "docs/technical-guide.md", section="appendix", offset=1_000_000
    )
    assert beyond.text == ""
    assert beyond.next_offset is None
    assert beyond.truncated is False


def test_unknown_and_traversal_paths_are_refused(
    context: ProjectContextService, tmp_path: Path
) -> None:
    outside = tmp_path / "secret.txt"
    outside.write_text("do not read me", encoding="utf-8")
    for path in (
        "docs/does-not-exist.md",
        "../secret.txt",
        str(outside),
        "docs/../README.md",
        "./README.md",
        "README.md/../../etc/passwd",
        "odd/private.md",
        "AGENTS.md",
        ".env",
    ):
        with pytest.raises(UnknownDocument):
            context.read_project_doc(path)


def test_default_service_refuses_a_fixture_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(project_context_service, "DEFAULT_PACK_PATH", _write_fixture(tmp_path))
    with pytest.raises(ProjectContextError):
        ProjectContextService().get_project_context()


def test_tools_return_bounded_plain_payloads() -> None:
    context = project_context_tools.get_project_context()
    assert context["ok"] is True
    assert context["fixture"] is False
    assert context["component_versions"]["backend"]

    found = project_context_tools.search_project_docs("installation", limit=5)
    assert found["ok"] is True
    assert len(found["matches"]) <= 5
    assert all(len(match["snippet"]) <= 400 for match in found["matches"])

    read = project_context_tools.read_project_doc("README.md", limit=200)
    assert read["ok"] is True
    assert len(read["text"]) <= 200

    missing = project_context_tools.read_project_doc("../README.md")
    assert missing["ok"] is False
    assert missing["error"] == "unknown_document"


def test_committed_pack_loads_and_stays_inside_the_allowlist() -> None:
    context = ProjectContextService()
    assert context.fixture is False
    view = context.get_project_context()
    assert view.pack_schema_version == 1
    assert set(view.component_versions) == {"backend", "frontend"}
    assert view.documents

    summaries = {summary.path: summary for summary in view.documents}
    assert [document.path for document in context.documents] == sorted(summaries)
    for document in context.documents:
        path = document.path
        parts = path.split("/")
        assert not path.startswith(("/", "../")), path
        assert ".." not in parts, path
        assert not path.startswith(FORBIDDEN_PREFIXES), path
        assert parts[-1] not in FORBIDDEN_NAMES, path
        assert not parts[-1].startswith(".env"), path
        assert Path(path).suffix not in FORBIDDEN_SUFFIXES, path
        assert document.sha256 == document.sha256.lower()
        assert len(document.sha256) == 64, path
        assert len(document.sections) == summaries[path].sections, path
        assert document.sections, path
        anchors = [section.anchor for section in document.sections]
        assert len(set(anchors)) == len(anchors), path
        assert all(section.text.strip() for section in document.sections), path

    backend_version = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    assert view.component_versions["backend"] == backend_version


def test_committed_pack_answers_a_documentation_question() -> None:
    context = ProjectContextService()
    result = context.search_project_docs("installation", limit=5)
    assert result.total >= 1
    assert result.matches[0].path in {
        document.path for document in context.get_project_context().documents
    }
    read = context.read_project_doc(result.matches[0].path, limit=400)
    assert read.text
