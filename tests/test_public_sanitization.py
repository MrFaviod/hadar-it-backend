"""Publication privacy gate for the backend sources.

The backend is published as an independent repository, so the files a reader can
check out must not describe the private installation it was written for: real
organization and site names, real private network addresses, the administrator's
home path or a local design-tool project id. The same gate covers the ignore
rules that keep local agent records and local snapshots out of the published
history, and keeps published docs from pointing at those unpublished records.

These checks read the working tree only; they never depend on Git history or on
Git being available at all.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.conftest import BACKEND_ROOT

# Directories and files that are published as product or public documentation.
PRODUCT_ROOTS = ("itsm", "tests", "docs", "migrations")
PRODUCT_FILES = (
    ".dockerignore",
    ".gitignore",
    "Dockerfile",
    "Dockerfile.extension-validator",
    "Dockerfile.ops",
    "README.md",
    "alembic.ini",
    "pyproject.toml",
    "requirements-dev.txt",
    "requirements.txt",
)
TEXT_SUFFIXES = frozenset(
    {".cfg", ".ini", ".js", ".json", ".mako", ".md", ".py", ".toml", ".txt", ".yaml", ".yml"}
)
# Local records that are kept outside the published history, plus this file,
# which has to spell out the patterns it forbids.
EXCLUDED_FILES = frozenset({"AGENTS.md", "tests/test_public_sanitization.py"})
EXCLUDED_PREFIXES = ("docs/reviews/",)

# (label, pattern). The label is what a failing test reports, so no private
# value from the file is echoed into the output.
DENYLIST: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("real organization name", re.compile(("pro" + "ducar"), re.IGNORECASE)),
    ("real site name", re.compile(r"bella\s+vista", re.IGNORECASE)),
    ("real city name", re.compile(("san" + r"\s+lorenzo"), re.IGNORECASE)),
    (
        "identifier derived from the real site",
        re.compile(r"\b[A-Za-z]{2,5}-BV\b", re.IGNORECASE),
    ),
    ("real private network", re.compile(r"\b192\.168\.120\.\d+")),
    ("real private network", re.compile(r"\b192\.168\.10\.\d+")),
    ("real private network", re.compile(r"\b10\.30\.\d+\.\d+")),
    ("administrator home path", re.compile("/home/" + "infor" + "matica")),
    ("local design-tool project id", re.compile("78077567-3e32-" + "4db7-92e0-6ca8cf4d351b")),
    (
        "organization-specific domain",
        re.compile((r"(?:empresa|pro" + r"ducar)\.local"), re.IGNORECASE),
    ),
)

# Ignore rules that keep local-only records out of the published tree.
REQUIRED_IGNORE_RULES = {
    ".dockerignore": ("AGENTS.md", "odd/", "docs/reviews/", ".worktrees/", ".publish/", ".env*"),
    ".gitignore": ("AGENTS.md", "odd/", "docs/reviews/", ".worktrees/", ".publish/", ".env*"),
}


def _published_sources() -> Iterator[tuple[str, Path]]:
    """Yield the relative path and location of every published text file."""
    seen: set[Path] = set()
    for name in PRODUCT_FILES:
        path = BACKEND_ROOT / name
        if path.is_file():
            seen.add(path)
            yield name, path
    for root in PRODUCT_ROOTS:
        for path in sorted((BACKEND_ROOT / root).rglob("*")):
            if not path.is_file() or path.suffix not in TEXT_SUFFIXES:
                continue
            relative = path.relative_to(BACKEND_ROOT).as_posix()
            if relative in EXCLUDED_FILES or relative.startswith(EXCLUDED_PREFIXES):
                continue
            if any(part.startswith(".") for part in path.relative_to(BACKEND_ROOT).parts):
                continue
            if path in seen:
                continue
            seen.add(path)
            yield relative, path


def _violations(relative: str, text: str) -> list[str]:
    return [
        f"{relative}:{text.count(chr(10), 0, match.start()) + 1} matches {label}"
        for label, pattern in DENYLIST
        for match in pattern.finditer(text)
    ]


# Published docs must not link or point at local records that are never published.
LOCAL_RECORD_REFERENCE = re.compile(r"(?<![\w.-])(?:odd/|AGENTS" + r"\.md\b|docs/" + r"reviews/)")


def test_every_published_root_file_is_scanned() -> None:
    scanned = {relative for relative, _ in _published_sources()}
    root_files = {
        path.name
        for path in BACKEND_ROOT.iterdir()
        if path.is_file() and path.name not in EXCLUDED_FILES
    }
    assert sorted(root_files - scanned) == []


def test_published_documents_do_not_reference_unpublished_local_records() -> None:
    found = [
        f"{relative}:{number}"
        for relative, path in _published_sources()
        if path.suffix == ".md"
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if LOCAL_RECORD_REFERENCE.search(line)
    ]
    assert found == []


def test_published_sources_carry_no_private_installation_identifiers() -> None:
    found: list[str] = []
    for relative, path in _published_sources():
        found.extend(_violations(relative, path.read_text(encoding="utf-8", errors="replace")))
    assert found == []


@pytest.mark.parametrize("name", sorted(REQUIRED_IGNORE_RULES))
def test_ignore_rules_keep_local_records_out_of_the_published_tree(name: str) -> None:
    rules = (BACKEND_ROOT / name).read_text(encoding="utf-8").splitlines()
    entries = {line.strip() for line in rules if line.strip() and not line.startswith("#")}
    missing = [rule for rule in REQUIRED_IGNORE_RULES[name] if rule not in entries]
    assert missing == []


@pytest.mark.parametrize(
    "sample",
    [
        ("SW-" + "BV-001"),
        ("sw-" + "bv-001"),
        ("PLANO-" + "BV-2026"),
        ("MCP-" + "BV-001"),
        ("ip 192.168." + "120.11"),
        ("ip 192.168." + "10.5"),
        ("ip 10." + "30.4.9"),
        ("ops@pro" + "ducar.local"),
        ("branding: Pro" + "ducar"),
        ("site: Bella" + " Vista"),
        ("site: San" + " Lorenzo"),
        ("san" + "  lorenzo"),
        ("/home/" + "infor" + "matica/Dev"),
        ("78077567-3e32-" + "4db7-92e0-6ca8cf4d351b"),
    ],
)
def test_gate_recognizes_private_installation_identifiers(sample: str) -> None:
    assert _violations("sample.py", sample) != []


def test_gate_accepts_the_published_replacements() -> None:
    sample = (
        '{"quickCode": "SW-SN-001", "site": "Sede Norte", "ip": "192.168.50.11"}\n'
        '{"contact": "bruno@example.invalid", "branding": "Acme"}\n'
        "/srv/itsm/backend/.venv/bin/python -m pytest tests/test_generic.py -q\n"
        "ITSM_AI_PERSONAL_PRIVATE_ENDPOINTS=192.168.1.0/24,models.internal:8443\n"
    )
    assert _violations("sample.py", sample) == []
