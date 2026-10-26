"""Scoped, idempotent installation of ITSM MCP configuration and Agent Skills.

The installer is a pure engine-neutral boundary.  It mutates only the explicitly
selected profile/workspace, writes a managed-resource manifest, and verifies the
configured MCP endpoint with a real FastMCP handshake and authorized read-only
query before it reports ``verified``.  It never scans a home directory and never
persists a bearer token: configuration contains an environment-variable
reference, and the token is resolved from the process environment for proof only.
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import hmac
import json
import os
import re
import tempfile
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from inspect import isawaitable
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

ProfileInspector = Callable[..., Awaitable[Mapping[str, Any] | None]]

SCHEMA_VERSION = 1
MANIFEST_RELATIVE = ".itsm-agent/manifest.json"
DEFAULT_AGENT = "itsm"
DEFAULT_SKILLS = (
    "itsm-inventory",
    "itsm-infrastructure",
    "itsm-monitoring",
    "itsm-incidents",
    "itsm-maintenance",
    "itsm-reporting",
    "itsm-operations",
)
OPERATIONS = {"install", "verify", "update", "repair", "disable", "uninstall"}
STATUSES = {"verified", "configured", "conflict", "disabled", "removed", "failed"}
SECRET_REFERENCE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+][0-9A-Za-z.-]+)?$")
MAX_CONFIG_BYTES = 8 * 1024 * 1024
MCP_QUERY = ("search_assets", {"limit": 1})


class InstallerError(Exception):
    """Stable installer error with a public code and sanitized message."""

    def __init__(self, code: str, message: str, *, details: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details is not None:
            payload["details"] = self.details
        return payload


@dataclass(frozen=True, slots=True)
class IntegrationTarget:
    """Explicit installation target; ``path`` must be an absolute directory."""

    engine: str
    path: str
    profile: str | None = None
    version: str | None = None


@dataclass(slots=True)
class _Skill:
    name: str
    version: str
    digest: str
    files: dict[str, bytes]


@dataclass(slots=True)
class _TargetState:
    target: IntegrationTarget
    root: Path
    engine: str
    format: str
    version: str
    profile: str | None
    config_path: Path
    config_relative: str
    config_text: str | None
    config_exists: bool
    config_data: dict[str, Any] | None
    skills_relative: str
    limitations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class _Snapshot:
    path: Path
    exists: bool
    data: bytes
    mode: int


# --------------------------------------------------------------------------- digests


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def request_digest(request: Mapping[str, Any]) -> str:
    """Return the SHA-256 binding for a remote installer request."""
    body = {key: value for key, value in request.items() if key != "requestDigest"}
    return _sha256_bytes(_canonical(body))


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    """Return the SHA-256 binding for a helper receipt."""
    body = {key: value for key, value in receipt.items() if key != "receiptDigest"}
    return _sha256_bytes(_canonical(body))


def _package_digest(files: Mapping[str, bytes]) -> str:
    value = hashlib.sha256()
    for relative in sorted(files):
        value.update(relative.encode("utf-8"))
        value.update(b"\0")
        value.update(files[relative])
        value.update(b"\0")
    return "sha256:" + value.hexdigest()


def _file_digest(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _normalize_digest(value: str, code: str = "invalid_digest") -> str:
    if not isinstance(value, str):
        raise InstallerError(code, "digest must be text")
    normalized = value.strip().lower()
    if not normalized.startswith("sha256:"):
        normalized = "sha256:" + normalized
    raw = normalized.removeprefix("sha256:")
    if len(raw) != 64 or any(char not in "0123456789abcdef" for char in raw):
        raise InstallerError(code, "digest is not a SHA-256 value")
    return normalized


# --------------------------------------------------------------------------- paths


def _absolute_root(path: str) -> Path:
    if not isinstance(path, str) or not path.strip():
        raise InstallerError("target_path_invalid", "target path must be absolute text")
    candidate = Path(path)
    if not candidate.is_absolute() or any(part == ".." for part in candidate.parts):
        raise InstallerError(
            "target_path_invalid", "target path must be absolute without traversal segments"
        )
    if not candidate.exists():
        raise InstallerError("target_missing", "selected target directory does not exist")
    if candidate.is_symlink() or not candidate.is_dir():
        raise InstallerError("target_path_invalid", "selected target must be a real directory")
    return candidate


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _check_contained(root: Path, path: Path) -> None:
    """Reject traversal and symlinks between the target root and ``path``."""
    if not path.is_absolute() or any(part == ".." for part in path.parts):
        raise InstallerError("unsafe_path", "managed path escapes the selected target")
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise InstallerError("unsafe_path", "managed path is outside the selected target") from exc
    current = root
    if current.is_symlink():
        raise InstallerError("unsafe_path", "target root must not be a symbolic link")
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise InstallerError("unsafe_path", "managed path traverses a symbolic link")
    if not _inside(root, path):
        raise InstallerError("unsafe_path", "managed path escapes the selected target")


def _ensure_dir(root: Path, path: Path, created: list[str]) -> None:
    _check_contained(root, path)
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise InstallerError("unsafe_path", "managed directory is not a real directory")
        return
    missing: list[Path] = []
    current = path
    while current != root and not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        _check_contained(root, directory)
        directory.mkdir(mode=0o700)
        try:
            relative = directory.relative_to(root).as_posix()
        except ValueError as exc:  # pragma: no cover - guarded above
            raise InstallerError("unsafe_path", "managed directory escapes target") from exc
        created.append(relative)


def _atomic_write(path: Path, data: bytes, *, mode: int | None = None) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".itsm-", suffix=".tmp", dir=str(path.parent))
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        target_mode = mode
        if target_mode is None and path.exists():
            target_mode = path.stat().st_mode & 0o777
        os.chmod(temporary_path, target_mode if target_mode is not None else 0o600)
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _read_bounded(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_CONFIG_BYTES:
        raise InstallerError("config_invalid", "configuration file is too large")
    return path.read_bytes()


def _snapshot(path: Path) -> _Snapshot:
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise InstallerError("unsafe_path", "managed file is not a regular file")
        return _Snapshot(
            path=path,
            exists=True,
            data=path.read_bytes(),
            mode=path.stat().st_mode & 0o777,
        )
    return _Snapshot(path=path, exists=False, data=b"", mode=0o600)


class _Transaction:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.snapshots: dict[Path, _Snapshot] = {}
        self.created_dirs: list[str] = []
        self.written: list[Path] = []

    def _remember(self, path: Path) -> None:
        _check_contained(self.root, path)
        if path not in self.snapshots:
            self.snapshots[path] = _snapshot(path)

    def ensure_dir(self, path: Path) -> None:
        _ensure_dir(self.root, path, self.created_dirs)

    def write(self, path: Path, data: bytes, *, mode: int | None = None) -> None:
        self._remember(path)
        self.ensure_dir(path.parent)
        _atomic_write(path, data, mode=mode)
        self.written.append(path)

    def remove(self, path: Path) -> None:
        self._remember(path)
        if path.exists():
            path.unlink()
            self.written.append(path)

    def rollback(self) -> None:
        for path in reversed(self.written):
            snapshot = self.snapshots.get(path)
            if snapshot is None:
                continue
            if snapshot.exists:
                path.parent.mkdir(parents=True, exist_ok=True)
                _atomic_write(path, snapshot.data, mode=snapshot.mode)
            else:
                path.unlink(missing_ok=True)
        for relative in reversed(self.created_dirs):
            with contextlib.suppress(OSError):
                (self.root / relative).rmdir()


# --------------------------------------------------------------------------- JSONC


@dataclass(slots=True)
class _JsonMember:
    key: str
    key_start: int
    value: _JsonNode
    comma: int | None = None


@dataclass(slots=True)
class _JsonNode:
    kind: str
    start: int
    end: int
    value: Any
    members: list[_JsonMember] = field(default_factory=list)
    elements: list[_JsonNode] = field(default_factory=list)
    trailing_comma: bool = False


class _JsoncParser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.length = len(text)
        self.index = 0

    def parse(self) -> _JsonNode:
        node = self._value()
        self._space()
        if self.index != self.length:
            raise InstallerError("config_invalid", "configuration has trailing content")
        return node

    def _space(self) -> None:
        while self.index < self.length:
            char = self.text[self.index]
            if char in " \t\r\n":
                self.index += 1
                continue
            if self.text.startswith("//", self.index):
                end = self.text.find("\n", self.index)
                self.index = self.length if end < 0 else end + 1
                continue
            if self.text.startswith("/*", self.index):
                end = self.text.find("*/", self.index + 2)
                if end < 0:
                    raise InstallerError("config_invalid", "unterminated comment")
                self.index = end + 2
                continue
            return

    def _value(self) -> _JsonNode:
        self._space()
        if self.index >= self.length:
            raise InstallerError("config_invalid", "configuration is empty")
        char = self.text[self.index]
        if char == "{":
            return self._object()
        if char == "[":
            return self._array()
        if char == '"':
            return self._string()
        for word, value in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(word, self.index):
                start = self.index
                self.index += len(word)
                return _JsonNode("literal", start, self.index, value)
        match = re.match(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?", self.text[self.index :])
        if match:
            start = self.index
            self.index += len(match.group(0))
            return _JsonNode("number", start, self.index, json.loads(match.group(0)))
        raise InstallerError("config_invalid", "configuration contains an invalid value")

    def _string(self) -> _JsonNode:
        start = self.index
        self.index += 1
        escaped = False
        while self.index < self.length:
            char = self.text[self.index]
            if escaped:
                escaped = False
                self.index += 1
                continue
            if char == "\\":
                escaped = True
                self.index += 1
                continue
            if char == '"':
                self.index += 1
                raw = self.text[start : self.index]
                try:
                    value = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise InstallerError(
                        "config_invalid", "configuration string is invalid"
                    ) from exc
                return _JsonNode("string", start, self.index, value)
            if ord(char) < 0x20:
                raise InstallerError(
                    "config_invalid", "configuration string has a control character"
                )
            self.index += 1
        raise InstallerError("config_invalid", "unterminated string")

    def _object(self) -> _JsonNode:
        start = self.index
        self.index += 1
        members: list[_JsonMember] = []
        seen: set[str] = set()
        self._space()
        if self.index < self.length and self.text[self.index] == "}":
            self.index += 1
            return _JsonNode("object", start, self.index, {}, members)
        while True:
            self._space()
            if self.index >= self.length or self.text[self.index] != '"':
                raise InstallerError("config_invalid", "object key must be a string")
            key_node = self._string()
            key = key_node.value
            if key in seen:
                raise InstallerError("config_invalid", "configuration has duplicate keys")
            seen.add(key)
            self._space()
            if self.index >= self.length or self.text[self.index] != ":":
                raise InstallerError("config_invalid", "object key is missing a colon")
            self.index += 1
            value = self._value()
            member = _JsonMember(key, key_node.start, value)
            members.append(member)
            self._space()
            if self.index >= self.length:
                raise InstallerError("config_invalid", "unterminated object")
            if self.text[self.index] == ",":
                member.comma = self.index
                self.index += 1
                self._space()
                if self.index < self.length and self.text[self.index] == "}":
                    self.trailing_comma = True
                    self.index += 1
                    return _JsonNode(
                        "object",
                        start,
                        self.index,
                        {item.key: item.value.value for item in members},
                        members,
                        trailing_comma=True,
                    )
                continue
            if self.text[self.index] == "}":
                self.index += 1
                return _JsonNode(
                    "object",
                    start,
                    self.index,
                    {item.key: item.value.value for item in members},
                    members,
                )
            raise InstallerError("config_invalid", "object requires a comma or closing brace")

    def _array(self) -> _JsonNode:
        start = self.index
        self.index += 1
        elements: list[_JsonNode] = []
        self._space()
        if self.index < self.length and self.text[self.index] == "]":
            self.index += 1
            return _JsonNode("array", start, self.index, [], elements=elements)
        while True:
            element = self._value()
            elements.append(element)
            self._space()
            if self.index >= self.length:
                raise InstallerError("config_invalid", "unterminated array")
            if self.text[self.index] == ",":
                self.index += 1
                self._space()
                if self.index < self.length and self.text[self.index] == "]":
                    self.index += 1
                    return _JsonNode(
                        "array",
                        start,
                        self.index,
                        [item.value for item in elements],
                        elements=elements,
                        trailing_comma=True,
                    )
                continue
            if self.text[self.index] == "]":
                self.index += 1
                return _JsonNode(
                    "array",
                    start,
                    self.index,
                    [item.value for item in elements],
                    elements=elements,
                )
            raise InstallerError("config_invalid", "array requires a comma or closing bracket")


def _jsonc_parse(text: str) -> tuple[_JsonNode, str]:
    if not text.strip():
        text = "{}\n"
    parser = _JsoncParser(text)
    try:
        node = parser.parse()
    except InstallerError:
        raise
    except Exception as exc:  # pragma: no cover - defensive parser boundary
        raise InstallerError("config_invalid", "configuration could not be parsed") from exc
    if node.kind != "object":
        raise InstallerError("config_invalid", "configuration root must be an object")
    return node, text


def _jsonc_only_comments(text: str) -> bool:
    probe = text
    probe = re.sub(r"/\*.*?\*/", "", probe, flags=re.DOTALL)
    probe = re.sub(r"//[^\n]*", "", probe)
    return not probe.strip()


def _jsonc_value(text: str) -> dict[str, Any]:
    node, _ = _jsonc_parse(text)
    return node.value


def _jsonc_get(text: str, path: Sequence[str]) -> Any:
    value: Any = _jsonc_value(text)
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return _MISSING
        value = value[key]
    return value


def _jsonc_has(text: str, path: Sequence[str]) -> bool:
    return _jsonc_get(text, path) is not _MISSING


_MISSING = object()


def _jsonc_member(node: _JsonNode, key: str) -> _JsonMember | None:
    for member in node.members:
        if member.key == key:
            return member
    return None


def _jsonc_insert_member(text: str, node: _JsonNode, key: str, value: Any) -> tuple[str, int]:
    rendered = f"{json.dumps(key)}: {json.dumps(value, ensure_ascii=False)}"
    if not node.members:
        insertion = node.start + 1
        replacement = f"\n  {rendered}\n"
    else:
        insertion = node.end - 1
        replacement = rendered if node.trailing_comma else f", {rendered}"
    return text[:insertion] + replacement + text[insertion:], 0


def _jsonc_delete_member(text: str, node: _JsonNode, member: _JsonMember) -> str:
    if member.comma is not None:
        start, end = member.key_start, member.comma + 1
    else:
        index = node.members.index(member)
        if index == 0:
            start, end = member.key_start, member.value.end
        else:
            previous = node.members[index - 1]
            if previous.comma is None:  # pragma: no cover - parser invariant
                raise InstallerError("config_invalid", "object separator is missing")
            start, end = previous.comma, member.value.end
    return text[:start] + text[end:]


def _jsonc_set(text: str, path: Sequence[str], value: Any) -> str:
    if not path:
        raise InstallerError("config_invalid", "configuration path is empty")
    if _jsonc_only_comments(text):
        text = text.rstrip() + "\n{}\n"
    node, current_text = _jsonc_parse(text)
    current = node
    for index, key in enumerate(path):
        member = _jsonc_member(current, key)
        last = index == len(path) - 1
        if last:
            if value is _MISSING:
                if member is None:
                    return current_text
                return _jsonc_delete_member(current_text, current, member)
            if member is None:
                updated, _ = _jsonc_insert_member(current_text, current, key, value)
                return updated
            if member.value.value == value:
                return current_text
            return (
                current_text[: member.value.start]
                + json.dumps(value, ensure_ascii=False)
                + current_text[member.value.end :]
            )
        if member is None:
            nested = value
            for nested_key in reversed(path[index + 1 :]):
                nested = {nested_key: nested}
            updated, _ = _jsonc_insert_member(current_text, current, key, nested)
            return updated
        if member.value.kind != "object":
            raise InstallerError("config_invalid", "configuration section has an incompatible type")
        current = member.value
    raise InstallerError(
        "config_invalid", "configuration path could not be applied"
    )  # pragma: no cover


def _jsonc_empty_after(text: str) -> bool:
    value = _jsonc_value(text)
    return value == {}


# --------------------------------------------------------------------------- YAML source editing


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _key_line(line: str, key: str, indent: int) -> bool:
    if _indent(line) != indent:
        return False
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    head = stripped.split(":", 1)[0].strip().strip("'\"")
    return head == key and ":" in stripped


def _block_end(lines: list[str], start: int, indent: int) -> int:
    index = start + 1
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped:
            index += 1
            continue
        if stripped.startswith("#") and _indent(lines[index]) <= indent:
            break
        if _indent(lines[index]) <= indent:
            break
        index += 1
    return index


def _find_block(
    lines: list[str], key: str, indent: int, start: int = 0, stop: int | None = None
) -> tuple[int, int] | None:
    limit = len(lines) if stop is None else stop
    for index in range(start, limit):
        if _key_line(lines[index], key, indent):
            return index, _block_end(lines, index, indent)
    return None


def _replace_block(text: str, start: int, end: int, replacement: list[str]) -> str:
    lines = text.splitlines()
    lines[start:end] = replacement
    return "\n".join(lines) + "\n"


def _inline_value(line: str) -> str:
    return line.split(":", 1)[1].strip() if ":" in line else ""


def _yaml_load(text: str) -> dict[str, Any]:
    import yaml

    if not text.strip():
        return {}
    try:
        value = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise InstallerError("config_invalid", "configuration YAML is invalid") from exc
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise InstallerError("config_invalid", "configuration root must be a mapping")
    return value


def _yaml_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _hermes_mcp_lines(mcp: Mapping[str, Any], enabled: bool) -> list[str]:
    return [
        "  itsm:",
        f"    url: {_yaml_dump(mcp['url'])}",
        "    headers:",
        f"      Authorization: Bearer ${{{mcp['secretRef']}}}",
        f"    enabled: {'true' if enabled else 'false'}",
        "    tools:",
        "      prompts: false",
        "      resources: false",
    ]


def _hermes_set_entry(text: str, mcp: Mapping[str, Any], enabled: bool) -> tuple[str, bool]:
    lines = text.splitlines()
    parent = _find_block(lines, "mcp_servers", 0)
    entry = _hermes_mcp_lines(mcp, enabled)
    created = False
    if parent is None:
        block = ["mcp_servers:", *entry]
        base = text if not text else text.rstrip("\n") + "\n"
        return base + "\n".join(block) + "\n", True
    start, end = parent
    inline = _inline_value(lines[start])
    if inline and inline not in {"{}", "null", "~"}:
        raise InstallerError("config_invalid", "inline mcp_servers mapping is not safely editable")
    child = _find_block(lines, "itsm", 2, start + 1, end)
    if inline in {"{}", "null", "~"}:
        header = lines[start].split("#", 1)[0].rstrip()
        lines[start : start + 1] = [header, *entry]
        return "\n".join(lines) + "\n", True
    if child is None:
        lines[end:end] = entry
        created = True
    else:
        child_start, child_end = child
        lines[child_start:child_end] = entry
    return "\n".join(lines) + "\n", created


def _hermes_remove_entry(text: str, *, remove_parent: bool) -> tuple[str, bool]:
    lines = text.splitlines()
    parent = _find_block(lines, "mcp_servers", 0)
    if parent is None:
        return text, False
    start, end = parent
    child = _find_block(lines, "itsm", 2, start + 1, end)
    if child is None:
        return text, False
    child_start, child_end = child
    del lines[child_start:child_end]
    entry_removed = True
    if remove_parent:
        try:
            parent_value = _yaml_load("\n".join(lines)).get("mcp_servers")
        except InstallerError:
            parent_value = None
        if parent_value in ({}, None):
            current = _find_block(lines, "mcp_servers", 0)
            if current is not None:
                current_start, current_end = current
                del lines[current_start:current_end]
    return "\n".join(lines) + "\n", entry_removed


def _hermes_set_api_server(text: str, toolsets: list[str]) -> tuple[str, bool]:
    lines = text.splitlines()
    parent = _find_block(lines, "platform_toolsets", 0)
    if parent is None:
        block = ["platform_toolsets:", f"  api_server: {_yaml_dump(toolsets)}"]
        base = text if not text else text.rstrip("\n") + "\n"
        return base + "\n".join(block) + "\n", True
    start, end = parent
    inline = _inline_value(lines[start])
    if inline and inline not in {"{}", "null", "~"}:
        raise InstallerError(
            "config_invalid", "inline platform_toolsets mapping is not safely editable"
        )
    child = _find_block(lines, "api_server", 2, start + 1, end)
    value = f"  api_server: {_yaml_dump(toolsets)}"
    if inline in {"{}", "null", "~"}:
        header = lines[start].split("#", 1)[0].rstrip()
        lines[start : start + 1] = [header, value]
        return "\n".join(lines) + "\n", True
    if child is None:
        lines[end:end] = [value]
        return "\n".join(lines) + "\n", True
    child_start, child_end = child
    lines[child_start:child_end] = [value]
    return "\n".join(lines) + "\n", False


def _hermes_remove_api_server(text: str, *, remove_parent: bool) -> str:
    lines = text.splitlines()
    parent = _find_block(lines, "platform_toolsets", 0)
    if parent is None:
        return text
    start, end = parent
    child = _find_block(lines, "api_server", 2, start + 1, end)
    if child is None:
        return text
    child_start, child_end = child
    del lines[child_start:child_end]
    if remove_parent:
        try:
            parent_value = _yaml_load("\n".join(lines)).get("platform_toolsets")
        except InstallerError:
            parent_value = None
        if parent_value in ({}, None):
            current = _find_block(lines, "platform_toolsets", 0)
            if current is not None:
                current_start, current_end = current
                del lines[current_start:current_end]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- catalog


class _CatalogView:
    def __init__(self, catalog: Any | None) -> None:
        self.catalog = catalog

    def _resolved(self) -> Any:
        if self.catalog is not None:
            return self.catalog
        try:
            from itsm.agent_integrations.catalog import SkillCatalog
        except ImportError as exc:  # pragma: no cover - sibling integration state
            raise InstallerError("catalog_unavailable", "skill catalog is not available") from exc
        self.catalog = SkillCatalog()
        return self.catalog

    def skills(self, names: Sequence[str]) -> list[_Skill]:
        if not names:
            return []
        if len(set(names)) != len(names):
            raise InstallerError("invalid_skills", "skill names must be unique")
        catalog = self._resolved()
        resolved: list[_Skill] = []
        for name in names:
            if not isinstance(name, str) or not name.strip():
                raise InstallerError("invalid_skills", "skill name is invalid")
            try:
                payload = catalog.get_skill(name)
            except Exception as exc:
                raise InstallerError("unknown_skill", f"skill {name!r} is not available") from exc
            if not isinstance(payload, Mapping):
                raise InstallerError("catalog_invalid", "skill metadata is invalid")
            files = payload.get("files")
            if not isinstance(files, Mapping) or not files:
                raise InstallerError("catalog_invalid", f"skill {name!r} has no files")
            clean: dict[str, bytes] = {}
            for relative, data in files.items():
                if not isinstance(relative, str) or not isinstance(data, bytes):
                    raise InstallerError("catalog_invalid", f"skill {name!r} files are invalid")
                pure = PurePosixPath(relative)
                if (
                    pure.is_absolute()
                    or "\\" in relative
                    or any(part in {"", ".", ".."} for part in pure.parts)
                    or relative.startswith(".")
                ):
                    raise InstallerError(
                        "catalog_invalid", f"skill {name!r} contains an unsafe path"
                    )
                clean[relative] = data
            digest = _package_digest(clean)
            declared = payload.get("digest")
            if (
                declared is not None
                and _normalize_digest(str(declared), "catalog_invalid") != digest
            ):
                raise InstallerError(
                    "catalog_invalid", f"skill {name!r} digest does not match its files"
                )
            version = payload.get("version")
            if not isinstance(version, str) or not version:
                raise InstallerError("catalog_invalid", f"skill {name!r} version is invalid")
            resolved.append(_Skill(name=name, version=version, digest=digest, files=clean))
        return resolved


# --------------------------------------------------------------------------- target detection


def _parse_version(raw: str) -> tuple[int, int, int]:
    match = SEMVER.fullmatch(raw.strip())
    if not match:
        raise InstallerError("version_invalid", "engine version is not a supported version")
    return (
        int(match.group(1)),
        int(match.group(2) or 0),
        int(match.group(3) or 0),
    )


def _normalized_version(raw: str) -> str:
    major, minor, patch = _parse_version(raw)
    return f"{major}.{minor}.{patch}"


def _opencode_format(version: str) -> str:
    major, _, _ = _parse_version(version)
    if major == 1:
        return "v1"
    if major == 2:
        return "v2"
    raise InstallerError(
        "unsupported_version", "OpenCode version is not supported (v1/v2 required)"
    )


def _opencode_config_path(root: Path) -> tuple[Path, bool]:
    json_path = root / "opencode.json"
    jsonc_path = root / "opencode.jsonc"
    if json_path.exists() and jsonc_path.exists():
        raise InstallerError(
            "config_invalid", "both opencode.json and opencode.jsonc exist; selection is ambiguous"
        )
    if jsonc_path.exists():
        return jsonc_path, True
    if json_path.exists():
        return json_path, True
    return json_path, False


def _opencode_markers(data: Mapping[str, Any]) -> set[str]:
    markers: set[str] = set()
    mcp = data.get("mcp")
    if isinstance(mcp, Mapping) and "servers" in mcp:
        markers.add("v2")
    if isinstance(data.get("permissions"), list):
        markers.add("v2")
    if isinstance(data.get("agents"), Mapping):
        markers.add("v2")
    if isinstance(data.get("skills"), list):
        markers.add("v2")
    if isinstance(data.get("permission"), Mapping):
        markers.add("v1")
    if isinstance(data.get("agent"), Mapping):
        markers.add("v1")
    if isinstance(mcp, Mapping) and "servers" not in mcp and mcp:
        markers.add("v1")
    if isinstance(data.get("skills"), Mapping):
        markers.add("v1")
    return markers


def _detect_opencode(target: IntegrationTarget, root: Path) -> _TargetState:
    config_path, exists = _opencode_config_path(root)
    config_text = _read_bounded(config_path).decode("utf-8") if exists else None
    data: dict[str, Any] | None = None
    if config_text is not None:
        if _jsonc_only_comments(config_text):
            data = {}
        else:
            node, _ = _jsonc_parse(config_text)
            data = node.value
    markers = _opencode_markers(data or {})
    if len(markers) > 1:
        raise InstallerError(
            "config_invalid", "configuration mixes incompatible OpenCode generations"
        )
    detected = next(iter(markers)) if markers else None
    if target.version:
        version = _normalized_version(target.version)
        expected_format = _opencode_format(version)
    elif detected:
        version = "1.0.0" if detected == "v1" else "2.0.0"
        expected_format = detected
    else:
        raise InstallerError(
            "version_required", "OpenCode version is required for an empty configuration"
        )
    if detected and detected != expected_format:
        raise InstallerError(
            "config_format_mismatch", "configuration format does not match the selected version"
        )
    return _TargetState(
        target=target,
        root=root,
        engine="opencode",
        format=expected_format,
        version=version,
        profile=None,
        config_path=config_path,
        config_relative=config_path.name,
        config_text=config_text,
        config_exists=exists,
        config_data=data,
        skills_relative=".opencode/skills",
        limitations=[
            "OpenCode effective permissions can inherit configuration sources outside the "
            "selected target; authenticated runtime inspection is required to prove profile safety."
        ]
        if target.profile
        else [
            "OpenCode effective permissions can inherit global/workspace configuration sources; "
            "authenticated runtime inspection is required to prove profile safety."
        ],
    )


def _detect_hermes(target: IntegrationTarget, root: Path) -> _TargetState:
    if not target.version:
        raise InstallerError(
            "version_required",
            "Hermes version is required and must support MCP header interpolation",
        )
    version = _normalized_version(target.version)
    if _parse_version(version) < (0, 16, 0):
        raise InstallerError(
            "unsupported_version", "Hermes version is older than the supported 0.16.0 floor"
        )
    profile = target.profile or root.name
    if not PROFILE_NAME.fullmatch(profile):
        raise InstallerError("profile_invalid", "Hermes profile name is invalid")
    config_path = root / "config.yaml"
    config_text = None
    exists = config_path.exists()
    data: dict[str, Any] | None = None
    if exists:
        config_text = _read_bounded(config_path).decode("utf-8")
        data = _yaml_load(config_text)
    return _TargetState(
        target=target,
        root=root,
        engine="hermes",
        format="hermes",
        version=version,
        profile=profile,
        config_path=config_path,
        config_relative="config.yaml",
        config_text=config_text,
        config_exists=exists,
        config_data=data,
        skills_relative="skills",
        limitations=[
            "The Hermes HTTP API does not attest the active profile home; trusted profile "
            "verification is unavailable."
        ],
    )


# --------------------------------------------------------------------------- validation


def _validate_mcp(mcp: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(mcp, Mapping):
        raise InstallerError("invalid_mcp", "MCP configuration must be an object")
    unknown = set(mcp) - {"url", "secretRef", "identityId"}
    if unknown:
        raise InstallerError("invalid_mcp", "MCP configuration contains unsupported fields")
    url = mcp.get("url")
    secret_ref = mcp.get("secretRef")
    identity = mcp.get("identityId")
    if not isinstance(url, str) or not url:
        raise InstallerError("invalid_mcp", "MCP url is required")
    parts = urlsplit(url)
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.fragment
    ):
        raise InstallerError(
            "invalid_mcp", "MCP url must be an http(s) URL without credentials or fragments"
        )
    if not isinstance(secret_ref, str) or not SECRET_REFERENCE.fullmatch(secret_ref):
        raise InstallerError("invalid_mcp", "MCP secretRef must be an environment variable name")
    if not isinstance(identity, str) or not identity.strip() or len(identity) > 200:
        raise InstallerError("invalid_mcp", "MCP identityId is invalid")
    if any(ord(char) < 0x20 for char in identity):
        raise InstallerError("invalid_mcp", "MCP identityId is invalid")
    return {"url": url, "secretRef": secret_ref, "identityId": identity}


def _validate_operation(operation: str) -> str:
    if operation not in OPERATIONS:
        raise InstallerError("invalid_operation", "installer operation is not supported")
    return operation


def _validate_skill_names(skills: Sequence[str]) -> list[str]:
    if not isinstance(skills, list) or any(not isinstance(name, str) for name in skills):
        raise InstallerError("invalid_skills", "skills must be a list of names")
    if len(set(skills)) != len(skills):
        raise InstallerError("invalid_skills", "skill names must be unique")
    for name in skills:
        if not PROFILE_NAME.fullmatch(name):
            raise InstallerError("invalid_skills", "skill name is invalid")
    return list(skills)


def _manifest_path(root: Path) -> Path:
    return root / MANIFEST_RELATIVE


def _load_manifest(root: Path) -> tuple[dict[str, Any] | None, str | None]:
    path = _manifest_path(root)
    if not path.exists():
        return None, None
    _check_contained(root, path)
    if path.is_symlink() or not path.is_file():
        raise InstallerError("manifest_invalid", "managed manifest is not a regular file")
    try:
        data = json.loads(_read_bounded(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallerError("manifest_invalid", "managed manifest is invalid") from exc
    if (
        not isinstance(data, dict)
        or data.get("schemaVersion") != SCHEMA_VERSION
        or not isinstance(data.get("skills"), dict)
        or not isinstance(data.get("config"), dict)
        or data.get("targetPath") != str(root)
    ):
        raise InstallerError("manifest_invalid", "managed manifest has an unsupported shape")
    return data, _file_digest(path)


def _manifest_files(manifest: Mapping[str, Any]) -> dict[str, str]:
    files: dict[str, str] = {}
    config = manifest.get("config")
    if isinstance(config, Mapping) and isinstance(config.get("path"), str):
        files[config["path"]] = str(config.get("digest", ""))
    skills = manifest.get("skills")
    if isinstance(skills, Mapping):
        for payload in skills.values():
            if not isinstance(payload, Mapping):
                continue
            for relative, digest in (payload.get("files") or {}).items():
                files[str(relative)] = str(digest)
    return files


def _path_from_relative(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise InstallerError("manifest_invalid", "managed manifest contains an unsafe path")
    path = root.joinpath(*pure.parts)
    _check_contained(root, path)
    return path


def _target_state(target: IntegrationTarget) -> _TargetState:
    if not isinstance(target, IntegrationTarget):
        raise InstallerError("target_invalid", "target must be an IntegrationTarget")
    if target.engine not in {"opencode", "hermes"}:
        raise InstallerError("unsupported_engine", "installer engine is not supported")
    root = _absolute_root(target.path)
    if target.engine == "hermes":
        state = _detect_hermes(target, root)
        if target.profile and target.profile != root.name:
            raise InstallerError(
                "profile_mismatch", "target profile does not match the selected profile directory"
            )
    else:
        state = _detect_opencode(target, root)
    return state


# --------------------------------------------------------------------------- preflight


def _conflict(resource: str, reason: str) -> dict[str, str]:
    return {"resource": resource, "reason": reason}


def _skill_destinations(
    state: _TargetState, skills: Sequence[_Skill]
) -> dict[str, dict[str, Path]]:
    destinations: dict[str, dict[str, Path]] = {}
    base = state.root.joinpath(*PurePosixPath(state.skills_relative).parts)
    for skill in skills:
        destinations[skill.name] = {
            relative: base / skill.name / Path(*PurePosixPath(relative).parts)
            for relative in skill.files
        }
    return destinations


def _exists_foreign_skill(
    state: _TargetState, manifest: Mapping[str, Any] | None, skill: _Skill
) -> bool:
    base = state.root.joinpath(*PurePosixPath(state.skills_relative).parts) / skill.name
    if not base.exists() and not base.is_symlink():
        return False
    managed = set((manifest or {}).get("skills", {}))
    return skill.name not in managed


def _preflight_opencode(
    state: _TargetState, skills: Sequence[_Skill], manifest: Mapping[str, Any] | None
) -> None:
    data = state.config_data or {}
    conflicts: list[dict[str, str]] = []
    mcp = data.get("mcp")
    if state.format == "v2":
        if mcp is not None and not isinstance(mcp, Mapping):
            raise InstallerError("config_invalid", "mcp section must be an object")
        servers = mcp.get("servers") if isinstance(mcp, Mapping) else None
        if servers is not None and not isinstance(servers, Mapping):
            raise InstallerError("config_invalid", "mcp.servers section must be an object")
        if isinstance(servers, Mapping) and "itsm" in servers and manifest is None:
            conflicts.append(_conflict("mcp.servers.itsm", "existing ITSM entry is not managed"))
        agents = data.get("agents")
        if agents is not None and not isinstance(agents, Mapping):
            raise InstallerError("config_invalid", "agents section must be an object")
        if isinstance(agents, Mapping) and "itsm" in agents and manifest is None:
            conflicts.append(_conflict("agents.itsm", "existing ITSM agent is not managed"))
        if "permissions" in data and not isinstance(data["permissions"], list):
            raise InstallerError("config_invalid", "permissions must be an array for v2")
    else:
        if mcp is not None and not isinstance(mcp, Mapping):
            raise InstallerError("config_invalid", "mcp section must be an object")
        if isinstance(mcp, Mapping) and "itsm" in mcp and manifest is None:
            conflicts.append(_conflict("mcp.itsm", "existing ITSM entry is not managed"))
        agents = data.get("agent")
        if agents is not None and not isinstance(agents, Mapping):
            raise InstallerError("config_invalid", "agent section must be an object")
        if isinstance(agents, Mapping) and "itsm" in agents and manifest is None:
            conflicts.append(_conflict("agent.itsm", "existing ITSM agent is not managed"))
        if "permission" in data and not isinstance(data["permission"], Mapping):
            raise InstallerError("config_invalid", "permission must be an object for v1")
    default_agent = data.get("default_agent")
    if default_agent is not None and default_agent != DEFAULT_AGENT:
        conflicts.append(
            _conflict("default_agent", "a different default agent is already configured")
        )
    for skill in skills:
        base = state.root.joinpath(*PurePosixPath(state.skills_relative).parts) / skill.name
        if base.is_symlink():
            raise InstallerError("unsafe_path", "skill destination traverses a symbolic link")
        if _exists_foreign_skill(state, manifest, skill):
            conflicts.append(
                _conflict(
                    f"{state.skills_relative}/{skill.name}",
                    "skill directory already exists outside installer management",
                )
            )
    if conflicts:
        raise InstallerError(
            "conflict", "existing configuration conflicts with managed resources", details=conflicts
        )


def _preflight_hermes(
    state: _TargetState,
    skills: Sequence[_Skill],
    manifest: Mapping[str, Any] | None,
    mcp: Mapping[str, Any],
) -> None:
    data = state.config_data or {}
    conflicts: list[dict[str, str]] = []
    mcp_servers = data.get("mcp_servers")
    if mcp_servers is not None and not isinstance(mcp_servers, Mapping):
        raise InstallerError("config_invalid", "mcp_servers section must be a mapping")
    if isinstance(mcp_servers, Mapping) and "itsm" in mcp_servers and manifest is None:
        conflicts.append(_conflict("mcp_servers.itsm", "existing ITSM entry is not managed"))
    toolsets = data.get("platform_toolsets")
    if toolsets is not None and not isinstance(toolsets, Mapping):
        raise InstallerError("config_invalid", "platform_toolsets section must be a mapping")
    expected = ["itsm"] + (["skills"] if skills else [])
    if (
        isinstance(toolsets, Mapping)
        and "api_server" in toolsets
        and toolsets["api_server"] != expected
    ):
        conflicts.append(
            _conflict(
                "platform_toolsets.api_server",
                "existing API server toolset allowlist differs from the safe ITSM allowlist",
            )
        )
    agent = data.get("agent")
    if agent is not None and not isinstance(agent, Mapping):
        raise InstallerError("config_invalid", "agent section must be a mapping")
    disabled = agent.get("disabled_toolsets") if isinstance(agent, Mapping) else None
    if disabled is not None and not isinstance(disabled, list):
        raise InstallerError("config_invalid", "agent.disabled_toolsets must be a list")
    if isinstance(disabled, list) and {"itsm", "skills"} & set(disabled):
        conflicts.append(
            _conflict(
                "agent.disabled_toolsets",
                "global toolset suppression would override the ITSM allowlist",
            )
        )
    for skill in skills:
        base = state.root.joinpath(*PurePosixPath(state.skills_relative).parts) / skill.name
        if base.is_symlink():
            raise InstallerError("unsafe_path", "skill destination traverses a symbolic link")
        if _exists_foreign_skill(state, manifest, skill):
            conflicts.append(
                _conflict(
                    f"{state.skills_relative}/{skill.name}",
                    "skill directory already exists outside installer management",
                )
            )
    if conflicts:
        raise InstallerError(
            "conflict", "existing configuration conflicts with managed resources", details=conflicts
        )


def _preflight(
    state: _TargetState,
    skills: Sequence[_Skill],
    manifest: Mapping[str, Any] | None,
    mcp: Mapping[str, Any],
) -> None:
    if state.engine == "opencode":
        _preflight_opencode(state, skills, manifest)
    else:
        _preflight_hermes(state, skills, manifest, mcp)


# --------------------------------------------------------------------------- config plans


def _opencode_mcp(mcp: Mapping[str, Any], enabled: bool) -> dict[str, Any]:
    return {
        "type": "remote",
        "url": mcp["url"],
        "disabled": not enabled,
        "codemode": False,
        "oauth": False,
        "headers": {"Authorization": f"Bearer {{env:{mcp['secretRef']}}}"},
    }


def _opencode_v1_mcp(mcp: Mapping[str, Any], enabled: bool) -> dict[str, Any]:
    return {
        "type": "remote",
        "url": mcp["url"],
        "enabled": enabled,
        "oauth": False,
        "headers": {"Authorization": f"Bearer {{env:{mcp['secretRef']}}}"},
    }


def _opencode_agent(skill_names: Sequence[str]) -> dict[str, Any]:
    permissions: list[dict[str, str]] = [
        {"action": "*", "resource": "*", "effect": "deny"},
        {"action": "itsm_*", "resource": "*", "effect": "allow"},
        {"action": "skill", "resource": "*", "effect": "deny"},
    ]
    permissions.extend(
        {"action": "skill", "resource": name, "effect": "allow"} for name in skill_names
    )
    return {"mode": "primary", "disabled": False, "permissions": permissions}


def _opencode_v1_agent(skill_names: Sequence[str]) -> dict[str, Any]:
    skill_permissions: dict[str, str] = {"*": "deny"}
    skill_permissions.update({name: "allow" for name in skill_names})
    return {
        "mode": "primary",
        "disable": False,
        "permission": {"*": "deny", "itsm_*": "allow", "skill": skill_permissions},
    }


def _opencode_install_text(
    state: _TargetState,
    mcp: Mapping[str, Any],
    skill_names: Sequence[str],
    *,
    enabled: bool,
) -> tuple[str, list[str]]:
    text = state.config_text or "{}\n"
    created: list[str] = []

    def set_value(path: list[str], value: Any) -> None:
        nonlocal text
        if enabled and not _jsonc_has(text, path):
            created.append(".".join(path))
        text = _jsonc_set(text, path, value)

    if state.format == "v2":
        set_value(["mcp", "servers", "itsm"], _opencode_mcp(mcp, enabled))
        set_value(["agents", "itsm"], _opencode_agent(skill_names if enabled else []))
    else:
        set_value(["mcp", "itsm"], _opencode_v1_mcp(mcp, enabled))
        set_value(["agent", "itsm"], _opencode_v1_agent(skill_names if enabled else []))
    if enabled:
        set_value(["default_agent"], DEFAULT_AGENT)
    return text, created


def _opencode_uninstall_text(state: _TargetState, manifest: Mapping[str, Any]) -> str:
    text = state.config_text or "{}\n"
    created_keys = set(manifest.get("config", {}).get("createdKeys", []))
    if state.format == "v2":
        text = _jsonc_set(text, ["mcp", "servers", "itsm"], _MISSING)
        text = _jsonc_set(text, ["agents", "itsm"], _MISSING)
        if text is not None:
            try:
                if (
                    "mcp.servers" in created_keys
                    and isinstance(_jsonc_get(text, ["mcp", "servers"]), dict)
                    and not _jsonc_get(text, ["mcp", "servers"])
                ):
                    text = _jsonc_set(text, ["mcp", "servers"], _MISSING)
                if (
                    "mcp" in created_keys
                    and isinstance(_jsonc_get(text, ["mcp"]), dict)
                    and not _jsonc_get(text, ["mcp"])
                ):
                    text = _jsonc_set(text, ["mcp"], _MISSING)
                if (
                    "agents" in created_keys
                    and isinstance(_jsonc_get(text, ["agents"]), dict)
                    and not _jsonc_get(text, ["agents"])
                ):
                    text = _jsonc_set(text, ["agents"], _MISSING)
            except InstallerError:
                pass
    else:
        text = _jsonc_set(text, ["mcp", "itsm"], _MISSING)
        text = _jsonc_set(text, ["agent", "itsm"], _MISSING)
        if (
            "mcp" in created_keys
            and isinstance(_jsonc_get(text, ["mcp"]), dict)
            and not _jsonc_get(text, ["mcp"])
        ):
            text = _jsonc_set(text, ["mcp"], _MISSING)
        if (
            "agent" in created_keys
            and isinstance(_jsonc_get(text, ["agent"]), dict)
            and not _jsonc_get(text, ["agent"])
        ):
            text = _jsonc_set(text, ["agent"], _MISSING)
    if "default_agent" in created_keys and _jsonc_get(text, ["default_agent"]) == DEFAULT_AGENT:
        text = _jsonc_set(text, ["default_agent"], _MISSING)
    return text


def _hermes_install_text(
    state: _TargetState,
    mcp: Mapping[str, Any],
    skill_names: Sequence[str],
    *,
    enabled: bool,
) -> tuple[str, list[str]]:
    text = state.config_text or ""
    created: list[str] = []
    if "mcp_servers" not in (state.config_data or {}):
        created.append("mcp_servers")
    text, changed = _hermes_set_entry(text, mcp, enabled)
    if changed and "mcp_servers" not in created:
        created.append("mcp_servers.itsm")
    if "platform_toolsets" not in (state.config_data or {}):
        created.append("platform_toolsets")
    toolsets = ["itsm"] + (["skills"] if skill_names and enabled else [])
    text, changed = _hermes_set_api_server(text, toolsets)
    if changed and "platform_toolsets" not in created:
        created.append("platform_toolsets.api_server")
    return text, created


def _hermes_uninstall_text(state: _TargetState, manifest: Mapping[str, Any]) -> str:
    text = state.config_text or ""
    created_keys = set(manifest.get("config", {}).get("createdKeys", []))
    text, _ = _hermes_remove_entry(text, remove_parent="mcp_servers" in created_keys)
    text = _hermes_remove_api_server(text, remove_parent="platform_toolsets" in created_keys)
    return text


# --------------------------------------------------------------------------- profile safety


def _profile_config_check(
    state: _TargetState,
    text: str,
    mcp: Mapping[str, Any],
    skill_names: Sequence[str],
    enabled: bool,
) -> tuple[bool, str]:
    if state.engine == "hermes":
        return _hermes_profile_config_check(state, text, mcp, skill_names, enabled)
    return _opencode_profile_config_check(state, text, mcp, skill_names, enabled)


def _runtime_evidence(
    evidence: Mapping[str, Any] | None,
    *,
    engine: str,
    config_digest: str,
    state: _TargetState,
    skill_names: Sequence[str],
) -> tuple[str, bool, str]:
    if evidence is None:
        return "unverified", False, "runtime profile binding has not been proven"
    if not isinstance(evidence, Mapping):
        return "fail", False, "runtime evidence is not an object"
    source = evidence.get("source")
    prefix = "opencode:" if engine == "opencode" else "hermes:"
    if str(evidence.get("configDigest", "")) != config_digest:
        return "fail", False, "runtime evidence does not bind the current configuration digest"
    if not isinstance(source, str) or not source.startswith(prefix) or not source[len(prefix) :]:
        return "fail", False, "runtime evidence source does not match the selected engine"
    if evidence.get("verified") is not True:
        return "fail", False, "runtime evidence did not prove the selected profile"
    checks = evidence.get("checks")
    if (
        not isinstance(checks, list)
        or not checks
        or any(
            not isinstance(check, Mapping)
            or check.get("status") != "pass"
            or not isinstance(check.get("name"), str)
            or not check["name"].strip()
            for check in checks
        )
    ):
        return "fail", False, "runtime evidence checks are invalid"
    if not _same_runtime_path(evidence.get("targetPath"), state.root):
        return "fail", False, "runtime evidence target path differs from the selected target"
    if engine == "opencode":
        ok, detail = _opencode_runtime_safety(evidence, state, skill_names)
    else:
        ok, detail = _hermes_runtime_safety(evidence, state)
    if not ok:
        return "fail", False, detail
    return "pass", True, f"authenticated runtime inspection accepted from {source}"


def _same_runtime_path(raw: Any, expected: Path) -> bool:
    if not isinstance(raw, str) or not raw or not os.path.isabs(raw):
        return False
    return os.path.realpath(raw) == os.path.realpath(str(expected))


def _opencode_runtime_safety(
    evidence: Mapping[str, Any], state: _TargetState, skill_names: Sequence[str]
) -> tuple[bool, str]:
    location = evidence.get("location")
    if not isinstance(location, Mapping) or not _same_runtime_path(
        location.get("directory"), state.root
    ):
        return False, "runtime location directory differs from the selected workspace"
    agent = evidence.get("agent")
    if not isinstance(agent, Mapping) or agent.get("id") != DEFAULT_AGENT:
        return False, "runtime inspection did not select the restricted ITSM agent"
    if agent.get("mode") not in {"primary", "all"}:
        return False, "runtime ITSM agent is not a selectable primary agent"
    if agent.get("hidden") is not False:
        return False, "runtime ITSM agent is hidden or not selectable"
    permissions = agent.get("permissions")
    if not isinstance(permissions, list) or not permissions:
        return False, "runtime ITSM agent effective permissions are missing"
    rules: list[tuple[str, str, str]] = []
    for permission in permissions:
        if not isinstance(permission, Mapping):
            return False, "runtime ITSM permission rule is invalid"
        action = permission.get("action")
        resource = permission.get("resource")
        effect = permission.get("effect")
        if (
            not isinstance(action, str)
            or not action
            or not isinstance(resource, str)
            or not isinstance(effect, str)
            or effect not in {"allow", "deny", "ask"}
        ):
            return False, "runtime ITSM permission rule is invalid"
        rules.append((action, resource, effect))
    deny_index: int | None = None
    for index, (action, resource, effect) in enumerate(rules):
        if action == "*" and resource == "*" and effect == "deny":
            deny_index = index
    if deny_index is None:
        return False, "runtime ITSM agent does not deny actions outside the ITSM allowlist"
    itsm_allow = False
    allowed_skills: set[str] = set()
    requested_skills = set(skill_names)
    # OpenCode evaluates rules with last-match-wins. The last wildcard deny
    # shadows every earlier built-in default and user rule; any later allow or
    # ask must itself stay inside the managed authority.
    for action, resource, effect in rules[deny_index + 1 :]:
        if effect == "deny":
            continue
        if effect == "ask":
            return False, "runtime ITSM agent can ask for an unapproved action"
        if _opencode_itsm_allow(action):
            itsm_allow = True
            continue
        if action == "skill" and resource in requested_skills:
            allowed_skills.add(resource)
            continue
        return False, f"runtime ITSM agent allows unmanaged action {action!r}"
    if not itsm_allow or _last_effect(rules, "itsm_search_assets", "*") != "allow":
        return False, "runtime ITSM agent does not allow ITSM MCP tools"
    if allowed_skills != requested_skills:
        return False, "runtime ITSM agent does not allow exactly the selected skills"
    for skill in requested_skills:
        if _last_effect(rules, "skill", skill) != "allow":
            return False, "runtime ITSM agent does not allow exactly the selected skills"
    config_entries = evidence.get("config")
    if not isinstance(config_entries, list) or not config_entries:
        return False, "runtime configuration documents were not inspected"
    selected_directory = False
    selected_documents = 0
    for entry in config_entries:
        if not isinstance(entry, Mapping):
            return False, "runtime configuration entry is invalid"
        if set(entry) - {"type", "path", "info"}:
            return False, "runtime configuration entry has unsupported fields"
        kind = entry.get("type")
        path = entry.get("path")
        if not isinstance(path, str) or not path or not os.path.isabs(path):
            return False, "runtime configuration entry path is not absolute"
        if kind == "directory":
            if selected_directory or not _same_runtime_path(path, state.root / ".opencode"):
                return False, (
                    "runtime configuration includes a directory source outside the selected "
                    "profile"
                )
            selected_directory = True
        elif kind == "document":
            if not _same_runtime_path(path, state.config_path):
                return False, (
                    "runtime configuration includes a document source outside the selected "
                    "profile"
                )
            info = entry.get("info")
            if not isinstance(info, Mapping) or info.get("default_agent") != DEFAULT_AGENT:
                return False, (
                    "runtime effective configuration does not select the ITSM default agent"
                )
            selected_documents += 1
        else:
            return False, "runtime configuration entry type is invalid"
    if not selected_directory:
        return False, "runtime configuration does not include the selected .opencode profile"
    if selected_documents != 1:
        return False, "runtime configuration does not bind exactly one selected profile document"
    saved = evidence.get("savedPermissions")
    if not isinstance(saved, list):
        return False, "saved runtime permissions were not inspected"
    saved_rules: list[tuple[str, str, str]] = []
    for permission in saved:
        if not isinstance(permission, Mapping):
            return False, "saved runtime permission entry is invalid"
        action = permission.get("action")
        resource = permission.get("resource")
        effect = permission.get("effect")
        if (
            not isinstance(action, str)
            or not isinstance(resource, str)
            or not isinstance(effect, str)
            or effect not in {"allow", "deny", "ask"}
        ):
            return False, "saved runtime permission entry is invalid"
        if effect == "ask":
            return False, "saved runtime permission requires approval"
        if (
            effect == "allow"
            and not _opencode_itsm_allow(action)
            and (action != "skill" or resource not in requested_skills)
        ):
            return False, "saved runtime permission overrides the restricted ITSM allowlist"
        saved_rules.append((action, resource, effect))
    combined = rules + saved_rules
    if not itsm_allow or _last_effect(combined, "itsm_search_assets", "*") != "allow":
        return False, "runtime ITSM agent does not allow ITSM MCP tools"
    for skill in requested_skills:
        if _last_effect(combined, "skill", skill) != "allow":
            return False, "runtime ITSM agent does not allow exactly the selected skills"
    skill_evidence = evidence.get("skills")
    if not isinstance(skill_evidence, Mapping):
        return False, "runtime skill inventory was not inspected"
    if set(skill_evidence) != {"location", "data"}:
        return False, "runtime skill inventory envelope is invalid"
    skills_location = skill_evidence.get("location")
    if not isinstance(skills_location, Mapping) or not _same_runtime_path(
        skills_location.get("directory"), state.root
    ):
        return False, "runtime skill inventory location differs from the selected workspace"
    skill_items = skill_evidence.get("data")
    if not isinstance(skill_items, list):
        return False, "runtime skill inventory is invalid"
    expected_skill_paths = {
        name: state.root / state.skills_relative / name / "SKILL.md" for name in requested_skills
    }
    seen_skills: set[str] = set()
    for item in skill_items:
        if not isinstance(item, Mapping):
            return False, "runtime skill entry is invalid"
        skill_id = item.get("id")
        skill_name = item.get("name")
        skill_path = item.get("path")
        if (
            not isinstance(skill_id, str)
            or not skill_id
            or not isinstance(skill_name, str)
            or not skill_name
            or not isinstance(skill_path, str)
            or not skill_path
            or not os.path.isabs(skill_path)
        ):
            return False, "runtime skill entry is invalid"
        if skill_id in seen_skills:
            return False, "runtime skill inventory contains duplicate skills"
        seen_skills.add(skill_id)
        expected_path = expected_skill_paths.get(skill_id)
        if expected_path is not None:
            if not _same_runtime_path(skill_path, expected_path):
                return False, "runtime skill does not point at the selected profile skill"
            continue
        if _last_effect(combined, "skill", skill_id) != "deny":
            return False, "runtime skill inventory exposes an unselected skill"
    if not requested_skills.issubset(seen_skills):
        return False, "runtime skill inventory does not include the selected skills"
    return True, (
        "runtime agent, workspace, effective rules, saved permissions, and selected "
        "skills are restricted"
    )


def _last_effect(rules: Sequence[tuple[str, str, str]], action: str, resource: str) -> str | None:
    effect: str | None = None
    for rule_action, rule_resource, rule_effect in rules:
        if fnmatch.fnmatchcase(action, rule_action) and fnmatch.fnmatchcase(
            resource, rule_resource
        ):
            effect = rule_effect
    return effect


def _opencode_itsm_allow(action: str) -> bool:
    return action.startswith("itsm_")


def _hermes_runtime_safety(
    evidence: Mapping[str, Any], _state: _TargetState
) -> tuple[bool, str]:
    runtime = evidence.get("runtime")
    if runtime is not None and not isinstance(runtime, Mapping):
        return False, "Hermes runtime evidence is invalid"
    return (
        False,
        "Hermes does not expose an official active-profile attestation; "
        "profile safety verification is unavailable",
    )


def _hermes_profile_config_check(
    state: _TargetState,
    text: str,
    mcp: Mapping[str, Any],
    skill_names: Sequence[str],
    enabled: bool,
) -> tuple[bool, str]:
    try:
        data = _yaml_load(text)
    except InstallerError:
        return False, "configuration could not be parsed for profile safety"
    if not isinstance(data, Mapping):
        return False, "configuration root is not a mapping"
    entry = (
        (data.get("mcp_servers") or {}).get("itsm")
        if isinstance(data.get("mcp_servers"), Mapping)
        else None
    )
    if not isinstance(entry, Mapping):
        return False, "managed MCP entry is missing"
    if entry.get("enabled") is not enabled:
        return False, "managed MCP entry state differs from the receipt"
    headers = entry.get("headers")
    if not isinstance(headers, Mapping) or headers.get("Authorization") != (
        f"Bearer ${{{mcp['secretRef']}}}"
    ):
        return False, "MCP authorization must use the environment reference"
    toolsets = data.get("platform_toolsets")
    expected = ["itsm"] + (["skills"] if skill_names and enabled else [])
    if not isinstance(toolsets, Mapping) or toolsets.get("api_server") != expected:
        return False, "api_server toolset allowlist is not the restricted ITSM allowlist"
    agent = data.get("agent")
    disabled = agent.get("disabled_toolsets") if isinstance(agent, Mapping) else None
    if isinstance(disabled, list) and {"itsm", "skills"} & set(disabled):
        return False, "agent.disabled_toolsets overrides the ITSM allowlist"
    return True, "api_server allowlist contains only ITSM and selected skills"


def _opencode_profile_config_check(
    state: _TargetState,
    text: str,
    mcp: Mapping[str, Any],
    skill_names: Sequence[str],
    enabled: bool,
) -> tuple[bool, str]:
    try:
        data = _jsonc_value(text)
    except InstallerError:
        return False, "configuration could not be parsed for profile safety"
    if state.format == "v2":
        entry = (
            data.get("mcp", {}).get("servers", {}).get("itsm")
            if isinstance(data.get("mcp"), Mapping)
            else None
        )
        expected_entry = _opencode_mcp(mcp, enabled)
        expected_agent = _opencode_agent(skill_names if enabled else [])
        agent = (
            data.get("agents", {}).get("itsm") if isinstance(data.get("agents"), Mapping) else None
        )
    else:
        entry = data.get("mcp", {}).get("itsm") if isinstance(data.get("mcp"), Mapping) else None
        expected_entry = _opencode_v1_mcp(mcp, enabled)
        expected_agent = _opencode_v1_agent(skill_names if enabled else [])
        agent = (
            data.get("agent", {}).get("itsm") if isinstance(data.get("agent"), Mapping) else None
        )
    if not isinstance(entry, Mapping) or dict(entry) != expected_entry:
        return False, "managed MCP entry differs from the required schema and state"
    if data.get("default_agent") != DEFAULT_AGENT:
        return False, "the restricted ITSM agent is not the default agent"
    if not isinstance(agent, Mapping) or dict(agent) != expected_agent:
        return False, "managed agent entry differs from the required restricted agent"
    if not enabled:
        return False, "installation is disabled"
    return True, "managed target denies native actions and allows only ITSM MCP tools/skills"


# --------------------------------------------------------------------------- MCP proof


def _public_error(exc: BaseException, secret: str | None) -> str:
    if isinstance(exc, InstallerError):
        return exc.message
    name = type(exc).__name__
    message = str(exc).strip().splitlines()[0][:240] if str(exc).strip() else ""
    if secret:
        message = message.replace(secret, "[redacted]")
    return f"{name}: {message}" if message else name


async def verify_connection(mcp: Mapping[str, Any]) -> dict[str, Any]:
    """Prove a real FastMCP handshake and authorized non-mutating query."""
    checks: list[dict[str, str]] = []
    try:
        spec = _validate_mcp(mcp)
    except InstallerError as exc:
        return {
            "verified": False,
            "checks": [{"name": "mcp.config", "status": "fail", "detail": exc.message}],
            "toolCount": 0,
        }
    secret = os.environ.get(spec["secretRef"])
    if not secret:
        return {
            "verified": False,
            "checks": [
                {
                    "name": "mcp.secret",
                    "status": "fail",
                    "detail": f"process environment variable {spec['secretRef']} is not set",
                },
                {"name": "mcp.handshake", "status": "skip", "detail": "not attempted"},
                {"name": "mcp.tools", "status": "skip", "detail": "not attempted"},
                {"name": "mcp.query", "status": "skip", "detail": "not attempted"},
            ],
            "toolCount": 0,
        }
    checks.append(
        {
            "name": "mcp.secret",
            "status": "pass",
            "detail": f"resolved from process environment {spec['secretRef']}",
        }
    )
    try:
        from fastmcp import Client
        from fastmcp.client.transports import StreamableHttpTransport

        transport = StreamableHttpTransport(
            spec["url"], headers={"Authorization": f"Bearer {secret}"}
        )
        async with Client(transport, timeout=15.0) as client:
            checks.append({"name": "mcp.handshake", "status": "pass", "detail": "initialized"})
            tools = await client.list_tools()
            names = {tool.name for tool in tools}
            if "search_assets" not in names:
                checks.append(
                    {
                        "name": "mcp.tools",
                        "status": "fail",
                        "detail": "authorized tool list does not include search_assets",
                    }
                )
                checks.append({"name": "mcp.query", "status": "skip", "detail": "not attempted"})
                return {"verified": False, "checks": checks, "toolCount": len(names)}
            checks.append(
                {
                    "name": "mcp.tools",
                    "status": "pass",
                    "detail": f"{len(names)} authorized tools available",
                }
            )
            tool_name, arguments = MCP_QUERY
            await client.call_tool(tool_name, arguments, raise_on_error=True)
            checks.append(
                {
                    "name": "mcp.query",
                    "status": "pass",
                    "detail": "non-mutating search_assets query succeeded",
                }
            )
            return {"verified": True, "checks": checks, "toolCount": len(names)}
    except Exception as exc:
        detail = _public_error(exc, secret)
        existing = {check["name"] for check in checks}
        if "mcp.handshake" not in existing:
            checks.append({"name": "mcp.handshake", "status": "fail", "detail": detail})
        else:
            checks.append({"name": "mcp.query", "status": "fail", "detail": detail})
        if "mcp.tools" not in {check["name"] for check in checks}:
            checks.append({"name": "mcp.tools", "status": "skip", "detail": "handshake failed"})
        if "mcp.query" not in {check["name"] for check in checks}:
            checks.append({"name": "mcp.query", "status": "skip", "detail": "not attempted"})
        return {"verified": False, "checks": checks, "toolCount": 0}


# --------------------------------------------------------------------------- installer


class IntegrationInstaller:
    """Apply, verify, repair, disable, or remove ITSM resources for one target."""

    def __init__(self, catalog: Any | None = None) -> None:
        self.catalog = _CatalogView(catalog)

    async def detect_target(self, target: IntegrationTarget) -> dict[str, Any]:
        state = _target_state(target)
        return {
            "engine": state.engine,
            "format": state.format,
            "version": state.version,
            "profile": state.profile,
            "targetPath": str(state.root),
            "configFile": state.config_relative,
            "configExists": state.config_exists,
            "skillsDirectory": state.skills_relative,
            "limitations": list(state.limitations),
        }

    async def apply(
        self,
        target: IntegrationTarget,
        *,
        mcp: Mapping[str, Any],
        skills: Sequence[str],
        operation: str = "install",
        profile_safety: Mapping[str, Any] | None = None,
        profile_inspector: ProfileInspector | None = None,
    ) -> dict[str, Any]:
        operation = _validate_operation(operation)
        names = _validate_skill_names(list(skills))
        spec = _validate_mcp(mcp)
        state: _TargetState | None = None
        base: dict[str, Any] = {
            "kind": "itsm-agent-installer-receipt",
            "schemaVersion": SCHEMA_VERSION,
            "digestAlgorithm": "sha256",
            "operation": operation,
            "engine": target.engine if isinstance(target, IntegrationTarget) else None,
            "profile": target.profile if isinstance(target, IntegrationTarget) else None,
            "version": target.version if isinstance(target, IntegrationTarget) else None,
            "identityId": spec["identityId"],
        }
        try:
            state = _target_state(target)
            base.update(
                engine=state.engine,
                profile=state.profile,
                version=state.version,
                format=state.format,
                targetPath=str(state.root),
            )
            catalog_skills = self.catalog.skills(names)
            manifest, manifest_digest = _load_manifest(state.root)
            # ``profile_safety`` is retained for compatibility only. A raw caller
            # mapping is never proof: trusted evidence can only come from an
            # in-process inspector invoked below after the managed write.
            if profile_inspector is not None and not callable(profile_inspector):
                raise InstallerError("invalid_evidence", "profile_inspector must be callable")
            if (
                operation in {"update", "repair", "verify", "disable", "uninstall"}
                and manifest is None
            ):
                raise InstallerError(
                    "not_installed", "no managed installation exists for the selected target"
                )
            if operation in {"update", "repair"}:
                return await self._apply(
                    state,
                    spec,
                    catalog_skills,
                    operation,
                    manifest,
                    _validate_manifest_config(state, manifest, manifest_digest),
                    profile_safety,
                    profile_inspector,
                    base,
                )
            if operation in {"install"}:
                if manifest is not None:
                    return await self._apply(
                        state,
                        spec,
                        catalog_skills,
                        "update",
                        manifest,
                        _validate_manifest_config(state, manifest, manifest_digest),
                        profile_safety,
                        profile_inspector,
                        base,
                    )
                _preflight(state, catalog_skills, None, spec)
                return await self._apply(
                    state,
                    spec,
                    catalog_skills,
                    "install",
                    None,
                    None,
                    profile_safety,
                    profile_inspector,
                    base,
                )
            if operation == "verify":
                return await self._verify(
                    state,
                    spec,
                    catalog_skills,
                    manifest,
                    _validate_manifest_config(state, manifest, manifest_digest),
                    profile_safety,
                    profile_inspector,
                    base,
                )
            if operation == "disable":
                return await self._disable(
                    state,
                    manifest,
                    _validate_manifest_config(state, manifest, manifest_digest),
                    base,
                )
            return await self._uninstall(
                state,
                manifest,
                _validate_manifest_config(
                    state, manifest, manifest_digest, allow_config_change=True
                ),
                base,
            )
        except InstallerError as exc:
            return self._error_receipt(base, exc, state)
        except Exception as exc:  # pragma: no cover - final public boundary
            return self._error_receipt(
                base,
                InstallerError("installer_failure", _public_error(exc, None)),
                state,
            )

    async def _apply(
        self,
        state: _TargetState,
        mcp: Mapping[str, str],
        catalog_skills: Sequence[_Skill],
        operation: str,
        manifest: Mapping[str, Any] | None,
        manifest_digest: str | None,
        profile_safety: Mapping[str, Any] | None,
        profile_inspector: ProfileInspector | None,
        base: dict[str, Any],
    ) -> dict[str, Any]:
        if manifest is not None:
            _assert_managed_skills(
                state,
                manifest,
                allow_missing=operation == "repair",
                allow_modified=operation == "repair",
            )
            _preflight(state, catalog_skills, manifest, mcp)
        enabled = operation != "disable"
        skill_names = [skill.name for skill in catalog_skills] if enabled else []
        if state.engine == "opencode":
            text, created_keys = _opencode_install_text(state, mcp, skill_names, enabled=enabled)
        else:
            text, created_keys = _hermes_install_text(state, mcp, skill_names, enabled=enabled)
        config_digest = sha256_text(text)
        existing_created = list((manifest or {}).get("config", {}).get("createdKeys", []))
        prior_config = (manifest or {}).get("config")
        created_keys_all = sorted(set(existing_created) | set(created_keys))
        state.config_data = _jsonc_value(text) if state.engine == "opencode" else _yaml_load(text)
        if state.engine == "opencode" and state.config_data is not None:
            state.config_data["_itsmCreatedKeys"] = created_keys_all
        skill_payloads, destinations = _skill_manifest(state, catalog_skills)
        stale = _stale_skill_files(manifest, catalog_skills)
        manifest_payload = _build_manifest(
            state,
            mcp,
            created_keys_all,
            skill_payloads,
            config_digest,
            enabled=True,
        )
        if isinstance(prior_config, Mapping) and isinstance(
            prior_config.get("existsBefore"), bool
        ):
            manifest_payload["config"]["existsBefore"] = prior_config["existsBefore"]
        transaction = _Transaction(state.root)
        try:
            if text != (state.config_text or "") or not state.config_exists:
                transaction.write(
                    state.config_path,
                    text.encode("utf-8"),
                    mode=None if state.config_exists else 0o600,
                )
            for skill in catalog_skills:
                for relative, path in destinations[skill.name].items():
                    data = skill.files[relative]
                    if not path.exists() or path.is_symlink() or path.read_bytes() != data:
                        if path.is_symlink():
                            raise InstallerError(
                                "unsafe_path", "managed skill path traverses a symbolic link"
                            )
                        transaction.write(path, data, mode=0o644)
            for relative in stale:
                path = _path_from_relative(state.root, relative)
                transaction.remove(path)
            manifest_data = (
                json.dumps(manifest_payload, indent=2, sort_keys=True, ensure_ascii=False).encode(
                    "utf-8"
                )
                + b"\n"
            )
            transaction.write(_manifest_path(state.root), manifest_data, mode=0o600)
            manifest_digest_after = _sha256_bytes(manifest_data)
        except BaseException:
            transaction.rollback()
            raise
        return await self._finish(
            state,
            mcp,
            catalog_skills,
            operation,
            text,
            manifest_payload,
            manifest_digest_after,
            profile_safety,
            profile_inspector,
            base,
            skill_names,
        )

    async def _verify(
        self,
        state: _TargetState,
        mcp: Mapping[str, str],
        catalog_skills: Sequence[_Skill],
        manifest: Mapping[str, Any],
        manifest_digest: str | None,
        profile_safety: Mapping[str, Any] | None,
        profile_inspector: ProfileInspector | None,
        base: dict[str, Any],
    ) -> dict[str, Any]:
        _assert_managed_skills(state, manifest, allow_missing=manifest.get("state") == "disabled")
        if manifest.get("state") == "disabled":
            return self._state_receipt(
                state,
                manifest,
                "disabled",
                base,
                checks=[
                    {
                        "name": "state.disabled",
                        "status": "pass",
                        "detail": "installation is disabled",
                    }
                ],
            )
        if [skill.name for skill in catalog_skills] != sorted(manifest.get("skills", {})):
            raise InstallerError(
                "conflict",
                "requested skills differ from the managed installation",
                details=[_conflict("skills", "verification input does not match the manifest")],
            )
        stored_mcp = manifest.get("mcp", {})
        for key in ("url", "secretRef", "identityId"):
            if stored_mcp.get(key) != mcp.get(key):
                raise InstallerError(
                    "conflict",
                    "requested MCP configuration differs from the managed installation",
                    details=[
                        _conflict(f"mcp.{key}", "verification input does not match the manifest")
                    ],
                )
        assert state.config_text is not None
        return await self._finish(
            state,
            mcp,
            catalog_skills,
            "verify",
            state.config_text,
            manifest,
            _manifest_path(state.root).read_bytes() and _file_digest(_manifest_path(state.root)),
            profile_safety,
            profile_inspector,
            base,
            [skill.name for skill in catalog_skills],
            verify_only=True,
        )

    async def _disable(
        self,
        state: _TargetState,
        manifest: Mapping[str, Any],
        manifest_digest: str | None,
        base: dict[str, Any],
    ) -> dict[str, Any]:
        _assert_managed_skills(state, manifest, allow_missing=manifest.get("state") == "disabled")
        stored_mcp = manifest.get("mcp", {})
        mcp = {
            "url": stored_mcp.get("url", ""),
            "secretRef": stored_mcp.get("secretRef", ""),
            "identityId": stored_mcp.get("identityId", ""),
        }
        spec = _validate_mcp(mcp)
        if state.engine == "opencode":
            text, _ = _opencode_install_text(state, spec, [], enabled=False)
        else:
            text, _ = _hermes_install_text(state, spec, [], enabled=False)
        config_digest = sha256_text(text)
        config = dict(manifest.get("config", {}))
        config["digest"] = config_digest
        skills_payload = dict(manifest.get("skills", {}))
        disabled_manifest = dict(manifest)
        disabled_manifest.update(
            state="disabled",
            config=config,
            skills=skills_payload,
            mcp={
                "url": spec["url"],
                "secretRef": spec["secretRef"],
                "identityId": spec["identityId"],
            },
        )
        transaction = _Transaction(state.root)
        try:
            if text != (state.config_text or ""):
                transaction.write(state.config_path, text.encode("utf-8"))
            for _name, payload in skills_payload.items():
                for relative in payload.get("files") or {}:
                    path = _path_from_relative(state.root, relative)
                    if path.exists():
                        if path.is_symlink():
                            raise InstallerError(
                                "unsafe_path", "managed skill path traverses a symbolic link"
                            )
                        transaction.remove(path)
            manifest_data = (
                json.dumps(disabled_manifest, indent=2, sort_keys=True, ensure_ascii=False).encode(
                    "utf-8"
                )
                + b"\n"
            )
            transaction.write(_manifest_path(state.root), manifest_data, mode=0o600)
        except BaseException:
            transaction.rollback()
            raise
        return self._state_receipt(
            state,
            disabled_manifest,
            "disabled",
            base,
            checks=[
                {
                    "name": "state.disabled",
                    "status": "pass",
                    "detail": "MCP disabled and skills removed",
                },
                {
                    "name": "mcp.handshake",
                    "status": "skip",
                    "detail": "disabled installation is not verified",
                },
            ],
        )

    async def _uninstall(
        self,
        state: _TargetState,
        manifest: Mapping[str, Any],
        manifest_digest: str | None,
        base: dict[str, Any],
    ) -> dict[str, Any]:
        _assert_managed_skills(state, manifest, allow_missing=True)
        if state.engine == "opencode":
            text = _opencode_uninstall_text(state, manifest)
        else:
            text = _hermes_uninstall_text(state, manifest)
        remove_config = False
        if not manifest.get("config", {}).get("existsBefore", True):
            remove_config = (
                _jsonc_empty_after(text) if state.engine == "opencode" else not text.strip()
            )
        transaction = _Transaction(state.root)
        try:
            if remove_config:
                transaction.remove(state.config_path)
            elif text != (state.config_text or ""):
                transaction.write(state.config_path, text.encode("utf-8"))
            for payload in manifest.get("skills", {}).values():
                for relative in payload.get("files") or {}:
                    path = _path_from_relative(state.root, relative)
                    if path.exists():
                        if path.is_symlink():
                            raise InstallerError(
                                "unsafe_path", "managed skill path traverses a symbolic link"
                            )
                        transaction.remove(path)
            transaction.remove(_manifest_path(state.root))
            for relative in sorted(manifest.get("createdDirs", []), reverse=True):
                directory = _path_from_relative(state.root, relative)
                if directory.exists() and directory.is_dir():
                    with contextlib.suppress(OSError):
                        directory.rmdir()
            if _manifest_path(state.root).parent.exists():
                with contextlib.suppress(OSError):
                    _manifest_path(state.root).parent.rmdir()
        except BaseException:
            transaction.rollback()
            raise
        return self._state_receipt(
            state,
            manifest,
            "removed",
            base,
            checks=[
                {"name": "state.removed", "status": "pass", "detail": "managed resources removed"},
                {"name": "mcp.handshake", "status": "skip", "detail": "uninstalled"},
            ],
            config_text=text,
        )

    async def _finish(
        self,
        state: _TargetState,
        mcp: Mapping[str, str],
        catalog_skills: Sequence[_Skill],
        operation: str,
        config_text: str,
        manifest: Mapping[str, Any],
        manifest_digest: str,
        profile_safety: Mapping[str, Any] | None,
        profile_inspector: ProfileInspector | None,
        base: dict[str, Any],
        skill_names: Sequence[str],
        *,
        verify_only: bool = False,
    ) -> dict[str, Any]:
        mcp_result = await verify_connection(mcp)
        mcp_verified = bool(mcp_result["verified"])
        config_digest = sha256_text(config_text)
        config_ok, config_detail = _profile_config_check(state, config_text, mcp, skill_names, True)
        profile_evidence: Mapping[str, Any] | None = None
        if not config_ok:
            safety_status, profile_ok, profile_detail = "fail", False, config_detail
        elif profile_inspector is None:
            safety_status, profile_ok, profile_detail = (
                "fail",
                False,
                (
                    "caller-supplied profile evidence is untrusted; "
                    "live engine inspection is required"
                    if profile_safety is not None
                    else "trusted engine profile inspection is not available"
                ),
            )
        else:
            target = IntegrationTarget(state.engine, str(state.root), state.profile, state.version)
            try:
                inspected = profile_inspector(
                    target=target,
                    mcp=dict(mcp),
                    skills=tuple(skill_names),
                    config_digest=config_digest,
                )
                if isawaitable(inspected):
                    profile_evidence = await inspected
                else:
                    profile_evidence = None
            except Exception:
                safety_status, profile_ok, profile_detail = (
                    "fail",
                    False,
                    "trusted engine profile inspection failed",
                )
            else:
                if profile_evidence is None:
                    safety_status, profile_ok, profile_detail = (
                        "fail",
                        False,
                        "trusted engine profile inspection returned no evidence",
                    )
                else:
                    safety_status, profile_ok, profile_detail = _runtime_evidence(
                        profile_evidence,
                        engine=state.engine,
                        config_digest=config_digest,
                        state=state,
                        skill_names=skill_names,
                    )
        checks = list(mcp_result["checks"])
        checks.append(
            {
                "name": "profile.safety",
                "status": safety_status,
                "detail": profile_detail,
            }
        )
        overall = mcp_verified and profile_ok
        status = "verified" if overall else "configured"
        receipt = _base_finished_receipt(state, manifest, base, config_text)
        receipt.update(
            status=status,
            verified=overall,
            mcpVerified=mcp_verified,
            profileSafetyVerified=profile_ok,
            checks=checks,
            limitations=list(state.limitations),
        )
        if not mcp_verified:
            receipt["limitations"].append("MCP proof did not pass; installation is not verified.")
        if not profile_ok:
            receipt["limitations"].append(
                "Selected engine profile/runtime binding was not proven; "
                "installation is not verified."
            )
        if profile_ok and profile_evidence is not None:
            source = profile_evidence.get("source")
            receipt["limitations"].append(f"Profile safety evidence source: {source}")
        return _finalize_receipt(receipt, state, manifest)

    def _state_receipt(
        self,
        state: _TargetState,
        manifest: Mapping[str, Any],
        status: str,
        base: dict[str, Any],
        *,
        checks: list[dict[str, str]],
        config_text: str | None = None,
    ) -> dict[str, Any]:
        text = config_text if config_text is not None else (state.config_text or "")
        receipt = _base_finished_receipt(state, manifest, base, text)
        receipt.update(
            status=status,
            verified=False,
            mcpVerified=False,
            profileSafetyVerified=False,
            checks=checks,
            limitations=list(state.limitations),
        )
        return _finalize_receipt(receipt, state, manifest)

    def _error_receipt(
        self,
        base: dict[str, Any],
        exc: InstallerError,
        state: _TargetState | None,
    ) -> dict[str, Any]:
        status = "conflict" if exc.code == "conflict" else "failed"
        receipt: dict[str, Any] = {
            **base,
            "status": status,
            "verified": False,
            "mcpVerified": False,
            "profileSafetyVerified": False,
            "conflicts": exc.details
            if status == "conflict" and isinstance(exc.details, list)
            else [],
            "checks": [],
            "managedFiles": [],
            "fileDigests": {},
            "skillDigests": {},
            "limitations": list(state.limitations) if state else [],
            "error": exc.as_dict(),
            "manifestVersion": SCHEMA_VERSION,
        }
        if state is not None:
            receipt.update(
                engine=state.engine,
                profile=state.profile,
                version=state.version,
                format=state.format,
                targetPath=str(state.root),
            )
            receipt["configDigest"] = (
                sha256_text(state.config_text) if state.config_text is not None else None
            )
        else:
            receipt.setdefault("targetPath", None)
            receipt["configDigest"] = None
        receipt["manifestDigest"] = None
        return _finalize_receipt(receipt, None, None)


# --------------------------------------------------------------------------- manifest lifecycle


def _validate_manifest_config(
    state: _TargetState,
    manifest: Mapping[str, Any],
    manifest_digest: str | None,
    *,
    allow_config_change: bool = False,
) -> str | None:
    config = manifest.get("config")
    if not isinstance(config, Mapping) or config.get("path") != state.config_relative:
        raise InstallerError(
            "manifest_invalid", "managed manifest config path does not match target"
        )
    current = sha256_text(state.config_text or "") if state.config_text is not None else None
    if state.config_text is None:
        raise InstallerError("manifest_invalid", "managed configuration file is missing")
    if not allow_config_change and config.get("digest") != current:
        raise InstallerError(
            "conflict",
            "managed configuration was modified outside the installer",
            details=[
                _conflict(state.config_relative, "configuration digest differs from manifest")
            ],
        )
    if manifest_digest is None:  # pragma: no cover - caller loaded it
        manifest_digest = _file_digest(_manifest_path(state.root))
    return manifest_digest


def _assert_managed_skills(
    state: _TargetState,
    manifest: Mapping[str, Any],
    *,
    allow_missing: bool,
    allow_modified: bool = False,
) -> None:
    conflicts: list[dict[str, str]] = []
    for name, payload in (manifest.get("skills") or {}).items():
        for relative, expected in (payload.get("files") or {}).items():
            path = _path_from_relative(state.root, relative)
            if path.is_symlink():
                raise InstallerError("unsafe_path", "managed skill path traverses a symbolic link")
            if not path.exists():
                if not allow_missing:
                    conflicts.append(_conflict(relative, f"managed skill {name} file is missing"))
                continue
            if not path.is_file():
                conflicts.append(_conflict(relative, "managed skill path is not a regular file"))
                continue
            if not allow_modified and _file_digest(path) != expected:
                conflicts.append(_conflict(relative, "managed skill file was modified"))
    if conflicts:
        raise InstallerError("conflict", "managed skill files were modified", details=conflicts)


def _stale_skill_files(manifest: Mapping[str, Any] | None, skills: Sequence[_Skill]) -> list[str]:
    if manifest is None:
        return []
    desired: set[str] = set()
    for skill in skills:
        for relative in skill.files:
            desired.add(f"{_state_skills_prefix(manifest)}{skill.name}/{relative}")
    stale: list[str] = []
    for payload in (manifest.get("skills") or {}).values():
        for relative in payload.get("files") or {}:
            if relative not in desired:
                stale.append(relative)
    return stale


def _state_skills_prefix(manifest: Mapping[str, Any]) -> str:
    config = manifest.get("config", {})
    skills = config.get("skillsDirectory")
    if isinstance(skills, str):
        return skills.rstrip("/") + "/"
    return ""


def _skill_manifest(
    state: _TargetState, skills: Sequence[_Skill]
) -> tuple[dict[str, Any], dict[str, dict[str, Path]]]:
    payloads: dict[str, Any] = {}
    destinations: dict[str, dict[str, Path]] = {}
    base = state.root.joinpath(*PurePosixPath(state.skills_relative).parts)
    for skill in skills:
        file_map: dict[str, str] = {}
        paths: dict[str, Path] = {}
        for relative, data in skill.files.items():
            path = base / skill.name / Path(*PurePosixPath(relative).parts)
            file_digest = _sha256_bytes(data)
            file_map[path.relative_to(state.root).as_posix()] = file_digest
            paths[relative] = path
        payloads[skill.name] = {
            "version": skill.version,
            "digest": skill.digest,
            "files": file_map,
        }
        destinations[skill.name] = paths
    return payloads, destinations


def _build_manifest(
    state: _TargetState,
    mcp: Mapping[str, str],
    created_keys: Sequence[str],
    skills: Mapping[str, Any],
    config_digest: str,
    *,
    enabled: bool,
) -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "engine": state.engine,
        "format": state.format,
        "version": state.version,
        "profile": state.profile,
        "targetPath": str(state.root),
        "identityId": mcp["identityId"],
        "mcp": {
            "url": mcp["url"],
            "secretRef": mcp["secretRef"],
            "identityId": mcp["identityId"],
        },
        "state": "enabled" if enabled else "disabled",
        "config": {
            "path": state.config_relative,
            "digest": config_digest,
            "existsBefore": state.config_exists,
            "skillsDirectory": state.skills_relative,
            "createdKeys": sorted(set(created_keys)),
        },
        "skills": dict(skills),
    }


def _managed_existing(state: _TargetState, manifest: Mapping[str, Any]) -> list[str]:
    candidates = [state.config_relative, MANIFEST_RELATIVE]
    for payload in (manifest.get("skills") or {}).values():
        candidates.extend((payload.get("files") or {}).keys())
    return [relative for relative in candidates if (state.root / relative).is_file()]


def _base_finished_receipt(
    state: _TargetState,
    manifest: Mapping[str, Any],
    base: dict[str, Any],
    config_text: str,
) -> dict[str, Any]:
    skills = manifest.get("skills") or {}
    return {
        **base,
        "engine": state.engine,
        "profile": state.profile,
        "version": state.version,
        "format": state.format,
        "targetPath": str(state.root),
        "identityId": manifest.get("mcp", {}).get("identityId", base.get("identityId")),
        "configDigest": sha256_text(config_text),
        "manifestVersion": manifest.get("schemaVersion", SCHEMA_VERSION),
        "skillDigests": {name: payload.get("digest") for name, payload in sorted(skills.items())},
        "skills": [
            {
                "name": name,
                "version": payload.get("version"),
                "digest": payload.get("digest"),
            }
            for name, payload in sorted(skills.items())
        ],
    }


def _finalize_receipt(
    receipt: dict[str, Any],
    state: _TargetState | None,
    manifest: Mapping[str, Any] | None,
) -> dict[str, Any]:
    managed: list[str] = []
    digests: dict[str, str] = {}
    if state is not None and manifest is not None:
        for relative in _managed_existing(state, manifest):
            path = _path_from_relative(state.root, relative)
            managed.append(relative)
            digests[relative] = _file_digest(path)
    receipt["managedFiles"] = sorted(managed)
    receipt["fileDigests"] = digests
    receipt["manifestDigest"] = (
        _file_digest(_manifest_path(state.root))
        if state is not None and _manifest_path(state.root).is_file()
        else receipt.get("manifestDigest")
    )
    receipt["receiptDigest"] = receipt_digest(receipt)
    return receipt


# --------------------------------------------------------------------------- remote request/receipt


def build_request(
    target: IntegrationTarget,
    *,
    mcp: Mapping[str, Any],
    skills: Sequence[str],
    operation: str = "install",
    expected_manifest_digest: str | None = None,
    catalog: Any | None = None,
) -> dict[str, Any]:
    """Build a scoped, token-free request for the destination-host helper."""
    operation = _validate_operation(operation)
    names = _validate_skill_names(list(skills))
    spec = _validate_mcp(mcp)
    if not isinstance(target, IntegrationTarget):
        raise InstallerError("target_invalid", "target must be an IntegrationTarget")
    if target.engine not in {"opencode", "hermes"}:
        raise InstallerError("unsupported_engine", "installer engine is not supported")
    root = Path(target.path)
    if not root.is_absolute() or any(part == ".." for part in root.parts):
        raise InstallerError(
            "target_path_invalid", "target path must be absolute without traversal"
        )
    if target.version:
        version = _normalized_version(target.version)
        "hermes" if target.engine == "hermes" else _opencode_format(version)
        profile = None if target.engine == "opencode" else (target.profile or root.name)
    else:
        state = _target_state(target)
        version = state.version
        profile = state.profile
    if target.engine == "hermes" and _parse_version(version) < (0, 16, 0):
        raise InstallerError(
            "unsupported_version", "Hermes version is older than the supported 0.16.0 floor"
        )
    if target.engine == "hermes" and (not profile or not PROFILE_NAME.fullmatch(profile)):
        raise InstallerError("profile_invalid", "Hermes profile name is invalid")
    view = _CatalogView(catalog)
    resolved = view.skills(names)
    expected: dict[str, Any] = {
        "engine": target.engine,
        "profile": profile,
        "version": version,
        "identityId": spec["identityId"],
    }
    manifest_digest = expected_manifest_digest
    if root.is_dir() and not root.is_symlink():
        manifest, current_manifest_digest = _load_manifest(root)
        if manifest_digest is None and manifest is not None:
            manifest_digest = current_manifest_digest
        if manifest is not None:
            expected["configDigest"] = manifest.get("config", {}).get("digest")
    if manifest_digest is not None:
        expected["manifestDigest"] = _normalize_digest(manifest_digest, "invalid_expected_manifest")
    request: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "itsm-agent-installer-request",
        "digestAlgorithm": "sha256",
        "engine": target.engine,
        "target": {
            "engine": target.engine,
            "path": target.path,
            "profile": profile,
            "version": version,
        },
        "mcp": dict(spec),
        "skills": list(names),
        "skillVersions": {skill.name: skill.version for skill in resolved},
        "skillDigests": {skill.name: skill.digest for skill in resolved},
        "operation": operation,
        "expected": expected,
    }
    request["requestDigest"] = request_digest(request)
    return request


def _request_from_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise InstallerError("request_invalid", "request must be a JSON object")
    if payload.get("kind") != "itsm-agent-installer-request":
        raise InstallerError("request_invalid", "request kind is invalid")
    if payload.get("schemaVersion") != SCHEMA_VERSION:
        raise InstallerError("request_invalid", "request schema version is unsupported")
    if payload.get("digestAlgorithm") != "sha256":
        raise InstallerError("request_invalid", "request digest algorithm is unsupported")
    digest = _normalize_digest(str(payload.get("requestDigest", "")), "request_invalid")
    if not hmac.compare_digest(digest, request_digest(payload)):
        raise InstallerError("request_invalid", "request digest does not match its content")
    target_payload = payload.get("target")
    if not isinstance(target_payload, Mapping):
        raise InstallerError("request_invalid", "request target is missing")
    target = IntegrationTarget(
        engine=target_payload.get("engine"),
        path=target_payload.get("path"),
        profile=target_payload.get("profile"),
        version=target_payload.get("version"),
    )
    if target.engine not in {"opencode", "hermes"}:
        raise InstallerError("request_invalid", "request target engine is unsupported")
    if target.engine == "opencode" and target.profile is not None:
        raise InstallerError(
            "request_invalid", "OpenCode requests must use a workspace, not a profile"
        )
    mcp = _validate_mcp(payload.get("mcp"))
    skills = _validate_skill_names(payload.get("skills"))
    operation = _validate_operation(payload.get("operation"))
    expected = payload.get("expected")
    if not isinstance(expected, Mapping):
        raise InstallerError("request_invalid", "request expected bindings are missing")
    for key, value in (
        ("engine", target.engine),
        ("profile", target.profile),
        ("version", target.version),
        ("identityId", mcp["identityId"]),
    ):
        if expected.get(key) != value:
            raise InstallerError("request_invalid", f"request expected {key} binding differs")
    if payload.get("engine") != target.engine:
        raise InstallerError("request_invalid", "request engine binding differs")
    return {
        "target": target,
        "mcp": mcp,
        "skills": skills,
        "operation": operation,
        "expected": expected,
    }


def validate_receipt(
    receipt: Mapping[str, Any], request: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Validate a helper receipt's integrity and optional request bindings."""
    errors: list[str] = []
    bindings: dict[str, Any] = {}
    if not isinstance(receipt, Mapping):
        return {"valid": False, "errors": ["receipt must be an object"], "bindings": {}}
    if receipt.get("kind") != "itsm-agent-installer-receipt":
        errors.append("receipt kind is invalid")
    if receipt.get("schemaVersion") != SCHEMA_VERSION:
        errors.append("receipt schema version is unsupported")
    if receipt.get("digestAlgorithm") != "sha256":
        errors.append("receipt digest algorithm is unsupported")
    if receipt.get("status") not in STATUSES:
        errors.append("receipt status is invalid")
    if not isinstance(receipt.get("verified"), bool):
        errors.append("receipt verified flag is invalid")
    try:
        digest = _normalize_digest(str(receipt.get("receiptDigest", "")), "invalid_receipt")
        if not hmac.compare_digest(digest, receipt_digest(receipt)):
            errors.append("receipt digest does not match its content")
    except InstallerError:
        errors.append("receipt digest is invalid")
    for key in (
        "engine",
        "profile",
        "version",
        "identityId",
        "targetPath",
        "configDigest",
        "manifestDigest",
        "skillDigests",
    ):
        bindings[key] = receipt.get(key)
    if receipt.get("status") == "verified":
        if receipt.get("mcpVerified") is not True:
            errors.append("verified receipt did not prove MCP")
        if receipt.get("profileSafetyVerified") is not True:
            errors.append("verified receipt did not prove profile safety")
        if not receipt.get("configDigest") or not receipt.get("manifestDigest"):
            errors.append("verified receipt lacks integrity digests")
        if not isinstance(receipt.get("skillDigests"), Mapping):
            errors.append("verified receipt lacks skill digests")
        checks = receipt.get("checks")
        if (
            not isinstance(checks, list)
            or not checks
            or any(
                not isinstance(check, Mapping) or check.get("status") != "pass" for check in checks
            )
        ):
            errors.append("verified receipt has failing or missing checks")
    if request is not None:
        if not isinstance(request, Mapping):
            errors.append("request must be an object")
        else:
            if receipt.get("requestDigest") != request.get("requestDigest"):
                errors.append("receipt requestDigest does not match the request")
            target = request.get("target") if isinstance(request.get("target"), Mapping) else {}
            for key in ("engine", "profile", "version", "identityId", "operation"):
                expected_value = request.get(key) if key != "engine" else target.get("engine")
                if key in {"profile", "version"}:
                    expected_value = target.get(key)
                if key == "identityId":
                    expected_value = (request.get("mcp") or {}).get("identityId")
                if key == "operation":
                    expected_value = request.get("operation")
                if receipt.get(key) != expected_value:
                    errors.append(f"receipt {key} binding does not match the request")
            if receipt.get("targetPath") != target.get("path"):
                errors.append("receipt targetPath binding does not match the request")
            requested_skills = request.get("skillDigests")
            actual_skills = receipt.get("skillDigests")
            if not isinstance(requested_skills, Mapping) or not isinstance(actual_skills, Mapping):
                errors.append("skill digests are missing from request or receipt")
            elif dict(requested_skills) != dict(actual_skills):
                errors.append("receipt skill digests do not match the request")
    return {"valid": not errors, "errors": errors, "bindings": bindings}


def _helper_failure(
    payload: Mapping[str, Any] | None, exc: InstallerError, request_digest_value: str | None
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "kind": "itsm-agent-installer-receipt",
        "schemaVersion": SCHEMA_VERSION,
        "digestAlgorithm": "sha256",
        "requestDigest": request_digest_value,
        "operation": payload.get("operation") if isinstance(payload, Mapping) else None,
        "engine": payload.get("engine") if isinstance(payload, Mapping) else None,
        "profile": (payload.get("target") or {}).get("profile")
        if isinstance(payload, Mapping) and isinstance(payload.get("target"), Mapping)
        else None,
        "version": (payload.get("target") or {}).get("version")
        if isinstance(payload, Mapping) and isinstance(payload.get("target"), Mapping)
        else None,
        "targetPath": (payload.get("target") or {}).get("path")
        if isinstance(payload, Mapping) and isinstance(payload.get("target"), Mapping)
        else None,
        "status": "conflict" if exc.code == "conflict" else "failed",
        "verified": False,
        "mcpVerified": False,
        "profileSafetyVerified": False,
        "identityId": (payload.get("mcp") or {}).get("identityId")
        if isinstance(payload, Mapping) and isinstance(payload.get("mcp"), Mapping)
        else None,
        "managedFiles": [],
        "fileDigests": {},
        "skillDigests": {},
        "conflicts": exc.details if isinstance(exc.details, list) else [],
        "checks": [],
        "limitations": [],
        "error": exc.as_dict(),
        "configDigest": None,
        "manifestDigest": None,
        "manifestVersion": SCHEMA_VERSION,
    }
    receipt["receiptDigest"] = receipt_digest(receipt)
    return receipt


# --------------------------------------------------------------------------- CLI


def main(argv: Sequence[str] | None = None) -> int:
    """Run the destination-host helper. Never performs remote shell execution."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="itsm-agent-installer",
        description="Apply one scoped ITSM agent-integration request on this host.",
    )
    parser.add_argument("--request", required=True, help="path to a scoped request JSON file")
    args = parser.parse_args(argv)
    payload: Mapping[str, Any] | None = None
    request_digest_value: str | None = None
    try:
        request_path = Path(args.request)
        if request_path.stat().st_size > MAX_CONFIG_BYTES:
            raise InstallerError("request_invalid", "request file is too large")
        raw = request_path.read_bytes()
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InstallerError("request_invalid", "request is not valid JSON") from exc
        if not isinstance(payload, Mapping):
            raise InstallerError("request_invalid", "request must be a JSON object")
        request_digest_value = (
            str(payload.get("requestDigest")) if payload.get("requestDigest") else None
        )
        parsed = _request_from_payload(payload)
        view = _CatalogView(None)
        resolved = view.skills(parsed["skills"])
        requested_digests = payload.get("skillDigests")
        requested_versions = payload.get("skillVersions")
        if not isinstance(requested_digests, Mapping) or not isinstance(
            requested_versions, Mapping
        ):
            raise InstallerError("request_invalid", "request skill bindings are missing")
        for skill in resolved:
            if requested_digests.get(skill.name) != skill.digest:
                raise InstallerError(
                    "catalog_digest_mismatch",
                    f"destination catalog digest differs for {skill.name}",
                )
            if requested_versions.get(skill.name) != skill.version:
                raise InstallerError(
                    "catalog_version_mismatch",
                    f"destination catalog version differs for {skill.name}",
                )
        expected = parsed["expected"]
        if expected.get("configDigest") is not None:
            state = _target_state(parsed["target"])
            current = sha256_text(state.config_text) if state.config_text else None
            if current != expected.get("configDigest"):
                raise InstallerError(
                    "config_mismatch",
                    "selected target configuration differs from the request binding",
                )
        if expected.get("manifestDigest") is not None:
            _, current_manifest = _load_manifest(Path(parsed["target"].path))
            if current_manifest != expected.get("manifestDigest"):
                raise InstallerError(
                    "manifest_mismatch",
                    "selected target manifest differs from the request binding",
                )
        installer = IntegrationInstaller()
        receipt = asyncio.run(
            installer.apply(
                parsed["target"],
                mcp=parsed["mcp"],
                skills=parsed["skills"],
                operation=parsed["operation"],
            )
        )
        receipt["requestDigest"] = payload.get("requestDigest")
        receipt["receiptDigest"] = receipt_digest(receipt)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        return (
            0 if receipt.get("status") in {"verified", "configured", "disabled", "removed"} else 1
        )
    except InstallerError as exc:
        receipt = _helper_failure(payload, exc, request_digest_value)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        return 1
    except Exception as exc:  # pragma: no cover - public command boundary
        receipt = _helper_failure(
            payload,
            InstallerError("installer_failure", _public_error(exc, None)),
            request_digest_value,
        )
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        return 1


# Imported late so the module can be inspected without starting a loop.
import asyncio  # noqa: E402
