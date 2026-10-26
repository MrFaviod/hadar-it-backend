"""Versioned, metadata-only catalog of official and module-provided skills.

Packages are inert ``SKILL.md`` resources. The catalog reads them, validates a
bounded frontmatter shape and computes a deterministic digest for installation
and integrity checks. It never writes to an agent profile, a global skill
directory or a mounted server, and it never turns skill text into a prompt:
distribution remains an installer decision and execution stays on demand.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from itsm.identity.permissions import is_known_permission

SKILL_NAME: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
MODULE_ID: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
VERSION: Final[re.Pattern[str]] = re.compile(r"^\d+\.\d+\.\d+$")
_DIGEST: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

OFFICIAL_MODULE_ID: Final[str] = "itsm"
OFFICIAL_MODULE_VERSION: Final[str] = "1.0.0"
OFFICIAL_ROOT: Final[Path] = Path(__file__).resolve().parent / "skills"

MAX_DESCRIPTION: Final[int] = 250
MAX_TEXT: Final[int] = 4096

# Capabilities name an ITSM domain use, never a general-purpose executor. A
# module cannot declare a capability outside this set, so a shell, HTTP or SQL
# tool has no vocabulary to register under.
CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "directory.read",
        "directory.write",
        "incidents.read",
        "incidents.write",
        "inventory.read",
        "inventory.write",
        "maintenance.read",
        "maintenance.write",
        "monitoring.read",
        "monitoring.write",
        "operations.read",
        "redundancy.read",
        "redundancy.write",
        "relationships.read",
        "relationships.write",
        "reports.generate",
        "reports.read",
        "system.configure",
        "system.operate",
        "system.read",
    }
)

_ALLOWED_FRONTMATTER: Final[frozenset[str]] = frozenset(
    {
        "name",
        "description",
        "license",
        "compatibility",
        "metadata",
        "tools",
        "permissions",
        "capabilities",
    }
)
_REQUIRED_FRONTMATTER: Final[frozenset[str]] = frozenset(
    {"name", "description", "license", "metadata", "tools", "permissions", "capabilities"}
)
_MANIFEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "id",
        "name",
        "version",
        "capabilities",
        "permissions",
        "skills",
        "skillDigests",
    }
)


class CatalogError(Exception):
    """Base class for catalog validation, lookup and conflict errors."""


class InvalidSkillPackage(CatalogError):
    """A skill package or module manifest is malformed or uncontained."""


class SkillNotFound(CatalogError):
    """The requested skill is not offered by an enabled module."""


class ModuleConflict(CatalogError):
    """A module id or a skill name is already registered."""


class UnknownModule(CatalogError):
    """The requested module id is not registered."""


@dataclass(frozen=True)
class _Skill:
    metadata: dict[str, Any]
    files: dict[str, bytes]
    tools: tuple[str, ...]


@dataclass
class _Module:
    metadata: dict[str, Any]
    skills: dict[str, _Skill] = field(default_factory=dict)
    enabled: bool = True


def package_digest(files: Mapping[str, bytes]) -> str:
    """Deterministic SHA-256 over every package file, sorted by relative name."""
    checked: list[tuple[str, bytes]] = []
    for name, content in files.items():
        if not isinstance(name, str) or not isinstance(content, (bytes, bytearray)):
            raise InvalidSkillPackage("skill files must map relative names to bytes")
        if not name or name.startswith("/") or ".." in Path(name).parts:
            raise InvalidSkillPackage("skill file names must be relative and contained")
        checked.append((name, bytes(content)))

    digest = hashlib.sha256()
    for name, content in sorted(checked):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def _text(value: Any, field_name: str, *, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise InvalidSkillPackage(f"{field_name} must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise InvalidSkillPackage(f"{field_name} must be 1-{maximum} characters")
    return normalized


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Parse the bounded YAML subset used by packaged skills.

    Only top-level scalars, top-level string lists and one nested metadata map
    are accepted. Anything else is rejected instead of guessed.
    """
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        raise InvalidSkillPackage("SKILL.md must start with frontmatter")
    closing = next(
        (index for index, line in enumerate(lines[1:], 1) if line.strip() == "---"), None
    )
    if closing is None:
        raise InvalidSkillPackage("SKILL.md frontmatter is not closed")

    data: dict[str, Any] = {}
    current: str | None = None
    for raw in "".join(lines[1:closing]).splitlines():
        if "\t" in raw:
            raise InvalidSkillPackage("SKILL.md frontmatter must not use tabs")
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.startswith("  - "):
            if current is None or not isinstance(data.get(current), list):
                raise InvalidSkillPackage("SKILL.md list item has no parent key")
            item = _unquote(raw[4:].strip())
            if not item:
                raise InvalidSkillPackage("SKILL.md list items must not be empty")
            data[current].append(item)
        elif raw.startswith("  "):
            if current is None:
                raise InvalidSkillPackage("SKILL.md nested field has no parent key")
            key, separator, value = raw.strip().partition(":")
            if not separator or not key.strip():
                raise InvalidSkillPackage("SKILL.md nested field is malformed")
            if data[current] == []:
                data[current] = {}
            if not isinstance(data.get(current), dict):
                raise InvalidSkillPackage("SKILL.md metadata must be a map")
            if key.strip() in data[current]:
                raise InvalidSkillPackage(f"duplicate frontmatter field: {key.strip()}")
            data[current][key.strip()] = _unquote(value)
        elif raw.startswith(" "):
            raise InvalidSkillPackage("SKILL.md frontmatter must use two-space indentation")
        else:
            key, separator, value = raw.partition(":")
            if not separator or not key.strip():
                raise InvalidSkillPackage("SKILL.md frontmatter field is malformed")
            current = key.strip()
            if current in data:
                raise InvalidSkillPackage(f"duplicate frontmatter field: {current}")
            data[current] = _unquote(value) if value.strip() else []

    return data, "".join(lines[closing + 1 :])


def _string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise InvalidSkillPackage(f"{field_name} must be a non-empty list")
    items: list[str] = []
    for item in value:
        normalized = _text(item, field_name)
        if normalized in items:
            raise InvalidSkillPackage(f"{field_name} must not repeat values")
        items.append(normalized)
    return items


def _read_files(package: Path, *, root: Path) -> dict[str, bytes]:
    if package.is_symlink():
        raise InvalidSkillPackage("skill package must not be a symlink")
    resolved = package.resolve(strict=True)
    if not resolved.is_dir() or not resolved.is_relative_to(root):
        raise InvalidSkillPackage("skill package is outside the module root")

    files: dict[str, bytes] = {}
    for current, directories, names in os.walk(resolved, followlinks=False):
        parent = Path(current)
        for directory in directories:
            candidate = parent / directory
            if candidate.is_symlink():
                raise InvalidSkillPackage("skill package must not contain symlinks")
        directories[:] = [name for name in sorted(directories) if not name.startswith(".")]
        for file_name in sorted(names):
            if file_name.startswith("."):
                continue
            path = parent / file_name
            if path.is_symlink():
                raise InvalidSkillPackage("skill package must not contain symlinks")
            if not path.is_file():
                raise InvalidSkillPackage("skill package contains a non-regular file")
            relative = path.relative_to(resolved)
            files[relative.as_posix()] = path.read_bytes()
    return files


def _load_skill(
    package: Path,
    *,
    root: Path,
    module_id: str,
    declared_digest: str | None = None,
) -> _Skill:
    files = _read_files(package, root=root)
    if "SKILL.md" not in files:
        raise InvalidSkillPackage("skill package must contain SKILL.md")
    try:
        text = files["SKILL.md"].decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidSkillPackage("SKILL.md must be UTF-8") from None
    front, body = _parse_frontmatter(text)
    unknown = set(front) - _ALLOWED_FRONTMATTER
    if unknown:
        raise InvalidSkillPackage("unknown frontmatter fields: " + ", ".join(sorted(unknown)))
    missing = _REQUIRED_FRONTMATTER - set(front)
    if missing:
        raise InvalidSkillPackage("missing frontmatter fields: " + ", ".join(sorted(missing)))

    name = _text(front["name"], "name")
    if not SKILL_NAME.fullmatch(name):
        raise InvalidSkillPackage("skill name is not a bounded lowercase identifier")
    if name != package.name:
        raise InvalidSkillPackage("skill name must match its package directory")
    description = _text(front["description"], "description", maximum=MAX_DESCRIPTION)
    if "\n" in description or not description.startswith("Trigger: "):
        raise InvalidSkillPackage("description must be one line starting with 'Trigger: '")
    _text(front["license"], "license")
    metadata = front["metadata"]
    if not isinstance(metadata, dict):
        raise InvalidSkillPackage("metadata must be a map of strings")
    _text(metadata.get("author"), "metadata.author")
    version = _text(metadata.get("version"), "metadata.version")
    if not VERSION.fullmatch(version):
        raise InvalidSkillPackage("metadata.version must be major.minor.patch")

    tools = _string_list(front["tools"], "tools")
    permissions = _string_list(front["permissions"], "permissions")
    unknown_permissions = [code for code in permissions if not is_known_permission(code)]
    if unknown_permissions:
        raise InvalidSkillPackage("unknown permissions: " + ", ".join(sorted(unknown_permissions)))
    capabilities = _string_list(front["capabilities"], "capabilities")
    unknown_capabilities = [code for code in capabilities if code not in CAPABILITIES]
    if unknown_capabilities:
        raise InvalidSkillPackage(
            "unknown capabilities: " + ", ".join(sorted(unknown_capabilities))
        )
    if "compatibility" in front:
        _text(front["compatibility"], "compatibility")
    if not body.strip():
        raise InvalidSkillPackage("SKILL.md body must not be empty")

    digest = package_digest(files)
    if declared_digest is not None and declared_digest != digest:
        raise InvalidSkillPackage(f"skill {name} digest does not match the module manifest")

    return _Skill(
        metadata={
            "name": name,
            "description": description,
            "version": version,
            "module": module_id,
            "permissions": sorted(permissions),
            "capabilities": sorted(capabilities),
            "digest": digest,
        },
        files=files,
        tools=tuple(tools),
    )


def _validate_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise InvalidSkillPackage("module manifest must be a map")
    unknown = set(manifest) - _MANIFEST_KEYS
    if unknown:
        raise InvalidSkillPackage("unknown manifest fields: " + ", ".join(sorted(unknown)))
    missing = {"id", "name", "version", "capabilities", "permissions"} - set(manifest)
    if missing:
        raise InvalidSkillPackage("missing manifest fields: " + ", ".join(sorted(missing)))

    module_id = _text(manifest["id"], "id")
    if not MODULE_ID.fullmatch(module_id):
        raise InvalidSkillPackage("module id is not a bounded lowercase identifier")
    name = _text(manifest["name"], "name")
    version = _text(manifest["version"], "version")
    if not VERSION.fullmatch(version):
        raise InvalidSkillPackage("module version must be major.minor.patch")

    capabilities = _string_list(manifest["capabilities"], "capabilities")
    unknown_capabilities = [code for code in capabilities if code not in CAPABILITIES]
    if unknown_capabilities:
        raise InvalidSkillPackage(
            "unknown capabilities: " + ", ".join(sorted(unknown_capabilities))
        )
    permissions = _string_list(manifest["permissions"], "permissions")
    unknown_permissions = [code for code in permissions if not is_known_permission(code)]
    if unknown_permissions:
        raise InvalidSkillPackage("unknown permissions: " + ", ".join(sorted(unknown_permissions)))

    skills_value = manifest.get("skills", [])
    if not isinstance(skills_value, list) or any(
        not isinstance(item, str) for item in skills_value
    ):
        raise InvalidSkillPackage("skills must be a list of skill names")
    skills = list(dict.fromkeys(skills_value))
    if len(skills) != len(skills_value):
        raise InvalidSkillPackage("skills must not repeat values")
    for skill in skills:
        if not SKILL_NAME.fullmatch(skill):
            raise InvalidSkillPackage("skill names must be bounded lowercase identifiers")

    digests_value = manifest.get("skillDigests", {})
    if not isinstance(digests_value, Mapping):
        raise InvalidSkillPackage("skillDigests must map skill names to digests")
    digests: dict[str, str] = {}
    for skill, digest in digests_value.items():
        if skill not in skills:
            raise InvalidSkillPackage("skillDigests must reference a declared skill")
        if (
            not isinstance(skill, str)
            or not isinstance(digest, str)
            or not _DIGEST.fullmatch(digest)
        ):
            raise InvalidSkillPackage("skillDigests must be lowercase SHA-256 values")
        digests[skill] = digest

    return {
        "id": module_id,
        "name": name,
        "version": version,
        "capabilities": sorted(capabilities),
        "permissions": sorted(permissions),
        "skills": skills,
        "skillDigests": digests,
    }


class SkillCatalog:
    """In-memory catalog over official packages and registered modules."""

    def __init__(self, official_root: Path | None = None) -> None:
        self._modules: dict[str, _Module] = {}
        self._skills: dict[str, tuple[str, _Skill]] = {}
        self._load_official(Path(official_root) if official_root is not None else OFFICIAL_ROOT)

    def _load_official(self, root: Path) -> None:
        if not root.is_dir():
            raise InvalidSkillPackage("official skill packages are not shipped")
        packages = sorted(path for path in root.iterdir() if path.is_dir())
        if not packages:
            raise InvalidSkillPackage("official skill catalog is empty")
        skills: dict[str, _Skill] = {}
        for package in packages:
            skill = _load_skill(package, root=root.resolve(), module_id=OFFICIAL_MODULE_ID)
            name = skill.metadata["name"]
            if name in skills:
                raise ModuleConflict(f"skill is already registered: {name}")
            skills[name] = skill
        permissions = sorted(
            {code for skill in skills.values() for code in skill.metadata["permissions"]}
        )
        capabilities = sorted(
            {code for skill in skills.values() for code in skill.metadata["capabilities"]}
        )
        module = _Module(
            metadata={
                "id": OFFICIAL_MODULE_ID,
                "name": "ITSM official skills",
                "version": OFFICIAL_MODULE_VERSION,
                "official": True,
                "permissions": permissions,
                "capabilities": capabilities,
            },
            skills=skills,
        )
        self._modules[OFFICIAL_MODULE_ID] = module
        for name, skill in skills.items():
            self._skills[name] = (OFFICIAL_MODULE_ID, skill)

    def list_skills(self) -> list[dict[str, Any]]:
        """Return metadata only, for every skill offered by an enabled module."""
        items: list[dict[str, Any]] = []
        for name in sorted(self._skills):
            module_id, skill = self._skills[name]
            if self._modules[module_id].enabled:
                items.append(dict(skill.metadata))
        return items

    def get_skill(self, name: str) -> dict[str, Any]:
        """Return one package's metadata plus its complete file map."""
        registered = self._skills.get(name)
        if registered is None or not self._modules[registered[0]].enabled:
            raise SkillNotFound("skill is not in the catalog")
        skill = registered[1]
        return {**skill.metadata, "files": dict(skill.files)}

    def list_modules(self) -> list[dict[str, Any]]:
        return [self._module_payload(module) for _, module in sorted(self._modules.items())]

    def get_module(self, module_id: str) -> dict[str, Any]:
        module = self._modules.get(module_id)
        if module is None:
            raise UnknownModule("module is not registered")
        return self._module_payload(module)

    @staticmethod
    def _module_payload(module: _Module) -> dict[str, Any]:
        return {
            **module.metadata,
            "enabled": module.enabled,
            "skills": sorted(module.skills),
        }

    def register_module(self, manifest: Mapping[str, Any], *, root: Path) -> None:
        """Validate and register a module and its packaged skills atomically."""
        checked = _validate_manifest(manifest)
        module_id = checked["id"]
        if module_id in self._modules:
            raise ModuleConflict("module id is already registered")

        module_root = Path(root)
        if not module_root.is_dir():
            raise InvalidSkillPackage("module root is not a directory")
        root_resolved = module_root.resolve(strict=True)
        staged: dict[str, _Skill] = {}
        for skill_name in checked["skills"]:
            package = module_root / "skills" / skill_name
            if not package.exists():
                raise InvalidSkillPackage("declared skill package does not exist")
            skill = _load_skill(
                package,
                root=root_resolved,
                module_id=module_id,
                declared_digest=checked["skillDigests"].get(skill_name),
            )
            permissions = set(skill.metadata["permissions"])
            if not permissions <= set(checked["permissions"]):
                raise InvalidSkillPackage("skill permissions exceed the module manifest")
            capabilities = set(skill.metadata["capabilities"])
            if not capabilities <= set(checked["capabilities"]):
                raise InvalidSkillPackage("skill capabilities exceed the module manifest")
            if skill.metadata["name"] in self._skills or skill.metadata["name"] in staged:
                raise ModuleConflict(f"skill is already registered: {skill.metadata['name']}")
            staged[skill.metadata["name"]] = skill

        module = _Module(
            metadata={
                "id": module_id,
                "name": checked["name"],
                "version": checked["version"],
                "official": False,
                "permissions": checked["permissions"],
                "capabilities": checked["capabilities"],
            },
            skills=staged,
        )
        self._modules[module_id] = module
        for name, skill in staged.items():
            self._skills[name] = (module_id, skill)

    def set_module_enabled(self, module_id: str, enabled: bool) -> None:
        module = self._modules.get(module_id)
        if module is None:
            raise UnknownModule("module is not registered")
        module.enabled = bool(enabled)


__all__ = [
    "CAPABILITIES",
    "OFFICIAL_MODULE_ID",
    "CatalogError",
    "InvalidSkillPackage",
    "ModuleConflict",
    "SkillCatalog",
    "SkillNotFound",
    "UnknownModule",
    "package_digest",
]
