"""Catalog content validation and the SDK i18n contract (D2, D6, D10).

This module is pure: it never reads the database, never inspects the filesystem
and never imports the extension runtime, so the same checks run inside the SDK,
the host admission path and the offline validator container.

A catalog is a flat JSON object ``{"<key>": "<message>"}``. Messages use the D2
syntax: named ``{parameters}`` and plural forms separated by `` | `` in CLDR
category order. A translation keeps the source parameters and the source number
of plural forms; that is what "parameter or plural-form mismatch" means.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

LOCALE_TAG: Final = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")
EXTENSION_ID: Final = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
CATALOG_PATH: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*\.json$")
DOC_PATH: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*\.md$")
TOPIC: Final = re.compile(r"^[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*$")
RANGE: Final = re.compile(r"^(?:\*|[~^]?\d+\.\d+\.\d+|[<>]=?\d+\.\d+\.\d+)$")
VERSION: Final = re.compile(r"^\d+\.\d+\.\d+$")

MAX_KEY_LENGTH: Final = 200
MAX_MESSAGE_LENGTH: Final = 4000
REVIEW_STATUSES: Final = ("draft", "reviewed")

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


class CatalogError(ValueError):
    """A catalog file is not a flat JSON object of messages."""


def parse_catalog(text: str, name: str = "catalog") -> dict[str, str]:
    """Parse one catalog, rejecting duplicate keys and non-string messages."""
    if not isinstance(text, str):
        raise CatalogError(f"{name}: catalog must be text")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, str]:
        result: dict[str, str] = {}
        for key, value in items:
            if key in result:
                raise CatalogError(f"{name}: duplicate key {key}")
            if not isinstance(value, str):
                raise CatalogError(f"{name}: message for {key} must be a string")
            result[key] = value
        return result

    try:
        data = json.loads(text, object_pairs_hook=pairs)
    except json.JSONDecodeError as exc:
        raise CatalogError(f"{name}: invalid JSON: {exc.msg}") from None
    if not isinstance(data, dict):
        raise CatalogError(f"{name}: catalog must be a JSON object")
    return data


def is_literal_json_message(message: str) -> bool:
    """Recognize a complete, non-empty JSON string map used as example copy."""
    if not message.lstrip().startswith("{"):
        return False
    duplicate = False

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal duplicate
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                duplicate = True
            result[key] = value
        return result

    try:
        value = json.loads(message, object_pairs_hook=pairs)
    except json.JSONDecodeError, ValueError:
        return False
    if duplicate or not isinstance(value, dict) or not value:
        return False
    return all(isinstance(key, str) and isinstance(item, str) for key, item in value.items())


def placeholder_names(message: str) -> frozenset[str]:
    """The named parameters a message uses."""
    if is_literal_json_message(message):
        return frozenset()
    return frozenset(_PLACEHOLDER.findall(message))


def plural_forms(message: str) -> tuple[str, ...]:
    """The plural forms of a message (one item when it does not pluralize)."""
    if is_literal_json_message(message):
        return (message,)
    return tuple(form.strip() for form in message.split("|"))


def key_namespace(key: str) -> str | None:
    """The namespace a key belongs to: ``ui``, ``api`` or ``ext.<id>``."""
    if not isinstance(key, str) or not key or len(key) > MAX_KEY_LENGTH:
        return None
    parts = key.split(".")
    if len(parts) < 3 or not all(parts):
        return None
    if parts[0] in {"ui", "api"}:
        return parts[0]
    if parts[0] == "ext" and EXTENSION_ID.match(parts[1] or ""):
        return f"ext.{parts[1]}"
    return None


def key_errors(key: str) -> list[str]:
    """Key-shape errors; an empty list means the key is usable."""
    return [] if key_namespace(key) is not None else [f"invalid translation key: {key!r}"]


def validate_translation(
    key: str, locale: str, message: str, source: str, source_locale: str
) -> list[str]:
    """One translation against its source message (parameters and plural forms)."""
    if not isinstance(message, str) or not message.strip():
        return [f"{locale} {key}: message must be a non-empty string"]
    problems: list[str] = []
    if len(message) > MAX_MESSAGE_LENGTH:
        problems.append(f"{locale} {key}: message is too long")
    expected = placeholder_names(source)
    actual = placeholder_names(message)
    if expected != actual:
        missing = ", ".join(sorted(expected - actual)) or "none"
        extra = ", ".join(sorted(actual - expected)) or "none"
        problems.append(
            f"{locale} {key}: parameters differ from {source_locale}"
            f" (missing: {missing}; unexpected: {extra})"
        )
    if len(plural_forms(message)) != len(plural_forms(source)):
        problems.append(
            f"{locale} {key}: plural forms differ from {source_locale}"
            f" ({len(plural_forms(message))} instead of {len(plural_forms(source))})"
        )
    return problems


def extension_i18n_errors(extension_id: str, block: Mapping[str, Any]) -> list[str]:
    """Structural `i18n` block rules: source locale, namespaces and paths."""
    problems: list[str] = []
    prefix = f"ext.{extension_id}."
    source_locale = block.get("sourceLocale")
    declared = block.get("catalogs") or {}
    if not isinstance(source_locale, str) or not LOCALE_TAG.match(source_locale):
        problems.append(f"i18n.sourceLocale is not a locale tag: {source_locale!r}")
    if not isinstance(declared, Mapping) or not declared:
        problems.append("i18n.catalogs must declare at least one locale catalog")
        return problems
    if isinstance(source_locale, str) and source_locale not in declared:
        problems.append(f"i18n.catalogs must include the source locale {source_locale}")
    if block.get("overrides"):
        problems.append("an extension i18n block cannot override keys; use a language pack")
    for locale, path in declared.items():
        if not LOCALE_TAG.match(str(locale)):
            problems.append(f"i18n.catalogs has an invalid locale tag: {locale!r}")
        if not CATALOG_PATH.match(str(path)) or ".." in str(path):
            problems.append(f"i18n.catalogs[{locale}] is not a relative .json path: {path!r}")
    if not prefix:
        problems.append("i18n block needs an extension id")
    return problems


def validate_extension_catalogs(
    extension_id: str,
    block: Mapping[str, Any],
    catalogs: Mapping[str, Mapping[str, str]],
) -> list[str]:
    """Own namespace, complete source locale and matching target catalogs."""
    problems = extension_i18n_errors(extension_id, block)
    prefix = f"ext.{extension_id}."
    source_locale = block.get("sourceLocale")
    if not isinstance(source_locale, str) or source_locale not in catalogs:
        return problems
    source = catalogs[source_locale]
    for key in source:
        if not key.startswith(prefix):
            problems.append(f"key {key!r} is outside the {prefix} namespace")
        problems.extend(key_errors(key))
    for locale, catalog in catalogs.items():
        if locale == source_locale:
            continue
        for key in catalog:
            if key not in source:
                problems.append(f"{locale} {key}: key is missing from the {source_locale} source")
        for key, source_message in source.items():
            if key not in catalog:
                problems.append(f"{locale} {key}: translation is missing from {locale}")
                continue
            problems.extend(
                validate_translation(key, locale, catalog[key], source_message, source_locale)
            )
    return problems


def declared_locales(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    """The tags a pack declares, in manifest order."""
    locales = manifest.get("locales") or ()
    return tuple(
        str(item.get("tag")) for item in locales if isinstance(item, Mapping) and item.get("tag")
    )


def pack_manifest_errors(manifest: Mapping[str, Any]) -> list[str]:
    """The structural D10 rules that need no catalog contents."""
    problems: list[str] = []
    if manifest.get("kind") != "language-pack":
        problems.append("kind must be language-pack")
    if manifest.get("sdkVersion") != 2:
        problems.append("sdkVersion must be 2")
    if not str(manifest.get("id") or ""):
        problems.append("a language pack needs an id")
    if not str(manifest.get("name") or "").strip():
        problems.append("a language pack needs a name")
    version = manifest.get("version")
    if not isinstance(version, str) or not VERSION.match(version):
        problems.append(f"version must be X.Y.Z: {version!r}")

    locales = declared_locales(manifest)
    if not locales:
        problems.append("a language pack must declare at least one locale")
    for item in manifest.get("locales") or ():
        if not isinstance(item, Mapping):
            problems.append("locales entries must be objects")
            continue
        tag = str(item.get("tag") or "")
        if not LOCALE_TAG.match(tag):
            problems.append(f"invalid locale tag: {tag!r}")
        for field in ("name", "nativeName"):
            value = item.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"locale {tag!r} needs a non-empty {field}")
    if len(set(locales)) != len(locales):
        problems.append("locales must not repeat a tag")

    catalogs = manifest.get("catalogs") or {}
    if not isinstance(catalogs, Mapping) or not catalogs:
        problems.append("catalogs must map at least one locale to a path")
    else:
        for locale, path in catalogs.items():
            if not LOCALE_TAG.match(str(locale)):
                problems.append(f"catalogs has an invalid locale tag: {locale!r}")
            if not CATALOG_PATH.match(str(path)) or ".." in str(path):
                problems.append(f"catalogs[{locale}] is not a relative .json path: {path!r}")
            if str(locale) not in locales and locales:
                problems.append(f"catalog {locale} is not declared in locales")

    overrides = manifest.get("overrides") or ()
    if not isinstance(overrides, Sequence) or isinstance(overrides, str):
        problems.append("overrides must be a list of keys")
    else:
        for key in overrides:
            problems.extend(key_errors(str(key)))
        if len(set(map(str, overrides))) != len(overrides):
            problems.append("overrides must not repeat a key")

    compatibility = manifest.get("compatibility") or {}
    if not isinstance(compatibility, Mapping):
        problems.append("compatibility must be an object")
    else:
        core_range = compatibility.get("core")
        if not isinstance(core_range, str) or compatibility_matches(core_range, "0.0.0") is None:
            problems.append(f"compatibility.core is not a valid range: {core_range!r}")
        extensions = compatibility.get("extensions") or {}
        if not isinstance(extensions, Mapping):
            problems.append("compatibility.extensions must map extension ids to ranges")
        else:
            for extension_id, range_text in extensions.items():
                if not EXTENSION_ID.match(str(extension_id)):
                    problems.append(f"compatibility.extensions has an invalid id: {extension_id!r}")
                if compatibility_matches(str(range_text), "0.0.0") is None:
                    problems.append(
                        f"compatibility.extensions[{extension_id}] is not a valid range:"
                        f" {range_text!r}"
                    )

    docs = manifest.get("docs") or {}
    if not isinstance(docs, Mapping):
        problems.append("docs must map locales to topics")
    else:
        for locale, topics in docs.items():
            if not LOCALE_TAG.match(str(locale)):
                problems.append(f"docs has an invalid locale tag: {locale!r}")
            elif locales and str(locale) not in locales:
                problems.append(f"docs locale {locale} is not declared in locales")
            if not isinstance(topics, Mapping):
                problems.append(f"docs[{locale}] must map topics to paths")
                continue
            for topic, path in topics.items():
                if not TOPIC.match(str(topic)):
                    problems.append(f"docs topic is invalid: {topic!r}")
                if not DOC_PATH.match(str(path)) or ".." in str(path):
                    problems.append(f"docs[{locale}][{topic}] is not a relative .md path: {path!r}")

    review = manifest.get("review") or {}
    status = review.get("status") if isinstance(review, Mapping) else None
    if status not in REVIEW_STATUSES:
        problems.append(f"review.status must be draft or reviewed: {status!r}")
    priority = manifest.get("priority", 0)
    if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= 1000:
        problems.append(f"priority must be an integer between 0 and 1000: {priority!r}")
    return problems


def validate_language_pack(
    manifest: Mapping[str, Any],
    catalogs: Mapping[str, Mapping[str, str]],
    *,
    sources: Mapping[str, Mapping[str, str]] | None = None,
    owner_catalogs: Mapping[str, Mapping[str, str]] | None = None,
) -> list[str]:
    """The D6/D10 content rules: overrides, source parity and catalog coverage.

    ``sources`` maps a provider id to its source-locale catalog (the host passes
    the core catalog first, then each installed extension), and ``owner_catalogs``
    maps a locale to the texts its owners already define there. A package that
    repeats an owned key without listing it in ``overrides`` is rejected.
    """
    problems: list[str] = []
    overrides = {str(key) for key in (manifest.get("overrides") or ())}
    declared = set(declared_locales(manifest))
    for locale in catalogs:
        if declared and locale not in declared:
            problems.append(f"catalog {locale} is not declared in locales")
    for locale in declared:
        if locale not in catalogs:
            problems.append(f"locale {locale} has no catalog")

    for locale, catalog in catalogs.items():
        # Owners are keyed canonically (``pt-br``); a manifest may declare
        # ``pt-BR``, so accept either spelling of the same locale.
        normalized = str(locale).replace("_", "-").lower()
        owners = owner_catalogs or {}
        owned = owners.get(locale) or owners.get(normalized) or {}
        for key, message in catalog.items():
            problems.extend(key_errors(key))
            source = _source_for(key, sources or {})
            if source is not None:
                problems.extend(validate_translation(key, locale, message, source[0], source[1]))
            if key in owned and key not in overrides:
                problems.append(
                    f"{locale} {key}: the key already exists in that locale;"
                    " list it in overrides to replace it explicitly"
                )
    return problems


def _source_for(key: str, sources: Mapping[str, Mapping[str, str]]) -> tuple[str, str] | None:
    """The first provider source-locale message that owns ``key``, when any."""
    for provider_id, catalog in sources.items():
        if key in catalog:
            return catalog[key], f"the {provider_id} source locale"
    return None


def validate_i18n_files(
    manifest: Mapping[str, Any],
    files: Mapping[str, str],
    *,
    sources: Mapping[str, Mapping[str, str]] | None = None,
    owner_catalogs: Mapping[str, Mapping[str, str]] | None = None,
) -> list[str]:
    """Validate the catalogs and docs a manifest declares against a file mapping."""
    problems: list[str] = []
    kind = manifest.get("kind", "extension")
    block = manifest.get("catalogs") if kind == "language-pack" else manifest.get("i18n")
    declared = block if kind == "language-pack" else (block or {}).get("catalogs")
    catalogs: dict[str, dict[str, str]] = {}
    for locale, path in (declared or {}).items():
        text = files.get(str(path))
        if text is None:
            problems.append(f"package is missing declared catalog: {path}")
            continue
        try:
            catalogs[str(locale)] = parse_catalog(str(text), str(path))
        except CatalogError as exc:
            problems.append(str(exc))
    if kind == "language-pack":
        problems.extend(pack_manifest_errors(manifest))
        problems.extend(
            validate_language_pack(
                manifest,
                catalogs,
                sources=sources,
                owner_catalogs=owner_catalogs,
            )
        )
        for topics in (manifest.get("docs") or {}).values():
            for path in (topics or {}).values():
                text = files.get(str(path))
                if text is None:
                    problems.append(f"package is missing declared doc: {path}")
                elif not str(text).strip():
                    problems.append(f"declared doc is empty: {path}")
    elif block:
        problems.extend(validate_extension_catalogs(str(manifest.get("id") or ""), block, catalogs))
    return problems


def read_i18n_content(
    manifest: Mapping[str, Any], files: Mapping[str, str]
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """Parse the catalogs and docs a manifest declares out of one file mapping.

    The caller has already validated the declarations (``validate_i18n_files``);
    this returns the parsed content the registry stores, so a package is parsed
    exactly once per admission path.
    """
    kind = manifest.get("kind", "extension")
    block = manifest.get("catalogs") if kind == "language-pack" else manifest.get("i18n")
    declared = block if kind == "language-pack" else (block or {}).get("catalogs")
    catalogs: dict[str, dict[str, str]] = {}
    if isinstance(declared, Mapping):
        for locale, path in declared.items():
            text = files.get(str(path))
            if text is not None:
                catalogs[str(locale)] = parse_catalog(str(text), str(path))
    docs: dict[str, dict[str, str]] = {}
    if kind == "language-pack":
        for locale, topics in (manifest.get("docs") or {}).items():
            if not isinstance(topics, Mapping):
                continue
            for topic, path in topics.items():
                text = files.get(str(path))
                if text is not None:
                    docs.setdefault(str(locale), {})[str(topic)] = str(text)
    return catalogs, docs


def compatibility_matches(range_text: str, version: str) -> bool | None:
    """Whether ``version`` satisfies a range; ``None`` means either one is invalid."""
    if not isinstance(range_text, str) or not RANGE.match(range_text):
        return None
    if not VERSION.match(version):
        return None
    if range_text == "*":
        return True
    current = _version_tuple(version)
    if range_text[0] in "<>":
        operator = range_text[:2] if range_text[1] == "=" else range_text[0]
        target = _version_tuple(range_text[len(operator) :])
        return {
            ">=": current >= target,
            "<=": current <= target,
            ">": current > target,
            "<": current < target,
        }[operator]
    if range_text.startswith("^"):
        lower = _version_tuple(range_text[1:])
        return lower <= current < (lower[0] + 1, 0, 0)
    if range_text.startswith("~"):
        lower = _version_tuple(range_text[1:])
        return lower <= current < (lower[0], lower[1] + 1, 0)
    return current == _version_tuple(range_text)


def _version_tuple(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


def compatibility_errors(
    manifest: Mapping[str, Any],
    *,
    core_version: str,
    extension_versions: Mapping[str, str],
) -> list[str]:
    """Core and per-extension ranges against the versions installed right now."""
    compatibility = manifest.get("compatibility") or {}
    problems: list[str] = []
    core_range = compatibility.get("core") if isinstance(compatibility, Mapping) else None
    if not core_range:
        problems.append("compatibility.core is required")
    elif compatibility_matches(str(core_range), core_version) is None:
        problems.append(f"compatibility.core is not a valid range: {core_range!r}")
    elif not compatibility_matches(str(core_range), core_version):
        problems.append(f"package requires core {core_range}, installed {core_version}")

    extensions = (
        compatibility.get("extensions") if isinstance(compatibility, Mapping) else None
    ) or {}
    if not isinstance(extensions, Mapping):
        problems.append("compatibility.extensions must map extension ids to ranges")
        return problems
    for extension_id, range_text in extensions.items():
        if compatibility_matches(str(range_text), "0.0.0") is None:
            problems.append(
                f"compatibility.extensions[{extension_id}] is not a valid range: {range_text!r}"
            )
            continue
        installed = extension_versions.get(str(extension_id))
        if installed is None:
            problems.append(f"package requires extension {extension_id}, which is not installed")
        elif not compatibility_matches(str(range_text), installed):
            problems.append(f"package requires {extension_id} {range_text}, installed {installed}")
    return problems


def label_text(value: Any, fallback_locale: str = "es") -> str:
    """The source text of a label that may be a string or a locale map."""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping) and value:
        preferred = value.get(fallback_locale)
        if isinstance(preferred, str):
            return preferred
        first = value[sorted(value)[0]]
        if isinstance(first, str):
            return first
    return ""
