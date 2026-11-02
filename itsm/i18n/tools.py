"""Translator tooling (S9/T7): sources, coverage, export, import and validation.

Only this module knows how a translator catalog becomes registry rows. It parses
JSON/PO, validates every message against the Spanish *source* catalog, builds
the coverage report and produces the downloadable export. The HTTP adapters in
``itsm/i18n/api.py`` only authorize, call these functions and translate problems
through ``api.i18n.problem.<reason>`` keys.

Validation rules (all reported together, nothing is written when one fails):

- unknown key: the key does not exist in the source catalog of its namespace;
- duplicate: the input repeats a key (JSON object pairs or PO ``msgctxt``);
- empty text, over-long text, non-string JSON value;
- malformed ``{parameter}`` syntax (unbalanced braces or an invalid name);
- parameter mismatch against the source message;
- plural forms: a pluralized source message must have exactly the CLDR category
  count of the target locale, and a single-form source must stay single.
"""

from __future__ import annotations

import io
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from babel.messages import pofile
from sqlalchemy.orm import Session

from itsm.i18n import registry
from itsm.i18n.catalog import CATALOG_DIR, DEFAULT_LOCALE
from itsm.i18n.messages import plural_categories, t
from itsm.i18n.packs import (
    MAX_MESSAGE_LENGTH,
    key_namespace,
    placeholder_names,
    plural_forms,
)

#: Spanish is the D3 source locale: every key is validated against its text.
SOURCE_LOCALE: Final[str] = DEFAULT_LOCALE
SOURCE_PROVIDER: Final[str] = registry.UI_SOURCE_PROVIDER
FORMATS: Final[tuple[str, str]] = ("json", "po")
DEFAULT_LIMIT: Final[int] = 50
MAX_LIMIT: Final[int] = 500
MAX_NAMESPACE_LENGTH: Final[int] = 200

_NAMESPACE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_PARAM = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


class UnsupportedFormat(ValueError):
    """The requested catalog format is neither JSON nor gettext PO."""

    def __init__(self, format_name: str) -> None:
        super().__init__(f"unsupported catalog format: {format_name!r}")
        self.format = format_name


class InvalidNamespace(ValueError):
    """The namespace prefix is not a safe catalog prefix."""

    def __init__(self, namespace: str) -> None:
        super().__init__(f"invalid namespace: {namespace!r}")
        self.namespace = namespace


@dataclass(frozen=True)
class Problem:
    """One rejected catalog entry, addressed by its translation key."""

    key: str | None
    reason: str
    params: Mapping[str, Any] = field(default_factory=dict)

    @property
    def message_key(self) -> str:
        return f"api.i18n.problem.{self.reason}"


def problem_payload(problem: Problem, locale: str) -> dict[str, Any]:
    """The public problem shape: key, machine reason and a localized message."""
    return {
        "key": problem.key,
        "reason": problem.reason,
        "reasonKey": problem.message_key,
        "message": t(problem.message_key, locale, **dict(problem.params)),
        "params": dict(problem.params),
    }


def problems_payload(problems: Sequence[Problem], locale: str) -> list[dict[str, Any]]:
    return [problem_payload(problem, locale) for problem in problems]


# --------------------------------------------------------------------------- #
# namespace filter
# --------------------------------------------------------------------------- #


def validate_namespace(namespace: str | None) -> str | None:
    """Normalize an optional namespace prefix (``ui``, ``api``, ``ext.<id>``)."""
    if namespace is None:
        return None
    candidate = namespace.strip()
    if (
        not candidate
        or len(candidate) > MAX_NAMESPACE_LENGTH
        or not _NAMESPACE.match(candidate)
        or candidate.endswith(".")
    ):
        raise InvalidNamespace(namespace)
    return candidate


def matches_namespace(key: str, namespace: str | None) -> bool:
    if namespace is None:
        return True
    return key == namespace or key.startswith(namespace + ".")


def namespace_of(key: str) -> str:
    """The report bucket of a key: ``api``, ``ui`` or ``ext.<id>``."""
    return key_namespace(key) or "other"


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #


def _malformed(message: str) -> bool:
    """True when a ``{parameter}`` is unbalanced or not a valid named parameter."""
    index = 0
    while index < len(message):
        character = message[index]
        if character == "{":
            end = message.find("}", index)
            if end == -1 or not _PARAM.fullmatch(message[index : end + 1]):
                return True
            index = end
        elif character == "}":
            return True
        index += 1
    return False


class _Pairs(list):
    """JSON object pairs, kept so duplicate keys survive ``json.loads``."""


def _parse_json(content: str) -> tuple[list[tuple[str, str]], list[Problem]]:
    problems: list[Problem] = []
    try:
        tree = json.loads(content, object_pairs_hook=_Pairs)
    except json.JSONDecodeError, ValueError:
        return [], [Problem(None, "invalid_json")]
    if not isinstance(tree, _Pairs):
        return [], [Problem(None, "invalid_json")]
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key, value in tree:
        if not isinstance(key, str):
            problems.append(Problem(None, "invalid_key"))
            continue
        if key in seen:
            problems.append(Problem(key, "duplicate_key"))
            continue
        seen.add(key)
        if not isinstance(value, str):
            problems.append(Problem(key, "invalid_value"))
            continue
        entries.append((key, value))
    return entries, problems


def _parse_po(content: str) -> tuple[list[tuple[str, str]], list[Problem]]:
    try:
        catalog = pofile.read_po(io.BytesIO(content.encode("utf-8")))
    except Exception:
        return [], [Problem(None, "invalid_po")]
    # Babel tolerates arbitrary text and yields an empty catalog; an import that
    # does not even contain a ``msgid`` is not a PO file, not an empty one.
    if not re.search(r"^\s*msgid\b", content, re.MULTILINE):
        return [], [Problem(None, "invalid_po")]
    entries: list[tuple[str, str]] = []
    problems: list[Problem] = []
    seen: set[str] = set()
    # ``read_po`` silently collapses two entries that share ``msgctxt`` and
    # ``msgid``, so duplicates have to be detected on the raw input instead.
    for match in re.finditer(r'^msgctxt\s+"((?:[^"\\]|\\.)*)"', content, re.MULTILINE):
        key = match.group(1)
        if not key:
            continue
        if key in seen:
            problems.append(Problem(key, "duplicate_key"))
        seen.add(key)
    seen = set()
    for message in catalog:
        # The header (and any entry without ``msgctxt``) carries no translation key.
        if not message.context:
            continue
        key = str(message.context)
        if key in seen:
            problems.append(Problem(key, "duplicate_key"))
            continue
        seen.add(key)
        raw = message.string
        text = (
            " | ".join(str(part).strip() for part in raw)
            if isinstance(raw, tuple)
            else str(raw or "")
        )
        # An empty ``msgstr`` is how a PO file says "not translated yet".
        if not text.strip():
            continue
        entries.append((key, text))
    return entries, problems


def parse_catalog(format_name: str, content: str) -> tuple[list[tuple[str, str]], list[Problem]]:
    """Parse a posted catalog; returns the entries in input order and parse problems."""
    if format_name == "json":
        return _parse_json(content)
    if format_name == "po":
        return _parse_po(content)
    raise UnsupportedFormat(format_name)


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #


def entry_problems(
    locale: str,
    key: str,
    message: str,
    sources: Mapping[str, str],
) -> list[Problem]:
    """Every problem of one posted entry against the Spanish source message."""
    if key_namespace(key) is None:
        return [Problem(key, "invalid_key")]
    source = sources.get(key)
    if source is None:
        return [Problem(key, "unknown_key")]
    if not message.strip():
        return [Problem(key, "empty_text")]
    problems: list[Problem] = []
    if len(message) > MAX_MESSAGE_LENGTH:
        problems.append(Problem(key, "too_long"))
    if _malformed(message):
        problems.append(Problem(key, "malformed_message"))
        return problems
    expected = placeholder_names(source)
    actual = placeholder_names(message)
    if expected != actual:
        problems.append(
            Problem(
                key,
                "parameters_mismatch",
                {
                    "missing": ", ".join(sorted(expected - actual)) or "none",
                    "unexpected": ", ".join(sorted(actual - expected)) or "none",
                },
            )
        )
    expected_forms = len(plural_forms(source))
    actual_forms = len(plural_forms(message))
    if expected_forms > 1:
        # A translation may use the CLDR category count of its locale, or the
        # form count of the source template when CLDR allows more categories
        # (the shipped Spanish catalog collapses ``many`` into ``other``).
        categories = len(plural_categories(locale))
        if actual_forms not in {categories, expected_forms}:
            problems.append(
                Problem(
                    key,
                    "plural_forms_mismatch",
                    {"expected": categories, "actual": actual_forms, "locale": locale},
                )
            )
    elif actual_forms > 1:
        problems.append(
            Problem(
                key,
                "plural_forms_mismatch",
                {"expected": 1, "actual": actual_forms, "locale": locale},
            )
        )
    return problems


def validate_entries(
    locale: str, entries: Sequence[tuple[str, str]], sources: Mapping[str, str]
) -> list[Problem]:
    problems: list[Problem] = []
    for key, message in entries:
        problems.extend(entry_problems(locale, key, message, sources))
    return problems


# --------------------------------------------------------------------------- #
# source catalogs and locale text
# --------------------------------------------------------------------------- #


def source_texts(session: Session) -> dict[str, str]:
    """The Spanish source text of every translatable key owned by this install."""
    texts = dict(registry.load_catalog(SOURCE_LOCALE) or {})
    registered = registry.source_catalogs(session)
    texts.update(registered.get(SOURCE_LOCALE, {}))
    texts.update(registry.extension_source_entries(session, SOURCE_LOCALE))
    return texts


def source_context_map(session: Session) -> dict[str, str]:
    """Translator context per key: shipped core context plus registered context."""
    shipped: dict[str, str] = {}
    path = CATALOG_DIR / "context.json"
    if path.is_file():
        shipped = {
            str(key): str(value)
            for key, value in json.loads(path.read_text(encoding="utf-8")).items()
        }
    shipped.update(registry.source_context(session))
    return shipped


def locale_texts(session: Session, snapshot: registry.Snapshot, canonical: str) -> dict[str, str]:
    """Effective text of one locale: the D5 overlay plus its registered source."""
    texts = dict(snapshot.locale_view(canonical).messages)
    registered = registry.source_catalogs(session).get(canonical, {})
    for key, value in registered.items():
        texts.setdefault(key, value)
    return texts


def _descriptor(snapshot: registry.Snapshot, canonical: str) -> dict[str, str] | None:
    for descriptor in snapshot.descriptors:
        if registry.canonical_tag(descriptor["tag"]) == canonical:
            return descriptor
    return None


# --------------------------------------------------------------------------- #
# source registration
# --------------------------------------------------------------------------- #


def normalize_ui_source(
    catalogs: Mapping[str, Mapping[str, str]],
    context: Mapping[str, str],
) -> tuple[dict[str, dict[str, str]], list[Problem]]:
    """Validate the frontend ``ui.*`` source registration; returns normalized text."""
    problems: list[Problem] = []
    normalized: dict[str, dict[str, str]] = {}
    provided: set[str] = set()
    rejected: set[tuple[str, str]] = set()
    for locale, catalog in catalogs.items():
        canonical = registry.canonical_tag(locale)
        if canonical is None:
            problems.append(Problem(None, "unknown_locale", {"locale": str(locale)}))
            continue
        provided.add(canonical)
        target = normalized.setdefault(canonical, {})
        for key, message in catalog.items():
            namespace = key_namespace(key)
            if namespace is None:
                problems.append(Problem(key, "invalid_key", {"locale": canonical}))
                rejected.add((canonical, key))
                continue
            if namespace != "ui":
                problems.append(Problem(key, "namespace_not_allowed", {"locale": canonical}))
                rejected.add((canonical, key))
                continue
            target[key] = message

    if SOURCE_LOCALE not in provided:
        problems.append(Problem(None, "source_locale_missing", {"locale": SOURCE_LOCALE}))
        return normalized, problems

    source = normalized.get(SOURCE_LOCALE, {})
    for locale in sorted(normalized):
        for key, message in normalized[locale].items():
            if (locale, key) in rejected:
                continue
            problems.extend(entry_problems(locale, key, message, source))

    known = set().union(*(set(catalog) for catalog in normalized.values())) if normalized else set()
    for key in sorted(context):
        if key not in known:
            problems.append(Problem(key, "unknown_context"))
    return normalized, problems


# --------------------------------------------------------------------------- #
# coverage
# --------------------------------------------------------------------------- #


def coverage_report(
    session: Session,
    *,
    locale: str | None = None,
    namespace: str | None = None,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    """Per installed locale: totals, missing page, providers and orphaned keys."""
    snapshot = registry.snapshot(session)
    sources = source_texts(session)
    context = source_context_map(session)
    source_keys = sorted(key for key in sources if matches_namespace(key, namespace))

    namespaces: dict[str, int] = {}
    for key in source_keys:
        bucket = namespace_of(key)
        namespaces[bucket] = namespaces.get(bucket, 0) + 1

    tags = list(snapshot.tags)
    if locale is not None:
        resolved = snapshot.resolve(locale)
        if resolved is None:
            raise KeyError(locale)
        tags = [resolved]

    custom = registry.custom_catalog(session)
    locales: list[dict[str, Any]] = []
    for canonical in tags:
        texts = locale_texts(session, snapshot, canonical)
        translated = sum(1 for key in source_keys if texts.get(key, "").strip())
        missing_keys = [key for key in source_keys if not texts.get(key, "").strip()]
        page = missing_keys[offset : offset + limit]
        descriptor = _descriptor(snapshot, canonical) or {
            "tag": canonical,
            "name": canonical,
            "nativeName": canonical,
            "provider": registry.CORE_PROVIDER,
        }
        locale_custom = {
            key: value
            for key, value in custom.get(canonical, {}).items()
            if matches_namespace(key, namespace)
        }
        orphaned = [
            {
                "key": key,
                "reason": "source_key_missing",
                "reasonKey": "api.i18n.problem.source_key_missing",
                "message": t("api.i18n.problem.source_key_missing", canonical, key=key),
                "params": {"key": key},
            }
            for key in sorted(locale_custom)
            if key not in sources
        ]
        locales.append(
            {
                "tag": canonical,
                "displayTag": descriptor["tag"],
                "name": descriptor["name"],
                "nativeName": descriptor["nativeName"],
                "localeProvider": descriptor["provider"],
                "source": canonical == SOURCE_LOCALE,
                "total": len(source_keys),
                "translated": translated,
                "percentage": round(translated * 100 / len(source_keys), 2)
                if source_keys
                else 100.0,
                "providers": [
                    {
                        "id": contribution.provider_id,
                        "kind": contribution.kind,
                        "entries": contribution.entries,
                    }
                    for contribution in registry.contributions(session, canonical)
                ],
                "custom": {"entries": len(locale_custom), "orphaned": orphaned},
                "missing": {
                    "total": len(missing_keys),
                    "limit": limit,
                    "offset": offset,
                    "items": [{"key": key, "context": context.get(key, "")} for key in page],
                },
            }
        )

    return {
        "revision": snapshot.revision,
        "sourceLocale": SOURCE_LOCALE,
        "namespace": namespace,
        "page": {"limit": limit, "offset": offset},
        "source": {
            "locale": SOURCE_LOCALE,
            "total": len(source_keys),
            "namespaces": dict(sorted(namespaces.items())),
        },
        "locales": locales,
    }


# --------------------------------------------------------------------------- #
# export
# --------------------------------------------------------------------------- #


def export_document(
    session: Session,
    canonical: str,
    *,
    namespace: str | None = None,
    format_name: str = "json",
) -> tuple[bytes, str, str]:
    """Render one locale as downloadable JSON or gettext PO."""
    if format_name not in FORMATS:
        raise UnsupportedFormat(format_name)
    namespace = validate_namespace(namespace)
    snapshot = registry.snapshot(session)
    sources = source_texts(session)
    texts = locale_texts(session, snapshot, canonical)
    keys = sorted(key for key in sources if matches_namespace(key, namespace))
    stem = canonical if namespace is None else f"{canonical}.{namespace}"

    if format_name == "json":
        document = {key: texts[key] for key in keys if texts.get(key, "").strip()}
        body = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        return body.encode("utf-8"), "application/json", f"{stem}.json"

    context = source_context_map(session)
    catalog = pofile.Catalog(
        locale=canonical.replace("-", "_"), fuzzy=False, project="ITSM", version="1.0"
    )
    for key in keys:
        comment = context.get(key, "").strip()
        catalog.add(
            sources[key],
            texts.get(key, ""),
            context=key,
            auto_comments=[comment] if comment else [],
        )
    buffer = io.BytesIO()
    pofile.write_po(buffer, catalog, width=100)
    return (
        buffer.getvalue(),
        "text/x-gettext-translation",
        f"{stem}.po",
    )


# --------------------------------------------------------------------------- #
# import and validate
# --------------------------------------------------------------------------- #


def catalog_report(
    session: Session,
    canonical: str,
    format_name: str,
    content: str,
    *,
    sources: Mapping[str, str],
    dry_run: bool,
) -> dict[str, Any]:
    """Validate and, unless dry-run or invalid, store one locale's custom layer."""
    entries, problems = parse_catalog(format_name, content)
    problems = [*problems, *validate_entries(canonical, entries, sources)]
    # The HTTP layer localizes problems; the report keeps the request locale
    # because a translator edits the language they are importing into.
    report_locale = canonical
    report: dict[str, Any] = {
        "locale": canonical,
        "format": format_name,
        "valid": not problems,
        "dryRun": dry_run,
        "entries": len(entries),
        "applied": 0,
        "problems": problems_payload(problems, report_locale),
        "revision": registry.revision(session),
    }
    if problems or dry_run:
        return report
    applied = registry.set_custom_translations(session, canonical, dict(entries))
    report["applied"] = applied
    report["revision"] = registry.revision(session)
    return report
