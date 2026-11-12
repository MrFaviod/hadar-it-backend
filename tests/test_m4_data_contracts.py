"""M4 catalog, CSS footer and bounded SDK contract regressions."""

from __future__ import annotations

import copy
from html.parser import HTMLParser

import pytest
import tinycss2
from itsm.extensions.sdk.contract import (
    ArgumentError,
    CollectionError,
    ManifestError,
    validate_arguments,
    validate_collection_value,
    validate_manifest,
)
from itsm.i18n.documents import DocumentLocale
from itsm.identity.service import ValidationFailed
from itsm.inventory.catalog import InventoryCatalog
from itsm.inventory.service import InventoryService
from itsm.reports.composition import compose_document
from tests.inventory_support import prepare
from tests.test_extension_runtime_support import (
    DECLARATIVE_ID,
    build_package,
    declarative_manifest,
    env,  # noqa: F401 - pytest fixture
    probe_manifest,
)
from tests.test_phase9_rendering import context, inventory_template


@pytest.mark.parametrize("alias", ["servidores", "Servidores"])
def test_inactive_category_blocks_new_assignment_not_history(settings_factory, alias):
    db = prepare(settings_factory)
    try:
        with db.session() as session:
            service = InventoryService(session, db.settings)
            principal = db.admin()
            old = service.create(principal, {"name": "Historical", "category": "servidores"})
            other = service.create(principal, {"name": "Other", "category": "legacy category"})
            catalog = InventoryCatalog(session, db.settings)
            category = catalog.category("servidores")
            assert category is not None
            catalog.put(principal, "categories", category["id"], {**category, "active": False})
            before = service.search(principal).as_payload()
            history = service.history(principal, other.id)
            for action in (
                lambda: service.create(principal, {"name": "Rejected", "category": alias}),
                lambda: service.update(principal, other.id, {"category": alias}),
            ):
                with pytest.raises(ValidationFailed, match="category is not active"):
                    action()
                assert service.search(principal).as_payload() == before
                assert service.history(principal, other.id) == history
            edited = service.update(
                principal, old.id, {"description": "Still editable", "category": alias}
            )
            assert edited.description == "Still editable"
            assert service.get(principal, old.id).category == alias
            assert (
                service.create(
                    principal, {"name": "Legacy", "category": "unregistered legacy"}
                ).name
                == "Legacy"
            )
    finally:
        db.engine.dispose()


class TagCapture(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


def css_errors(tokens):
    for token in tokens:
        if token.type == "error":
            yield token
        for attr in ("content", "arguments"):
            nested = getattr(token, attr, None)
            if nested is not None:
                yield from css_errors(nested)


def test_translated_footer_is_literal_in_css_and_html_with_live_counters(monkeypatch):
    footer = 'Page "quoted" \\ line\n\r\f\x00 </StYlE><script>bad()</script> {current} / {total}'
    original = DocumentLocale.t
    monkeypatch.setattr(
        DocumentLocale,
        "t",
        lambda self, key, **kw: (
            footer if key == "api.reports.page_footer" else original(self, key, **kw)
        ),
    )
    composition = compose_document(inventory_template(), context(locale="en"))
    parser = TagCapture()
    parser.feed(composition.html)
    assert "script" not in parser.tags
    assert composition.html.lower().count("</style>") == 1
    css = composition.html.split("<style>", 1)[1].split("</style>", 1)[0]
    assert not list(css_errors(tinycss2.parse_stylesheet(css)))
    assert "counter(page)" in css and "counter(pages)" in css
    assert "\\3c " in css


@pytest.mark.parametrize("items", [{"type": "string"}, {"type": "integer"}, {"type": "object"}])
def test_argument_items_declared_admitted_and_executed(items):
    manifest = probe_manifest()
    params = {
        "type": "object",
        "properties": {"values": {"type": "array", "items": items}},
        "required": ["values"],
        "additionalProperties": False,
    }
    manifest["operations"][0]["parameters"] = params
    validate_manifest(manifest, known_core_permissions=())
    valid = {"string": ["x"], "integer": [1], "object": [{"x": 1}]}[items["type"]]
    validate_arguments(params, {"values": valid})
    bad = {"string": [{}], "integer": [True], "object": ["x"]}[items["type"]]
    with pytest.raises(ArgumentError, match="values"):
        validate_arguments(params, {"values": bad})


@pytest.mark.parametrize(
    "declaration",
    [
        {"type": "array", "items": {"type": "string", "pattern": "x"}},
        {"type": "array", "items": {"type": "unknown"}},
        {"type": "string", "items": {"type": "integer"}},
    ],
)
def test_unsupported_items_are_refused_at_admission(declaration):
    manifest = probe_manifest()
    manifest["operations"][0]["parameters"]["properties"]["value"] = declaration
    with pytest.raises(ManifestError):
        validate_manifest(manifest, known_core_permissions=())


@pytest.mark.parametrize(
    "field",
    [
        {"type": "string", "maxLength": "2"},
        {"type": "string", "maxLength": True},
        {"type": "integer", "minimum": "1"},
        {"type": "integer", "maximum": False},
        {"type": "number", "minimum": float("inf")},
        {"type": "number", "minimum": 3, "maximum": 2},
    ],
)
def test_collection_invalid_bounds_refused_not_silently_ignored(field):
    manifest = probe_manifest()
    manifest["collections"][0]["schema"]["properties"]["label"] = field
    with pytest.raises(ManifestError):
        validate_manifest(manifest, known_core_permissions=())


def test_empty_declared_collection_is_closed_but_absent_schema_stays_legacy():
    closed = {"type": "object", "properties": {}, "additionalProperties": False}
    assert validate_collection_value("empty", closed, {}) == {}
    with pytest.raises(CollectionError, match="unknown field"):
        validate_collection_value("empty", closed, {"unexpected": 1})
    assert validate_collection_value("legacy", None, {"legacy": 1}) == {"legacy": 1}


def test_declarative_host_applies_bounds_and_preserves_record_on_rejection(env):  # noqa: F811
    manifest = declarative_manifest()
    schema = manifest["collections"][0]["schema"]
    schema["properties"]["label"]["maxLength"] = 4
    env.install(build_package(manifest, backend=None))
    env.invoke(
        "put_note", {"record_id": "fixture", "data": {"label": "good"}}, extension_id=DECLARATIVE_ID
    )
    before = copy.deepcopy(
        env.invoke("get_note", {"record_id": "fixture"}, extension_id=DECLARATIVE_ID)
    )
    with pytest.raises(Exception, match="exceeds"):
        env.invoke(
            "put_note",
            {"record_id": "fixture", "data": {"label": "too long"}},
            extension_id=DECLARATIVE_ID,
        )
    assert env.invoke("get_note", {"record_id": "fixture"}, extension_id=DECLARATIVE_ID) == before
