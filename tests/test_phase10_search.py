"""Phase 10 global search: SQL primary, Meilisearch adapter, durable sync."""

from __future__ import annotations

import json
import re
import socket
import threading
import unicodedata
from datetime import UTC, date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from itsm.directory.models import DirectoryLocation, DirectoryPerson
from itsm.identity.api import AuthenticationRequired, create_identity_router
from itsm.identity.service import IdentityService, PermissionDenied, ValidationFailed
from itsm.interventions.models import Incident
from itsm.inventory.models import Asset
from itsm.inventory.service import InventoryService
from itsm.maintenance.models import MaintenancePlan
from itsm.search.api import create_search_router
from itsm.search.indexer import execute_rebuild, execute_sync, install_search_sync
from itsm.search.models import SearchBase, SearchIndexState, SearchSyncOutbox
from itsm.search.service import SearchService
from sqlalchemy import select
from tests.conftest import sign_in
from tests.inventory_support import asset_values, prepare


# ------------------------------------------------------------------ stub engine
def _fold(value: str) -> str:
    return "".join(
        char
        for char in unicodedata.normalize("NFKD", value.lower())
        if not unicodedata.combining(char)
    )


class StubEngine:
    """Small Meilisearch 1.x surface: indexes, documents, tasks, atomic swap."""

    def __init__(self) -> None:
        self.indexes: dict[str, dict[str, dict[str, Any]]] = {}
        self.tasks: dict[int, str] = {}
        self.counter = 0
        self.fail_documents = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def docs(self, uid: str = "itsm_entities") -> dict[str, dict[str, Any]]:
        return self.indexes.get(uid, {})

    def _task(self) -> dict[str, Any]:
        self.counter += 1
        self.tasks[self.counter] = "succeeded"
        return {"taskUid": self.counter, "status": "enqueued"}

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        engine = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:
                return

            def _send(self, code: int, payload: Any) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self) -> Any:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                return json.loads(raw or b"{}")

            def do_GET(self) -> None:
                path = urlparse(self.path).path
                if path == "/health":
                    self._send(200, {"status": "available"})
                    return
                if path.startswith("/tasks/"):
                    uid = int(path.rsplit("/", 1)[1])
                    self._send(200, {"uid": uid, "status": engine.tasks.get(uid, "succeeded")})
                    return
                if path.startswith("/indexes/"):
                    uid = path.split("/")[2]
                    if uid in engine.indexes:
                        self._send(200, {"uid": uid})
                    else:
                        self._send(404, {"code": "index_not_found"})
                    return
                self._send(404, {"code": "not_found", "message": path})

            def do_POST(self) -> None:
                path = urlparse(self.path).path
                if path == "/indexes":
                    uid = str(self._body().get("uid"))
                    if uid in engine.indexes:
                        self._send(409, {"code": "index_already_exists"})
                        return
                    engine.indexes[uid] = {}
                    self._send(202, engine._task())
                    return
                if path.endswith("/search") and path.startswith("/indexes/"):
                    uid = path.split("/")[2]
                    body = self._body()
                    query = _fold(str(body.get("q") or ""))
                    types = re.findall(r'"([^"]+)"', str(body.get("filter") or ""))
                    hits = []
                    for doc in engine.docs(uid).values():
                        if types and doc.get("type") not in types:
                            continue
                        haystack = _fold(
                            " ".join(
                                [
                                    str(doc.get("label") or ""),
                                    str(doc.get("subtitle") or ""),
                                    " ".join(str(value) for value in doc.get("keywords") or []),
                                ]
                            )
                        )
                        if query and query not in haystack:
                            continue
                        hits.append(doc)
                    self._send(
                        200,
                        {
                            "hits": hits,
                            "estimatedTotalHits": len(hits),
                            "limit": body.get("limit", 20),
                            "offset": body.get("offset", 0),
                        },
                    )
                    return
                if path.endswith("/documents/delete-batch") and path.startswith("/indexes/"):
                    uid = path.split("/")[2]
                    docs = engine.indexes.setdefault(uid, {})
                    for identifier in self._body():
                        for key, document in list(docs.items()):
                            if document.get("_engine_id", document["id"]) == identifier:
                                docs.pop(key)
                    self._send(202, engine._task())
                    return
                if path.endswith("/documents") and path.startswith("/indexes/"):
                    if engine.fail_documents:
                        self._send(500, {"message": "indexing failed"})
                        return
                    uid = path.split("/")[2]
                    docs = engine.indexes.setdefault(uid, {})
                    incoming = self._body()
                    if any(
                        not re.fullmatch(
                            r"[A-Za-z0-9_-]{1,511}", str(doc.get("_engine_id", doc["id"]))
                        )
                        for doc in incoming
                    ):
                        self._send(400, {"message": "invalid document primary key"})
                        return
                    for doc in incoming:
                        docs[str(doc["id"])] = doc
                    self._send(202, engine._task())
                    return
                if path == "/swap-indexes":
                    for pair in self._body():
                        first, second = pair["indexes"]
                        left = engine.indexes.setdefault(first, {})
                        right = engine.indexes.setdefault(second, {})
                        engine.indexes[first], engine.indexes[second] = right, left
                    self._send(202, engine._task())
                    return
                self._send(404, {"code": "not_found", "message": path})

            def do_PUT(self) -> None:
                self._body()
                path = urlparse(self.path).path
                if path.endswith("/settings/filterable-attributes"):
                    self._send(202, engine._task())
                    return
                self._send(404, {"code": "not_found", "message": path})

            def do_DELETE(self) -> None:
                path = urlparse(self.path).path
                if path.startswith("/indexes/"):
                    engine.indexes.pop(path.split("/")[2], None)
                    self._send(202, engine._task())
                    return
                self._send(404, {"code": "not_found", "message": path})

        return Handler


# --------------------------------------------------------------------- fixtures
def _catalog(settings_factory: Any, engine_url: str | None = None) -> Any:
    overrides = {"meilisearch_url": engine_url} if engine_url else {}
    catalog = prepare(settings_factory, **overrides)
    SearchBase.metadata.create_all(catalog.engine)
    install_search_sync(catalog.settings)
    return catalog


def _asset(catalog: Any, **overrides: Any) -> str:
    with catalog.session() as session:
        identity = IdentityService(session, catalog.settings)
        inventory = InventoryService(session, catalog.settings, identity=identity)
        view = inventory.create(catalog.admin(), asset_values(**overrides))
        return str(view.id)


def _extra_entities(catalog: Any, asset_id: str) -> dict[str, str]:
    now = datetime.now(UTC)
    with catalog.session() as session:
        person = DirectoryPerson(
            id=str(uuid4()),
            name="Camila Torres",
            job_title="Analista NOC",
            status="active",
            created_at=now,
            updated_at=now,
        )
        site = DirectoryLocation(
            id=str(uuid4()),
            level="site",
            name="Sede Central",
            name_key="sede-central",
            active=True,
            created_at=now,
            updated_at=now,
        )
        session.add_all([person, site])
        session.flush()
        incident = Incident(
            id=str(uuid4()),
            description="Servidor caído en sala técnica",
            priority="alta",
            status="open",
            primary_asset_id=asset_id,
            opened_on=date.today(),
            created_at=now,
            updated_at=now,
        )
        plan = MaintenancePlan(
            id=str(uuid4()),
            asset_id=asset_id,
            maintenance_type="Preventivo UPS",
            interval_months=6,
            tasks=[],
            status="active",
            scheduled_on=date.today(),
            due_on=date.today() + timedelta(days=30),
            created_at=now,
            updated_at=now,
        )
        session.add_all([incident, plan])
        session.commit()
        return {
            "person": person.id,
            "site": site.id,
            "incident": incident.id,
            "maintenance": plan.id,
        }


def _search(catalog: Any, principal: Any, query: str, **kwargs: Any) -> dict[str, Any]:
    with catalog.session() as session:
        identity = IdentityService(session, catalog.settings)
        service = SearchService(session, identity, catalog.settings)
        return service.search(principal, query, **kwargs).as_payload()


def _keys(payload: dict[str, Any]) -> list[str]:
    return [item["key"] for item in payload["items"]]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# ------------------------------------------------------------------------ tests
def test_sql_groups_entities_with_stable_keys_and_targets(settings_factory: Any) -> None:
    catalog = _catalog(settings_factory)
    asset_id = _asset(catalog)
    extra = _extra_entities(catalog, asset_id)
    admin = catalog.admin()

    asset_page = _search(catalog, admin, "aruba")
    assert asset_page["engine"] == "sql"
    assert asset_page["fallback"] is False
    assert asset_page["limit"] == 20 and asset_page["offset"] == 0
    assert f"asset:{asset_id}" in _keys(asset_page)
    asset_item = next(item for item in asset_page["items"] if item["key"] == f"asset:{asset_id}")
    assert asset_item["type"] == "asset"
    assert asset_item["target"] == {"kind": "asset", "id": asset_id}
    assert asset_item["label"] and asset_item["subtitle"] is not None

    person_page = _search(catalog, admin, "camila")
    person_item = next(
        item for item in person_page["items"] if item["key"] == f"person:{extra['person']}"
    )
    assert person_item["target"]["kind"] == "person"

    location_page = _search(catalog, admin, "sede central")
    location_item = next(
        item
        for item in location_page["items"]
        if item["key"] in {f"site:{extra['site']}", f"location:{extra['site']}"}
    )
    assert location_item["type"] in {"site", "location"}
    assert location_item["target"]["kind"] in {"site", "location"}

    incident_page = _search(catalog, admin, "servidor caído")
    incident_item = next(
        item for item in incident_page["items"] if item["key"] == f"incident:{extra['incident']}"
    )
    assert incident_item["target"] == {"kind": "incident", "id": extra["incident"]}

    plan_page = _search(catalog, admin, "preventivo ups")
    plan_item = next(
        item for item in plan_page["items"] if item["key"] == f"maintenance:{extra['maintenance']}"
    )
    assert plan_item["target"] == {"kind": "maintenance", "id": extra["maintenance"]}

    section_page = _search(catalog, admin, "inventario")
    section = next(item for item in section_page["items"] if item["type"] == "section")
    assert section["target"]["kind"] == "section"
    assert section["target"]["route"]["name"] == "inventory"

    exact = _search(catalog, admin, "SW-SN-001")
    assert exact["items"][0]["key"] == f"asset:{asset_id}"

    scoped = _search(catalog, admin, "aruba", kinds=["person"])
    assert all(item["type"] == "person" for item in scoped["items"])
    with pytest.raises(ValidationFailed):
        _search(catalog, admin, "aruba", kinds=["nonsense"])


def test_effective_permission_change_hides_results(settings_factory: Any) -> None:
    catalog = _catalog(settings_factory)
    asset_id = _asset(catalog)
    extra = _extra_entities(catalog, asset_id)
    reader = catalog.add_user("reader-user", "Reader User", "user")

    assert f"person:{extra['person']}" in _keys(_search(catalog, reader, "camila"))
    assert f"asset:{asset_id}" in _keys(_search(catalog, reader, "aruba"))

    catalog.deactivate("reader-user")

    hidden_people = _search(catalog, reader, "camila")
    assert hidden_people["items"] == []
    assert hidden_people["total"] == 0
    hidden_assets = _search(catalog, reader, "aruba")
    assert hidden_assets["items"] == []
    assert hidden_assets["total"] == 0


def test_engine_hits_rehydrate_and_drop_stale_archived_and_deleted(
    settings_factory: Any,
) -> None:
    stub = StubEngine()
    try:
        catalog = _catalog(settings_factory, stub.url)
        asset_id = _asset(catalog)
        other_id = _asset(
            catalog,
            quick_code="SW-SN-002",
            name="Switch Aruba Respaldo",
            serial="AR2930F002",
            ip="192.168.50.12",
        )
        with catalog.session() as session:
            result = execute_sync(session, catalog.settings)
        assert result["configured"] is True
        assert result["synced"] >= 2
        assert f"asset:{asset_id}" in stub.docs()
        assert f"asset:{other_id}" in stub.docs()

        admin = catalog.admin()
        page = _search(catalog, admin, "aruba")
        assert page["engine"] == "meilisearch"
        assert page["fallback"] is False
        assert f"asset:{asset_id}" in _keys(page)

        # Stale index entry: not rehydratable from SQL, must be dropped.
        stub.indexes["itsm_entities"]["asset:missing"] = {
            "id": "asset:missing",
            "type": "asset",
            "entity_id": "missing",
            "label": "Aruba fantasma",
            "subtitle": "",
        }
        stale_page = _search(catalog, admin, "fantasma")
        assert stale_page["items"] == []

        # Archived entity: SQL excludes it and the sync deletes the document.
        with catalog.session() as session:
            identity = IdentityService(session, catalog.settings)
            InventoryService(session, catalog.settings, identity=identity).archive(
                admin, asset_id, reason="baja"
            )
            execute_sync(session, catalog.settings)
        assert f"asset:{asset_id}" not in stub.docs()
        assert f"asset:{asset_id}" not in _keys(_search(catalog, admin, "aruba"))

        # Deleted entity: a committed ORM delete queues a removal.
        with catalog.session() as session:
            session.delete(session.get(Asset, other_id))
            session.commit()
            execute_sync(session, catalog.settings)
        assert f"asset:{other_id}" not in stub.docs()
    finally:
        stub.stop()


def test_engine_outage_falls_back_to_sql(settings_factory: Any) -> None:
    catalog = _catalog(settings_factory, f"http://127.0.0.1:{_free_port()}")
    asset_id = _asset(catalog)
    admin = catalog.admin()

    page = _search(catalog, admin, "aruba")
    assert page["engine"] == "sql"
    assert page["fallback"] is True
    assert f"asset:{asset_id}" in _keys(page)

    with catalog.session() as session:
        status = SearchService(
            session, IdentityService(session, catalog.settings), catalog.settings
        ).status()
    assert status["configured"] is True
    assert status["available"] is False
    assert status["engine"] == "meilisearch"


def test_sync_configuration_is_scoped_to_each_database(
    settings_factory: Any, tmp_path: Any
) -> None:
    indexed = _catalog(settings_factory, "http://127.0.0.1:18770")
    sql_only = _catalog(
        lambda **overrides: settings_factory(
            database_url=f"sqlite:///{tmp_path / 'sql-only.db'}", **overrides
        )
    )
    indexed_id = _asset(indexed)
    _asset(sql_only)
    with indexed.session() as session:
        rows = session.scalars(select(SearchSyncOutbox)).all()
        assert any(row.entity_id == indexed_id for row in rows)
    with sql_only.session() as session:
        assert session.scalars(select(SearchSyncOutbox)).all() == []


def test_sync_retries_transient_engine_failure(settings_factory: Any) -> None:
    stub = StubEngine()
    try:
        catalog = _catalog(settings_factory, stub.url)
        asset_id = _asset(catalog)
        stub.fail_documents = True

        now = datetime.now(UTC)
        with catalog.session() as session:
            first = execute_sync(session, catalog.settings, as_of=now)
            row = session.scalars(select(SearchSyncOutbox)).one()
            assert row.status == "failed"
            assert row.attempts == 1
        assert first["failed"] == 1
        assert first["pending"] == 1
        assert f"asset:{asset_id}" not in stub.docs()

        stub.fail_documents = False
        with catalog.session() as session:
            retried = execute_sync(session, catalog.settings, as_of=now + timedelta(hours=1))
        assert retried["synced"] == 1
        assert retried["failed"] == 0
        assert retried["pending"] == 0
        assert f"asset:{asset_id}" in stub.docs()
    finally:
        stub.stop()


def test_full_rebuild_is_atomic_and_preserves_index_on_failure(
    settings_factory: Any,
) -> None:
    stub = StubEngine()
    try:
        catalog = _catalog(settings_factory, stub.url)
        asset_id = _asset(catalog)
        stub.indexes.setdefault("itsm_entities", {})["asset:stale"] = {
            "id": "asset:stale",
            "type": "asset",
            "entity_id": "stale",
            "label": "Viejo",
            "subtitle": "",
        }

        with catalog.session() as session:
            result = execute_rebuild(session, catalog.settings)
            state = session.get(SearchIndexState, 1)
        assert result["status"] == "idle"
        assert result["rebuilt"] >= 1
        assert f"asset:{asset_id}" in stub.docs()
        assert "asset:stale" not in stub.docs()
        assert state is not None and state.status == "idle"
        assert state.last_rebuild_at is not None
        assert state.document_count == result["rebuilt"]

        stub.fail_documents = True
        with catalog.session() as session:
            failed = execute_rebuild(session, catalog.settings)
            state = session.get(SearchIndexState, 1)
        assert failed["status"] == "failed"
        assert f"asset:{asset_id}" in stub.docs()
        assert state is not None and state.status == "failed"
        assert state.last_error
    finally:
        stub.stop()


def test_search_router_returns_contract_and_guards_actions(
    settings_factory: Any,
) -> None:
    catalog = _catalog(settings_factory)
    asset_id = _asset(catalog)
    settings = catalog.settings
    app = FastAPI()

    @app.exception_handler(PermissionDenied)
    def denied(_request: Any, exc: PermissionDenied) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(AuthenticationRequired)
    def unauthenticated(_request: Any, exc: AuthenticationRequired) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    app.state.settings = settings
    app.state.session_factory = catalog.factory()
    app.include_router(create_identity_router(), prefix=settings.api_prefix)
    app.include_router(create_search_router(), prefix=settings.api_prefix)

    with TestClient(app) as client:
        headers = sign_in(client, settings)
        response = client.get(
            f"{settings.api_prefix}/search", params={"q": "aruba"}, headers=headers
        )
        assert response.status_code == 200
        payload = response.json()
        assert set(payload) == {"items", "total", "limit", "offset", "engine", "fallback"}
        assert f"asset:{asset_id}" in [item["key"] for item in payload["items"]]
        assert payload["engine"] == "sql"

        scoped = client.get(
            f"{settings.api_prefix}/search",
            params=[("q", "aruba"), ("kind", "person")],
            headers=headers,
        )
        assert scoped.status_code == 200
        assert all(item["type"] == "person" for item in scoped.json()["items"])

        status = client.get(f"{settings.api_prefix}/search/status", headers=headers)
        assert status.status_code == 200
        assert status.json()["configured"] is False

        rebuild = client.post(f"{settings.api_prefix}/search/rebuild", headers=headers)
        assert rebuild.status_code == 202
        assert rebuild.json()["state"] == "completed"

        sync = client.post(f"{settings.api_prefix}/search/sync", headers=headers)
        assert sync.status_code == 202

        denied = client.post(f"{settings.api_prefix}/search/rebuild")
        assert denied.status_code == 403

        catalog.add_user("status-reader", "Status Reader", "user")
        with TestClient(app) as reader:
            login = reader.post(
                f"{settings.api_prefix}/auth/login",
                json={"username": "status-reader", "password": "machine-identity-password-2026"},
                headers={"Origin": settings.auth_origin},
            )
            assert login.status_code == 200
            restricted = reader.get(f"{settings.api_prefix}/search/status")
            assert restricted.status_code == 403
            assert not {"index", "lastError", "documentCount", "pending"} & restricted.json().keys()

    anonymous = TestClient(app)
    assert anonymous.get(f"{settings.api_prefix}/search", params={"q": "aruba"}).status_code == 401
