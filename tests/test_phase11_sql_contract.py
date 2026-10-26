"""Portable consumer contract; opt-in URLs MUST name disposable test databases."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from itsm.database import create_engine_from_settings
from itsm.main import create_app
from sqlalchemy import inspect
from tests.conftest import bootstrap_superadmin, run_migrations, sign_in
from tests.test_inventory_api import api_values


@pytest.mark.parametrize(
    "variable",
    [
        None,
        "ITSM_TEST_IDENTITY_POSTGRES_URL",
        "ITSM_TEST_IDENTITY_MARIADB_URL",
        "ITSM_TEST_MSSQL_URL",
    ],
    ids=["sqlite", "postgresql", "mariadb", "mssql"],
)
def test_portable_install_transactions_retries_and_reopen(variable, settings_factory, tmp_path):
    url = os.environ.get(variable, "") if variable else ""
    if variable and not url:
        pytest.skip(f"{variable} not configured: live engine not validated")
    overrides = {"database_url": url} if url else {}
    settings = settings_factory(attachment_storage_path=tmp_path / "blobs", **overrides)
    migrated = run_migrations(settings)
    assert migrated.returncode == 0, migrated.stderr
    bootstrap_superadmin(settings)
    suffix = uuid4().hex[:12]
    with TestClient(create_app(settings)) as client:
        auth = sign_in(client, settings)
        readiness = client.get("/api/v1/health/ready")
        assert readiness.status_code == 200, readiness.text
        assert readiness.json()["migrations"]["current"] == readiness.json()["migrations"]["head"]
        site = client.post(
            "/api/v1/locations", json={"level": "site", "name": f"P11 {suffix}"}, headers=auth
        )
        assert site.status_code == 201, site.text
        site_id = site.json()["id"]
        person = client.post("/api/v1/people", json={"name": f"P11 {suffix}"}, headers=auth)
        assert person.status_code == 201, person.text
        values = api_values(quick_code=f"P11-{suffix}", name=f"Portable {suffix}")
        values.update(
            siteId=site_id, site=site.json()["name"], responsiblePersonId=person.json()["id"]
        )
        values.pop("responsible")
        response = client.post("/api/v1/assets", json=values, headers=auth)
        assert response.status_code == 201, response.text
        asset = response.json()
        assert str(UUID(asset["id"])) == asset["id"]
        assert asset["responsiblePersonId"] == person.json()["id"]
        assert asset["siteId"] == site_id
        before = client.get("/api/v1/assets").json()["total"]
        rejected = client.post(
            "/api/v1/assets/batch",
            json={
                "create": [
                    api_values(quick_code=f"X-{suffix}-MANUAL"),
                    api_values(quick_code=f"x-{suffix}-manual"),
                ]
            },
            headers=auth,
        )
        assert rejected.status_code == 409, rejected.text
        assert client.get("/api/v1/assets").json()["total"] == before
        history = client.get(f"/api/v1/assets/{asset['id']}/history").json()
        denied = client.patch(f"/api/v1/assets/{asset['id']}", json={"name": "Forged"})
        assert denied.status_code == 403
        assert client.get(f"/api/v1/assets/{asset['id']}/history").json() == history
        changed = client.patch(
            f"/api/v1/assets/{asset['id']}", json={"quickCode": f"REN-{suffix}"}, headers=auth
        )
        assert changed.status_code == 200 and changed.json()["id"] == asset["id"]
        document = b"%PDF-1.7\nportable receipt\n%%EOF"
        uploaded = client.post(
            f"/api/v1/assets/{asset['id']}/attachments",
            params={"filename": "receipt.pdf", "category": "receipt"},
            content=document,
            headers={**auth, "Content-Type": "application/pdf"},
        )
        assert uploaded.status_code == 201, uploaded.text
        download_url = uploaded.json()["downloadUrl"]
        parsed = client.post(
            "/api/v1/imports/analyze",
            params={"filename": "portable.csv"},
            content=f"id,name\n{asset['id']},Imported {suffix}\n".encode(),
            headers={**auth, "Content-Type": "application/octet-stream"},
        )
        assert parsed.status_code == 200, parsed.text
        operation = parsed.json()["id"]
        assert client.get(f"/api/v1/assets/{asset['id']}").json()["name"] == values["name"]
        assert (
            client.post(f"/api/v1/operations/{operation}/execute", headers=auth).status_code == 409
        )
        assert (
            client.post(f"/api/v1/operations/{operation}/approve", headers=auth).status_code == 200
        )
        executed = client.post(f"/api/v1/operations/{operation}/execute", headers=auth)
        assert executed.status_code == 200, executed.text
        assert executed.json()["summary"] == {
            "created": 0,
            "modified": 1,
            "omitted": 0,
            "failed": 0,
        }
        after_history = client.get(f"/api/v1/assets/{asset['id']}/history").json()
        retried = client.post(f"/api/v1/operations/{operation}/execute", headers=auth)
        assert retried.json()["summary"] == executed.json()["summary"]
        assert client.get(f"/api/v1/assets/{asset['id']}/history").json() == after_history
        cookie = dict(client.cookies)

        def create_same_manual_code(_):
            with TestClient(create_app(settings)) as concurrent:
                concurrent.cookies.update(cookie)
                return concurrent.post(
                    "/api/v1/assets",
                    json=api_values(quick_code=f"RACE-{suffix}-MANUAL"),
                    headers=auth,
                ).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = sorted(pool.map(create_same_manual_code, range(2)))
        assert outcomes == [201, 409]
        assert client.get("/api/v1/assets").json()["total"] == before + 1
        assert client.post("/api/v1/auth/logout", headers=auth).status_code == 200
        assert client.get(download_url).status_code == 401

    assert run_migrations(settings).returncode == 0
    with TestClient(create_app(settings)) as reopened:
        sign_in(reopened, settings)
        stored = reopened.get(f"/api/v1/assets/{asset['id']}")
        assert stored.status_code == 200
        assert stored.json()["name"] == f"Imported {suffix}"
        assert stored.json()["quickCode"] == f"REN-{suffix}"
        assert reopened.get(download_url).content == document
        assert reopened.get(f"/api/v1/assets/{asset['id']}/history").json() == after_history
    engine = create_engine_from_settings(settings)
    try:
        schema = inspect(engine)
        assert schema.get_pk_constraint("assets")["constrained_columns"] == ["id"]
        assert schema.get_indexes("assets") or schema.get_unique_constraints("assets")
    finally:
        engine.dispose()
