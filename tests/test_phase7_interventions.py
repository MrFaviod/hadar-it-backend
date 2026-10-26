"""Technical intervention and incident behavior through real HTTP and SQL.

The focused fixture builds isolated metadata and canonical identity/catalog state.
The full migration chain and composition root are exercised separately by the
integrated API, worker and SQL-engine checks.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.directory.models import DirectoryBase
from itsm.identity.clock import utcnow
from itsm.identity.models import IdentityBase, IdentityRole, IdentityRolePolicy
from itsm.identity.permissions import (
    BUILT_IN_ROLE_IDS,
    BUILT_IN_ROLE_NAMES,
    BUILT_IN_ROLE_PERMISSIONS,
)
from itsm.identity.service import IdentityService
from itsm.inventory.catalog_defaults import installation_catalog
from itsm.inventory.catalog_models import InventoryCatalogEntry
from itsm.inventory.models import InventoryBase
from itsm.maintenance.service import add_months
from sqlalchemy import Engine, text
from starlette.routing import Mount
from tests.conftest import ADMIN_NAME, ADMIN_PASSWORD, ADMIN_USERNAME, sign_in
from tests.inventory_support import sign_in_as
from tests.test_attachments import upload
from tests.test_inventory_api import create_asset

SettingsFactory = Callable[..., Settings]
PDF = b"%PDF-1.7\nintervention sheet\n%%EOF"
READER_PASSWORD = "reader-password-2026"


def _schema(settings: Settings) -> None:
    """Create every focused table without the sibling 0013 migration."""

    import itsm.attachments.models
    import itsm.interventions.models
    import itsm.inventory.catalog_models
    import itsm.maintenance.models
    import itsm.redundancy.models
    import itsm.relationships.models
    import itsm.workflows.models  # noqa: F401

    engine = create_engine_from_settings(settings)
    for base in (IdentityBase, DirectoryBase, InventoryBase):
        base.metadata.create_all(engine)
    with create_session_factory(engine)() as session:
        for role_id in BUILT_IN_ROLE_IDS:
            session.add(
                IdentityRole(
                    id=role_id,
                    name=BUILT_IN_ROLE_NAMES[role_id],
                    built_in=True,
                    created_at=utcnow(),
                )
            )
            for code in BUILT_IN_ROLE_PERMISSIONS[role_id]:
                resource, _, operation = code.partition(".")
                session.add(
                    IdentityRolePolicy(role_id=role_id, resource=resource, operation=operation)
                )
        catalog = installation_catalog()
        for kind, entries in catalog.items():
            for entry in entries:
                session.add(
                    InventoryCatalogEntry(
                        kind=kind,
                        key=entry.get("id") or entry["key"],
                        payload=dict(entry),
                    )
                )
        session.execute(
            text("INSERT INTO inventory_code_sequences (key, next_value) VALUES ('__lock__', 0)")
        )
        session.commit()
    engine.dispose()


def _bootstrap(settings: Settings) -> None:
    engine = create_engine_from_settings(settings)
    session = create_session_factory(engine)()
    try:
        IdentityService(session, settings).bootstrap_superadmin(
            ADMIN_USERNAME, ADMIN_NAME, ADMIN_PASSWORD
        )
    finally:
        session.close()
        engine.dispose()


def _app(settings: Settings) -> Any:
    from itsm.interventions.api import create_intervention_router
    from itsm.main import create_app

    app = create_app(settings)
    prefix = settings.api_prefix
    if any(getattr(route, "path", None) == f"{prefix}/incidents" for route in app.routes):
        return app
    mount = next(route for route in app.routes if isinstance(route, Mount) and route.path == prefix)
    app.router.routes.remove(mount)
    app.include_router(create_intervention_router(), prefix=prefix)
    app.router.routes.append(mount)
    return app


@dataclass
class Api:
    client: TestClient
    auth: dict[str, str]
    settings: Settings
    engine: Engine


@pytest.fixture
def api(settings_factory: SettingsFactory, tmp_path: Any) -> Iterator[Api]:
    settings = settings_factory(attachment_storage_path=tmp_path / "blobs")
    _schema(settings)
    _bootstrap(settings)
    engine = create_engine_from_settings(settings)
    with TestClient(_app(settings)) as client:
        yield Api(
            client=client,
            auth=sign_in(client, settings),
            settings=settings,
            engine=engine,
        )
    engine.dispose()


def asset(test_client: TestClient, auth: dict[str, str], quick_code: str, **overrides: Any):
    return create_asset(test_client, auth, quick_code=quick_code, **overrides)


def person(test_client: TestClient, auth: dict[str, str], name: str, **overrides: Any):
    response = test_client.post("/api/v1/people", json={"name": name, **overrides}, headers=auth)
    assert response.status_code == 201, response.text
    return response.json()


def make_site(test_client: TestClient, auth: dict[str, str], name: str) -> str:
    response = test_client.post(
        "/api/v1/locations", json={"level": "site", "name": name}, headers=auth
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def add_intervention(test_client: TestClient, auth: dict[str, str], **values: Any):
    return test_client.post("/api/v1/interventions", json=values, headers=auth)


def add_incident(test_client: TestClient, auth: dict[str, str], **values: Any):
    return test_client.post("/api/v1/incidents", json=values, headers=auth)


def technical_history(test_client: TestClient, asset_id: str) -> dict[str, Any]:
    response = test_client.get(f"/api/v1/assets/{asset_id}/technical-history")
    assert response.status_code == 200, response.text
    return response.json()


def asset_history(test_client: TestClient, asset_id: str) -> dict[str, Any]:
    response = test_client.get(f"/api/v1/assets/{asset_id}/history")
    assert response.status_code == 200, response.text
    return response.json()


def create_plan(test_client: TestClient, auth: dict[str, str], asset_id: str, **values: Any):
    response = test_client.post(
        "/api/v1/maintenance/plans",
        json={"assetId": asset_id, "intervalMonths": 1, **values},
        headers=auth,
    )
    assert response.status_code == 201, response.text
    return response.json()


def read_plan(test_client: TestClient, plan_id: str) -> dict[str, Any]:
    response = test_client.get(f"/api/v1/maintenance/plans/{plan_id}")
    assert response.status_code == 200, response.text
    return response.json()


def plan_state(plan: dict[str, Any]) -> dict[str, Any]:
    """Compare domain values; SQLite reloads drop the response timestamp offset."""
    return {key: value for key, value in plan.items() if key not in {"createdAt", "updatedAt"}}


def test_intervention_persists_rich_and_minimal_records_with_asset_history(api: Api):
    technician = person(api.client, api.auth, "Técnico Uno")
    rich = asset(api.client, api.auth, "INT-RICH", category="Red", site="Example Site")
    attachment = upload(api.client, api.auth, rich["id"], PDF).json()

    response = add_intervention(
        api.client,
        api.auth,
        assetId=rich["id"],
        type="corrective",
        description="Replace fan",
        technicianPersonId=technician["id"],
        occurredOn="2026-10-20",
        notes="Noise on start",
        parts=[{"name": "Fan", "quantity": 2, "unitCost": "12.50"}],
        laborCost="100.50",
        attachmentIds=[attachment["id"]],
    )
    assert response.status_code == 201, response.text
    created = response.json()
    assert str(uuid.UUID(created["id"])) == created["id"]
    assert created["assetId"] == rich["id"]
    assert created["assetQuickCode"] == "INT-RICH"
    assert created["technicianPersonId"] == technician["id"]
    assert created["technicianName"] == technician["name"]
    assert created["occurredOn"] == "2026-10-20"
    assert created["status"] == "open"
    assert created["parts"] == [
        {"name": "Fan", "quantity": 2, "unitCost": "12.50", "lineCost": "25.00"}
    ]
    assert created["laborCost"] == "100.50"
    assert created["partsCost"] == "25.00"
    assert created["totalCost"] == "125.50"
    assert created["attachments"] == [
        {"id": attachment["id"], "filename": "receipt.pdf", "category": "receipt"}
    ]
    assert api.client.get(f"/api/v1/interventions/{created['id']}").json() == created

    history = technical_history(api.client, rich["id"])
    event = next(item for item in history["items"] if item["action"] == "intervention_logged")
    assert event["entityType"] == "intervention"
    assert event["entityId"] == created["id"]
    assert event["source"] == "rest"
    assert event["actorUsername"] == ADMIN_USERNAME
    assert history["total"] == 1

    minimal_asset = asset(api.client, api.auth, "INT-MIN")
    minimal = add_intervention(api.client, api.auth, assetId=minimal_asset["id"], type="preventive")
    assert minimal.status_code == 201, minimal.text
    payload = minimal.json()
    assert payload["description"] is None
    assert payload["parts"] == []
    assert payload["attachments"] == []
    assert payload["occurredOn"] == utcnow().date().isoformat()
    assert payload["laborCost"] is None
    assert payload["totalCost"] is None
    page = api.client.get(f"/api/v1/interventions?assetId={minimal_asset['id']}").json()
    assert page["total"] == 1
    assert page["items"][0]["id"] == payload["id"]


def test_invalid_references_money_and_inputs_change_nothing(api: Api):
    primary = asset(api.client, api.auth, "INT-BAD")
    other = asset(api.client, api.auth, "INT-OTHER")
    foreign = upload(api.client, api.auth, other["id"], PDF).json()
    inactive = person(api.client, api.auth, "Técnico Retirado", status="inactive")
    before = technical_history(api.client, primary["id"])

    invalid: list[dict[str, Any]] = [
        {"assetId": primary["id"], "attachmentIds": [foreign["id"]]},
        {"assetId": primary["id"], "technicianPersonId": str(uuid.uuid4())},
        {"assetId": primary["id"], "technicianPersonId": inactive["id"]},
        {"assetId": primary["id"], "attachmentIds": ["../../etc/passwd"]},
        {"assetId": primary["id"], "attachmentIds": [foreign["id"], foreign["id"]]},
        {"assetId": primary["id"], "laborCost": "10.555"},
        {"assetId": primary["id"], "laborCost": "-1.00"},
        {"assetId": primary["id"], "parts": [{"name": "Fan", "quantity": 1, "unitCost": "1.234"}]},
        {"assetId": primary["id"], "parts": [{"name": "Fan", "quantity": 0}]},
        {"assetId": primary["id"], "occurredOn": "2026-02-30"},
        {"assetId": primary["id"], "type": "recovery"},
        {"assetId": primary["id"], "planId": "../plans/1"},
        {"assetId": primary["id"], "incidentId": str(uuid.uuid4())},
        {"assetId": primary["id"], "unknown": True},
    ]
    for values in invalid:
        response = add_intervention(api.client, api.auth, **values)
        assert response.status_code == 422, (values, response.text)
        assert response.json()["error"]["code"] == "validation_error"
        assert api.client.get(f"/api/v1/interventions?assetId={primary['id']}").json()["total"] == 0
        assert technical_history(api.client, primary["id"]) == before

    missing_plan = add_intervention(
        api.client, api.auth, assetId=primary["id"], planId=str(uuid.uuid4())
    )
    assert missing_plan.status_code == 404, missing_plan.text
    assert missing_plan.json()["error"]["code"] == "not_found"
    assert api.client.get(f"/api/v1/interventions?assetId={primary['id']}").json()["total"] == 0
    assert technical_history(api.client, primary["id"]) == before

    missing = add_intervention(api.client, api.auth, assetId=str(uuid.uuid4()), type="corrective")
    assert missing.status_code == 404
    assert api.client.get(f"/api/v1/interventions?assetId={primary['id']}").json()["total"] == 0


def test_incident_minimal_creation_multi_asset_links_and_interventions(api: Api):
    responsible = person(api.client, api.auth, "Responsable Uno")
    primary = asset(
        api.client,
        api.auth,
        "INC-PRIMARY",
        responsiblePersonId=responsible["id"],
        responsible=responsible["name"],
        category="Red",
        site="Example Site",
    )
    first = asset(api.client, api.auth, "INC-O1", category="Red", site="Example Site")
    second = asset(api.client, api.auth, "INC-O2", category="Blue", site="Matriz")

    response = add_incident(
        api.client,
        api.auth,
        primaryAssetId=primary["id"],
        description="Uplink down",
    )
    assert response.status_code == 201, response.text
    incident = response.json()
    assert incident["status"] == "open"
    assert incident["priority"] == "normal"
    assert incident["responsiblePersonId"] == responsible["id"]
    assert incident["affectedAssetIds"] == []
    assert incident["revision"] == 1
    assert incident["openedOn"] == utcnow().date().isoformat()

    assert (
        add_incident(
            api.client,
            api.auth,
            primaryAssetId=primary["id"],
            description="Duplicate ids",
            affectedAssetIds=[first["id"], first["id"]],
        ).status_code
        == 422
    )
    assert (
        add_incident(
            api.client,
            api.auth,
            primaryAssetId=primary["id"],
            description="Primary repeated",
            affectedAssetIds=[primary["id"]],
        ).status_code
        == 422
    )
    assert (
        add_incident(
            api.client,
            api.auth,
            primaryAssetId=primary["id"],
            description="Unknown asset",
            affectedAssetIds=[str(uuid.uuid4())],
        ).status_code
        == 404
    )
    assert api.client.get("/api/v1/incidents").json()["total"] == 1

    linked = api.client.patch(
        f"/api/v1/incidents/{incident['id']}/affected-assets",
        json={"affectedAssetIds": [first["id"], second["id"]]},
        headers=api.auth,
    )
    assert linked.status_code == 200, linked.text
    linked_payload = linked.json()
    assert linked_payload["affectedAssetIds"] == [first["id"], second["id"]]
    assert linked_payload["revision"] == 2
    for body, status in (
        ({"affectedAssetIds": [first["id"], first["id"]]}, 422),
        ({"affectedAssetIds": [primary["id"]]}, 422),
        ({"affectedAssetIds": [str(uuid.uuid4())]}, 404),
    ):
        rejected = api.client.patch(
            f"/api/v1/incidents/{incident['id']}/affected-assets",
            json=body,
            headers=api.auth,
        )
        assert rejected.status_code == status, rejected.text
        current = api.client.get(f"/api/v1/incidents/{incident['id']}").json()
        assert current["affectedAssetIds"] == [first["id"], second["id"]]
        assert current["revision"] == 2

    replaced = api.client.patch(
        f"/api/v1/incidents/{incident['id']}/affected-assets",
        json={"affectedAssetIds": [second["id"]]},
        headers=api.auth,
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["affectedAssetIds"] == [second["id"]]
    assert replaced.json()["revision"] == 3
    first_history = technical_history(api.client, first["id"])
    removal = [
        item for item in first_history["items"] if item["action"] == "incident_assets_updated"
    ][-1]
    assert removal["entityType"] == "incident"
    assert removal["changes"]["affectedAssets"]["old"] == [first["id"], second["id"]]
    assert removal["changes"]["affectedAssets"]["new"] == [second["id"]]

    base = f"/api/v1/incidents/{incident['id']}"
    before_invalid = api.client.get(base).json()
    unknown = api.client.patch(
        f"{base}/affected-assets",
        json={"affectedAssetIds": [str(uuid.uuid4())]},
        headers=api.auth,
    )
    assert unknown.status_code == 404
    duplicate = api.client.patch(
        f"{base}/affected-assets",
        json={"affectedAssetIds": [second["id"], second["id"]]},
        headers=api.auth,
    )
    assert duplicate.status_code == 422
    primary_again = api.client.patch(
        f"{base}/affected-assets",
        json={"affectedAssetIds": [primary["id"]]},
        headers=api.auth,
    )
    assert primary_again.status_code == 422
    after_invalid = api.client.get(base).json()
    assert after_invalid["affectedAssetIds"] == [second["id"]]
    assert after_invalid["revision"] == before_invalid["revision"]
    assert after_invalid["events"] == before_invalid["events"]

    one = add_intervention(
        api.client, api.auth, assetId=primary["id"], type="corrective", incidentId=incident["id"]
    )
    two = add_intervention(
        api.client, api.auth, assetId=second["id"], type="corrective", incidentId=incident["id"]
    )
    assert one.status_code == 201, one.text
    assert two.status_code == 201, two.text
    detail = api.client.get(f"/api/v1/incidents/{incident['id']}").json()
    assert detail["interventionsTotal"] == 2
    assert {item["id"] for item in detail["interventions"]} == {
        one.json()["id"],
        two.json()["id"],
    }
    assert detail["affectedAssets"] == [
        {
            "id": second["id"],
            "name": second["name"],
            "quickCode": "INC-O2",
        }
    ]
    assert detail["costs"] == {"totalCost": None, "countedInterventions": 0}
    actions = [event["action"] for event in detail["events"]]
    assert actions == [
        "created",
        "affected_assets_updated",
        "affected_assets_updated",
        "intervention_linked",
        "intervention_linked",
    ]
    assert detail["revision"] == 5
    assert technical_history(api.client, primary["id"])["items"][0]["action"] == "incident_opened"
    second_history = technical_history(api.client, second["id"])["items"]
    assert any(
        item["action"] == "incident_assets_updated" and item["entityType"] == "incident"
        for item in second_history
    )


def test_incident_transitions_are_explicit_and_ordered(api: Api):
    primary = asset(api.client, api.auth, "INC-FLOW")
    incident = add_incident(
        api.client, api.auth, primaryAssetId=primary["id"], description="Printer offline"
    ).json()
    base = f"/api/v1/incidents/{incident['id']}"

    assert api.client.post(f"{base}/resolve", headers=api.auth).status_code == 409
    assert api.client.post(f"{base}/close", headers=api.auth).status_code == 409
    assert api.client.get(base).json()["status"] == "open"

    acknowledged = api.client.post(
        f"{base}/acknowledge", json={"note": "En sitio"}, headers=api.auth
    )
    assert acknowledged.status_code == 200, acknowledged.text
    assert acknowledged.json()["status"] == "in_progress"
    assert api.client.post(f"{base}/acknowledge", headers=api.auth).status_code == 409
    assert api.client.post(f"{base}/close", headers=api.auth).status_code == 409

    resolved = api.client.post(f"{base}/resolve", json={"note": "Fusor"}, headers=api.auth)
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "resolved"
    assert resolved.json()["resolvedAt"] is not None
    assert api.client.post(f"{base}/resolve", headers=api.auth).status_code == 409

    closed = api.client.post(f"{base}/close", headers=api.auth)
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "closed"
    assert closed.json()["closedAt"] is not None
    assert api.client.post(f"{base}/close", headers=api.auth).status_code == 409
    assert api.client.post(f"{base}/acknowledge", headers=api.auth).status_code == 409

    detail = api.client.get(base).json()
    assert [(event["action"], event["toStatus"]) for event in detail["events"]] == [
        ("created", "open"),
        ("acknowledged", "in_progress"),
        ("resolved", "resolved"),
        ("closed", "closed"),
    ]
    assert detail["events"][1]["note"] == "En sitio"
    history = technical_history(api.client, primary["id"])
    assert [item["action"] for item in history["items"]] == [
        "incident_opened",
        "incident_acknowledged",
        "incident_resolved",
        "incident_closed",
    ]
    assert {item["entityType"] for item in history["items"]} == {"incident"}
    assert history["items"][2]["changes"] == {"status": {"old": "in_progress", "new": "resolved"}}


def test_prepare_does_not_resolve_and_confirmation_requires_fresh_authority_and_token(api: Api):
    primary = asset(api.client, api.auth, "INC-RES")
    incident = add_incident(
        api.client, api.auth, primaryAssetId=primary["id"], description="Intermittent link"
    ).json()
    base = f"/api/v1/incidents/{incident['id']}"

    assert api.client.post(f"{base}/acknowledge", headers=api.auth).status_code == 200
    prepared = api.client.post(
        f"{base}/resolution/prepare", json={"note": "Signal recovered"}, headers=api.auth
    )
    assert prepared.status_code == 200, prepared.text
    suggestion = prepared.json()
    assert suggestion["incidentId"] == incident["id"]
    assert len(suggestion["token"]) >= 24
    assert api.client.get(base).json()["status"] == "in_progress"
    assert api.client.get(base).json()["resolution"] == {
        "prepared": True,
        "preparedAt": suggestion["preparedAt"],
        "preparedBy": ADMIN_USERNAME,
    }
    assert "token" not in api.client.get(base).json()

    wrong = api.client.post(
        f"{base}/resolution/confirm", json={"token": "not-the-token"}, headers=api.auth
    )
    assert wrong.status_code == 409
    assert api.client.get(base).json()["status"] == "in_progress"

    reprepared = api.client.post(f"{base}/resolution/prepare", headers=api.auth)
    assert reprepared.status_code == 200, reprepared.text
    assert reprepared.json()["token"] != suggestion["token"]
    stale = api.client.post(
        f"{base}/resolution/confirm", json={"token": suggestion["token"]}, headers=api.auth
    )
    assert stale.status_code == 409

    confirmed = api.client.post(
        f"{base}/resolution/confirm",
        json={"token": reprepared.json()["token"], "note": "Confirmed by operator"},
        headers=api.auth,
    )
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["status"] == "resolved"
    assert confirmed.json()["resolution"]["prepared"] is False
    assert (
        api.client.post(
            f"{base}/resolution/confirm",
            json={"token": reprepared.json()["token"]},
            headers=api.auth,
        ).status_code
        == 409
    )
    assert [event["action"] for event in confirmed.json()["events"]] == [
        "created",
        "acknowledged",
        "resolution_prepared",
        "resolution_prepared",
        "resolution_confirmed",
    ]

    stale_incident = add_incident(
        api.client,
        api.auth,
        primaryAssetId=primary["id"],
        description="Stale resolution",
    ).json()
    stale_base = f"/api/v1/incidents/{stale_incident['id']}"
    assert api.client.post(f"{stale_base}/acknowledge", headers=api.auth).status_code == 200
    token = api.client.post(f"{stale_base}/resolution/prepare", headers=api.auth).json()["token"]
    other = asset(api.client, api.auth, "INC-STALE-OTHER")
    assert (
        api.client.patch(
            f"{stale_base}/affected-assets",
            json={"affectedAssetIds": [other["id"]]},
            headers=api.auth,
        ).status_code
        == 200
    )
    stale_confirmation = api.client.post(
        f"{stale_base}/resolution/confirm", json={"token": token}, headers=api.auth
    )
    assert stale_confirmation.status_code == 409
    assert api.client.get(stale_base).json()["status"] == "in_progress"


def test_intervention_update_progresses_state_and_unlinks_reference_only(api: Api):
    target = asset(api.client, api.auth, "INT-UPD")
    first = upload(api.client, api.auth, target["id"], PDF).json()
    second = upload(
        api.client,
        api.auth,
        target["id"],
        PDF,
        filename="manual.pdf",
        category="manual",
    ).json()
    created = add_intervention(
        api.client,
        api.auth,
        assetId=target["id"],
        type="corrective",
        attachmentIds=[first["id"], second["id"]],
    ).json()
    base = f"/api/v1/interventions/{created['id']}"

    updated = api.client.patch(
        base,
        json={"status": "in_progress", "notes": "On site", "attachmentIds": [second["id"]]},
        headers=api.auth,
    )
    assert updated.status_code == 200, updated.text
    payload = updated.json()
    assert payload["status"] == "in_progress"
    assert payload["notes"] == "On site"
    assert [item["id"] for item in payload["attachments"]] == [second["id"]]
    assert (
        api.client.get(
            f"/api/v1/assets/{target['id']}/attachments/{first['id']}/download"
        ).status_code
        == 200
    )
    history = technical_history(api.client, target["id"])["items"]
    changes = next(item for item in history if item["action"] == "intervention_updated")["changes"]
    assert changes["status"] == {"old": "open", "new": "in_progress"}
    assert changes["attachments"]["old"] == [first["id"], second["id"]]
    assert changes["attachments"]["new"] == [second["id"]]

    completed = api.client.patch(base, json={"status": "completed"}, headers=api.auth)
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "completed"
    assert "intervention_completed" in [
        item["action"] for item in technical_history(api.client, target["id"])["items"]
    ]
    terminal = api.client.patch(base, json={"status": "open"}, headers=api.auth)
    assert terminal.status_code == 409
    assert api.client.get(base).json()["status"] == "completed"
    assert (
        api.client.patch(
            base, json={"attachmentIds": [str(uuid.uuid4())]}, headers=api.auth
        ).status_code
        == 422
    )
    assert api.client.get(base).json()["status"] == "completed"


def test_queries_filters_pagination_active_incidents_and_optional_costs(api: Api):
    first_person = person(api.client, api.auth, "Técnico Uno")
    second_person = person(api.client, api.auth, "Técnico Dos")
    red = asset(api.client, api.auth, "Q-RED", category="Red", site="Example Site")
    blue = asset(api.client, api.auth, "Q-BLUE", category="Blue", site="Matriz")
    responsible = person(api.client, api.auth, "Responsable Dos")

    first = add_intervention(
        api.client,
        api.auth,
        assetId=red["id"],
        type="corrective",
        occurredOn="2026-01-10",
        technicianPersonId=first_person["id"],
        laborCost="10.00",
        parts=[{"name": "Cable", "quantity": 1, "unitCost": "2.50"}],
    ).json()
    add_intervention(
        api.client,
        api.auth,
        assetId=red["id"],
        type="inspection",
        occurredOn="2026-02-10",
        technicianPersonId=second_person["id"],
        status="completed",
    )
    third = add_intervention(
        api.client,
        api.auth,
        assetId=blue["id"],
        type="corrective",
        occurredOn="2026-03-10",
        technicianPersonId=first_person["id"],
        laborCost="5.00",
    ).json()

    assert api.client.get("/api/v1/interventions?category=Red").json()["total"] == 2
    assert api.client.get("/api/v1/interventions?site=Matriz").json()["total"] == 1
    assert api.client.get("/api/v1/interventions?status=open").json()["total"] == 2
    assert api.client.get(f"/api/v1/interventions?assetId={red['id']}").json()["total"] == 2
    assert (
        api.client.get(f"/api/v1/interventions?technicianPersonId={first_person['id']}").json()[
            "total"
        ]
        == 2
    )
    assert (
        api.client.get("/api/v1/interventions?from=2026-02-01&to=2026-03-31").json()["total"] == 2
    )
    page = api.client.get(f"/api/v1/interventions?assetId={red['id']}&limit=1&offset=1").json()
    assert page["total"] == 2
    assert page["limit"] == 1 and page["offset"] == 1
    assert len(page["items"]) == 1
    assert page["items"][0]["id"] == first["id"]

    costs = api.client.get(f"/api/v1/interventions/costs?assetId={red['id']}").json()
    assert costs == {"totalCost": "12.50", "countedInterventions": 1}
    assert api.client.get("/api/v1/interventions/costs?from=2026-03-01").json() == {
        "totalCost": "5.00",
        "countedInterventions": 1,
    }
    empty_asset = asset(api.client, api.auth, "Q-NONE")
    assert api.client.get(f"/api/v1/interventions/costs?assetId={empty_asset['id']}").json() == {
        "totalCost": None,
        "countedInterventions": 0,
    }

    active_incident = add_incident(
        api.client,
        api.auth,
        primaryAssetId=red["id"],
        description="Active one",
        priority="high",
        responsiblePersonId=responsible["id"],
    ).json()
    closed_incident = add_incident(
        api.client, api.auth, primaryAssetId=blue["id"], description="Closed one"
    ).json()
    for action in ("acknowledge", "resolve", "close"):
        assert (
            api.client.post(
                f"/api/v1/incidents/{closed_incident['id']}/{action}", headers=api.auth
            ).status_code
            == 200
        )
    assert api.client.get("/api/v1/incidents?active=true").json()["total"] == 1
    assert api.client.get("/api/v1/incidents?status=closed").json()["total"] == 1
    assert api.client.get("/api/v1/incidents?priority=high").json()["total"] == 1
    assert (
        api.client.get(f"/api/v1/incidents?responsiblePersonId={responsible['id']}").json()["total"]
        == 1
    )
    assert api.client.get("/api/v1/incidents?site=Matriz").json()["total"] == 1
    assert api.client.get("/api/v1/incidents?category=Red").json()["total"] == 1
    assert api.client.get(f"/api/v1/incidents?assetId={red['id']}").json()["total"] == 1
    incident_page = api.client.get("/api/v1/incidents?limit=1&offset=1").json()
    assert incident_page["total"] == 2
    assert len(incident_page["items"]) == 1
    detail = api.client.get(f"/api/v1/incidents/{active_incident['id']}").json()
    assert detail["primaryAssetQuickCode"] == "Q-RED"
    assert detail["id"] == active_incident["id"]
    assert third["id"] not in {item["id"] for item in detail["interventions"]}


def test_current_authorization_denies_writes_and_confirmation_without_mutation(api: Api):
    target = asset(api.client, api.auth, "AUTH-ASSET")
    incident = add_incident(
        api.client, api.auth, primaryAssetId=target["id"], description="Auth flow"
    ).json()
    token = api.client.post(
        f"/api/v1/incidents/{incident['id']}/resolution/prepare", headers=api.auth
    ).json()["token"]
    before = technical_history(api.client, target["id"])
    session = create_session_factory(api.engine)()
    try:
        service = IdentityService(session, api.settings)
        admin = service.resolve_actor(service._identity_by_username(ADMIN_USERNAME).id)
        service.create_user(
            admin,
            username="reader.one",
            name="Reader One",
            password=READER_PASSWORD,
            role_id="user",
        )
        service.bootstrap_machine("reader.machine", "Reader Machine", "external_client", "user")
        machine_token = service.issue_machine_credential("reader.machine").token
    finally:
        session.close()

    assert api.client.post("/api/v1/auth/logout", headers=api.auth).status_code == 200
    reader = sign_in_as(api.client, api.settings, "reader.one", READER_PASSWORD)
    assert api.client.get("/api/v1/interventions").status_code == 200
    denied = add_intervention(
        api.client, reader, assetId=target["id"], type="corrective", description="Nope"
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "forbidden"
    machine_denied = api.client.post(
        "/api/v1/interventions",
        json={"assetId": target["id"], "type": "corrective"},
        headers={"Authorization": f"Bearer {machine_token}"},
    )
    assert machine_denied.status_code == 403
    confirmation = api.client.post(
        f"/api/v1/incidents/{incident['id']}/resolution/confirm",
        json={"token": token},
        headers={"Authorization": f"Bearer {machine_token}"},
    )
    assert confirmation.status_code == 403
    assert api.client.get(f"/api/v1/interventions?assetId={target['id']}").json()["total"] == 0
    assert technical_history(api.client, target["id"]) == before
    assert api.client.get(f"/api/v1/incidents/{incident['id']}").status_code == 200
    assert api.client.get(f"/api/v1/incidents/{incident['id']}").json()["status"] == "open"


def test_preventive_completion_updates_plan_once_and_corrective_does_not(api: Api):
    target = asset(api.client, api.auth, "INT-PLAN")
    plan = create_plan(api.client, api.auth, target["id"])
    assert plan["lastCompletedOn"] is None
    assert plan["persisted"] is True
    today = utcnow().date()

    created = add_intervention(
        api.client,
        api.auth,
        assetId=target["id"],
        type="preventive",
        planId=plan["id"],
        status="open",
        occurredOn=today.isoformat(),
    )
    assert created.status_code == 201, created.text
    intervention = created.json()
    assert intervention["planId"] == plan["id"]
    assert plan_state(read_plan(api.client, plan["id"])) == plan_state(plan)

    completed = api.client.patch(
        f"/api/v1/interventions/{intervention['id']}",
        json={"status": "completed"},
        headers=api.auth,
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "completed"

    after = read_plan(api.client, plan["id"])
    assert after["lastCompletedOn"] == today.isoformat()
    assert after["dueOn"] == add_months(today, 1).isoformat()
    history = asset_history(api.client, target["id"])
    completions = [item for item in history["items"] if item["action"] == "maintenance_completed"]
    assert len(completions) == 1

    again = api.client.patch(
        f"/api/v1/interventions/{intervention['id']}",
        json={"status": "completed"},
        headers=api.auth,
    )
    assert again.status_code == 200, again.text
    assert read_plan(api.client, plan["id"]) == after
    history = asset_history(api.client, target["id"])
    assert len([i for i in history["items"] if i["action"] == "maintenance_completed"]) == 1

    corrective = add_intervention(
        api.client,
        api.auth,
        assetId=target["id"],
        type="corrective",
        planId=plan["id"],
        status="completed",
        occurredOn=today.isoformat(),
    )
    assert corrective.status_code == 201, corrective.text
    assert corrective.json()["status"] == "completed"
    assert read_plan(api.client, plan["id"]) == after
    history = asset_history(api.client, target["id"])
    assert len([i for i in history["items"] if i["action"] == "maintenance_completed"]) == 1


def test_plan_conflicts_roll_back_and_cross_asset_links_are_rejected(api: Api):
    target = asset(api.client, api.auth, "INT-PLAN-FAIL")
    other = asset(api.client, api.auth, "INT-PLAN-OTHER")
    today = utcnow().date().isoformat()
    stale = create_plan(api.client, api.auth, target["id"], lastCompletedOn=today)
    assert stale["lastCompletedOn"] == today
    before = asset_history(api.client, target["id"])

    direct = add_intervention(
        api.client,
        api.auth,
        assetId=target["id"],
        type="preventive",
        planId=stale["id"],
        status="completed",
        occurredOn=today,
    )
    assert direct.status_code == 409, direct.text
    assert direct.json()["error"]["code"] == "conflict"
    assert api.client.get(f"/api/v1/interventions?assetId={target['id']}").json()["total"] == 0
    assert plan_state(read_plan(api.client, stale["id"])) == plan_state(stale)
    assert asset_history(api.client, target["id"]) == before

    opened = add_intervention(
        api.client,
        api.auth,
        assetId=target["id"],
        type="preventive",
        planId=stale["id"],
        status="open",
        occurredOn=today,
    )
    assert opened.status_code == 201, opened.text
    opened_id = opened.json()["id"]
    opened_history = asset_history(api.client, target["id"])

    conflict = api.client.patch(
        f"/api/v1/interventions/{opened_id}",
        json={"status": "completed"},
        headers=api.auth,
    )
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["error"]["code"] == "conflict"
    assert api.client.get(f"/api/v1/interventions/{opened_id}").json()["status"] == "open"
    assert plan_state(read_plan(api.client, stale["id"])) == plan_state(stale)
    assert asset_history(api.client, target["id"]) == opened_history
    assert not [
        item for item in opened_history["items"] if item["action"] == "maintenance_completed"
    ]

    foreign = create_plan(api.client, api.auth, other["id"])
    cross = add_intervention(
        api.client,
        api.auth,
        assetId=target["id"],
        type="preventive",
        planId=foreign["id"],
    )
    assert cross.status_code == 422, cross.text
    assert cross.json()["error"]["code"] == "validation_error"
    assert plan_state(read_plan(api.client, foreign["id"])) == plan_state(foreign)
    assert api.client.get(f"/api/v1/interventions?assetId={target['id']}").json()["total"] == 1
    assert asset_history(api.client, target["id"]) == opened_history


def test_query_filters_apply_to_interventions_costs_and_incidents(api: Api):
    site_a = make_site(api.client, api.auth, "Sede Norte")
    site_b = make_site(api.client, api.auth, "Sede Sur")
    technician = person(api.client, api.auth, "Técnico Filtro")
    first = asset(
        api.client, api.auth, "INT-Q-A1", siteId=site_a, site="Sede Norte", category="Red"
    )
    second = asset(
        api.client, api.auth, "INT-Q-A2", siteId=site_a, site="Sede Norte", category="Energía"
    )
    third = asset(api.client, api.auth, "INT-Q-B1", siteId=site_b, site="Sede Sur", category="Red")
    assert (first["siteId"], first["site"]) == (site_a, "Sede Norte")
    plan = create_plan(api.client, api.auth, first["id"])
    incident_a = add_incident(
        api.client, api.auth, primaryAssetId=first["id"], description="Falla sede norte"
    )
    assert incident_a.status_code == 201, incident_a.text
    incident_b = add_incident(
        api.client, api.auth, primaryAssetId=third["id"], description="Falla sede sur"
    )
    assert incident_b.status_code == 201, incident_b.text

    a1 = add_intervention(
        api.client,
        api.auth,
        assetId=first["id"],
        type="corrective",
        occurredOn="2026-01-10",
        status="open",
        laborCost="10.00",
        parts=[{"name": "Cable", "quantity": 1, "unitCost": "2.50"}],
        technicianPersonId=technician["id"],
        incidentId=incident_a.json()["id"],
        planId=plan["id"],
    )
    assert a1.status_code == 201, a1.text
    a2 = add_intervention(
        api.client,
        api.auth,
        assetId=second["id"],
        type="preventive",
        occurredOn="2026-02-10",
        status="completed",
        laborCost="20.00",
    )
    assert a2.status_code == 201, a2.text
    b1 = add_intervention(
        api.client,
        api.auth,
        assetId=third["id"],
        type="corrective",
        occurredOn="2026-03-10",
        status="open",
        laborCost="5.00",
    )
    assert b1.status_code == 201, b1.text

    def interventions(**params: Any) -> dict[str, Any]:
        response = api.client.get("/api/v1/interventions", params=params)
        assert response.status_code == 200, response.text
        return response.json()

    def costs(**params: Any) -> dict[str, Any]:
        response = api.client.get("/api/v1/interventions/costs", params=params)
        assert response.status_code == 200, response.text
        return response.json()

    def incidents(**params: Any) -> dict[str, Any]:
        response = api.client.get("/api/v1/incidents", params=params)
        assert response.status_code == 200, response.text
        return response.json()

    assert interventions()["total"] == 3
    assert interventions(siteId=site_a)["total"] == 2
    assert interventions(site="Sede Norte")["total"] == 2
    assert interventions(siteId=site_a, type="corrective")["total"] == 1
    assert interventions(planId=plan["id"])["total"] == 1
    assert interventions(incidentId=incident_a.json()["id"])["total"] == 1
    assert interventions(technicianPersonId=technician["id"])["total"] == 1
    assert interventions(siteId=site_a, category="Red")["total"] == 1
    assert interventions(siteId=site_a, status="completed")["total"] == 1
    assert interventions(siteId=site_a, **{"from": "2026-02-01", "to": "2026-02-28"})["total"] == 1
    assert interventions(siteId=site_b, **{"from": "2026-03-01", "to": "2026-03-31"})["total"] == 1
    assert interventions(siteId=str(uuid.uuid4()))["total"] == 0

    page = interventions(siteId=site_a, limit=1, offset=0)
    following = interventions(siteId=site_a, limit=1, offset=1)
    assert (page["total"], page["limit"], page["offset"], len(page["items"])) == (2, 1, 0, 1)
    assert (
        following["total"],
        following["limit"],
        following["offset"],
        len(following["items"]),
    ) == (2, 1, 1, 1)
    assert {page["items"][0]["id"], following["items"][0]["id"]} == {
        a1.json()["id"],
        a2.json()["id"],
    }

    assert costs() == {"totalCost": "37.50", "countedInterventions": 3}
    assert costs(category="__no_such_category__") == {
        "totalCost": None,
        "countedInterventions": 0,
    }
    assert costs(siteId=site_a) == {"totalCost": "32.50", "countedInterventions": 2}
    assert costs(site="Sede Norte") == {"totalCost": "32.50", "countedInterventions": 2}
    assert costs(siteId=site_a, category="Red") == {
        "totalCost": "12.50",
        "countedInterventions": 1,
    }
    assert costs(siteId=site_b) == {"totalCost": "5.00", "countedInterventions": 1}
    assert costs(type="corrective") == {"totalCost": "17.50", "countedInterventions": 2}
    assert costs(type="preventive") == {"totalCost": "20.00", "countedInterventions": 1}
    assert costs(status="open") == {"totalCost": "17.50", "countedInterventions": 2}
    assert costs(technicianPersonId=technician["id"]) == {
        "totalCost": "12.50",
        "countedInterventions": 1,
    }
    assert costs(incidentId=incident_a.json()["id"]) == {
        "totalCost": "12.50",
        "countedInterventions": 1,
    }
    assert costs(**{"from": "2026-01-01", "to": "2026-01-31"}) == {
        "totalCost": "12.50",
        "countedInterventions": 1,
    }
    assert costs(siteId=site_a, **{"from": "2026-02-01", "to": "2026-02-28"}) == {
        "totalCost": "20.00",
        "countedInterventions": 1,
    }

    assert incidents(siteId=site_a)["total"] == 1
    assert incidents(siteId=site_a)["items"][0]["id"] == incident_a.json()["id"]
    assert incidents(siteId=site_b)["total"] == 1
    assert incidents(siteId=site_b)["items"][0]["id"] == incident_b.json()["id"]
    assert incidents(site="Sede Norte")["total"] == 1
    assert incidents(siteId=str(uuid.uuid4()))["total"] == 0

    for path in ("/api/v1/interventions", "/api/v1/interventions/costs", "/api/v1/incidents"):
        rejected = api.client.get(path, params={"siteId": "not-a-uuid"})
        assert rejected.status_code == 422, (path, rejected.text)
        assert rejected.json()["error"]["code"] == "validation_error"
    for path in ("/api/v1/interventions", "/api/v1/interventions/costs"):
        rejected = api.client.get(path, params={"from": "2026-03-01", "to": "2026-01-01"})
        assert rejected.status_code == 422, (path, rejected.text)
