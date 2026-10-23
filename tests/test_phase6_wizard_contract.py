"""The incumbent wizard sends optional per-sheet maps even when empty."""

from sqlalchemy import text
from tests.test_phase6_workflows import analyze


def test_wizard_accepts_empty_optional_sheet_defaults(signed_in_client):
    client, auth = signed_in_client()
    result = analyze(
        client,
        auth,
        b"name,category,serial\nWizard,switch,WIZ-1\n",
        options={
            "selectedSheets": ["CSV"],
            "sheetMappings": {"CSV": {"name": "name", "category": "category", "serial": "serial"}},
            "sheetSites": {},
            "sheetCategories": {},
            "matchFields": ["serial", "ip"],
        },
    )
    assert result.status_code == 200, result.text
    assert result.json()["rows"][0]["classification"] == "new"
    assert result.json()["rows"][0]["values"]["serial"] == "WIZ-1"


def test_wizard_empty_target_ignores_that_column(signed_in_client):
    client, auth = signed_in_client()
    result = analyze(
        client,
        auth,
        b"name,serial,notes\nWizard,WIZ-2,unused\n",
        options={"sheetMappings": {"CSV": {"name": "name", "serial": "serial", "notes": ""}}},
    )
    assert result.status_code == 200, result.text
    assert result.json()["rows"][0]["values"] == {"name": "Wizard", "serial": "WIZ-2"}


def test_wizard_accepts_an_empty_per_sheet_mapping_entry(signed_in_client):
    client, auth = signed_in_client()
    result = analyze(
        client, auth, b"name,serial\nWizard,WIZ-3\n", options={"sheetMappings": {"CSV": {}}}
    )
    assert result.status_code == 200, result.text
    assert result.json()["rows"][0]["values"] == {"name": "Wizard", "serial": "WIZ-3"}


def test_analyze_rejects_non_object_options_without_touching_inventory(signed_in_client):
    client, auth = signed_in_client()
    before = client.get("/api/v1/assets").json()["total"]
    for options in (["nope"], "nope"):
        response = analyze(client, auth, b"name\nBroken\n", options=options)
        assert response.status_code == 422, options
    assert client.get("/api/v1/assets").json()["total"] == before


def test_analyze_rejects_malformed_per_sheet_targets(signed_in_client):
    client, auth = signed_in_client()
    before = client.get("/api/v1/assets").json()["total"]
    for options in (
        {"sheetMappings": {"CSV": {"name": 7}}},
        {"sheetMappings": {"CSV": {"name": "name", "": "name"}}},
        {"sheetSites": {"CSV": {"site": "  "}}},
        {"sheetCategories": {"CSV": ""}},
    ):
        response = analyze(client, auth, b"name\nBroken\n", options=options)
        assert response.status_code == 422, options
    assert client.get("/api/v1/assets").json()["total"] == before


def preference_events(client) -> int:
    """Count persisted preference audit events through the app's own session."""
    with client.app.state.session_factory() as session:
        statement = text(
            "SELECT COUNT(*) FROM identity_audit_events "
            "WHERE action = 'inventory.warranty_preferences'"
        )
        return int(session.execute(statement).scalar_one())


def test_warranty_preferences_reject_coerced_booleans_and_strings(signed_in_client):
    client, auth = signed_in_client()
    saved = client.put("/api/v1/warranty-preferences", json={"expiringDays": 45}, headers=auth)
    assert saved.status_code == 200, saved.text
    events = preference_events(client)

    for payload in ({"expiringDays": True}, {"expiringDays": "30"}, {"expiringDays": 30.0}):
        response = client.put("/api/v1/warranty-preferences", json=payload, headers=auth)
        assert response.status_code == 422, payload

    assert client.get("/api/v1/warranty-preferences", headers=auth).json() == {"expiringDays": 45}
    assert preference_events(client) == events
