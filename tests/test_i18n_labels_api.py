"""Admin-editable labels (S4/D9): legacy strings, locale maps and fixed state labels.

Every check goes through the public HTTP surface: the stored catalog row and the
relationship type row must keep their ids and keys while the resolved ``label``
follows the request locale and the additive ``labels`` map stays intact.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.i18n import t
from itsm.main import create_app
from sqlalchemy import text
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, BACKEND_ROOT, run_cli, run_migrations
from tests.inventory_support import Catalog, asset_values, prepare, sign_in_as

API = "/api/v1"
MAINTENANCE_LABELS = {"es": "En mantenimiento", "en": "Under maintenance"}


@pytest.fixture
def catalog(settings_factory: Callable[..., Settings]) -> Catalog:
    return prepare(settings_factory)


@pytest.fixture
def api(catalog: Catalog) -> Iterator[tuple[TestClient, dict[str, str]]]:
    with TestClient(create_app(catalog.settings)) as client:
        yield client, sign_in_as(client, catalog.settings, ADMIN_USERNAME, ADMIN_PASSWORD)


def headers(auth: dict[str, str], language: str | None = None) -> dict[str, str]:
    return {**auth, "Accept-Language": language} if language else dict(auth)


def config(client: TestClient, auth: dict[str, str], language: str | None = None) -> dict[str, Any]:
    response = client.get(f"{API}/inventory/config", headers=headers(auth, language))
    assert response.status_code == 200, response.text
    return response.json()


def status_of(payload: dict[str, Any], key: str) -> dict[str, Any]:
    return next(item for item in payload["statuses"] if item["id"] == key)


def category_of(payload: dict[str, Any], key: str) -> dict[str, Any]:
    return next(item for item in payload["categories"] if item["id"] == key)


def types_of(client: TestClient, auth: dict[str, str], language: str | None = None) -> list[Any]:
    response = client.get(f"{API}/relationship-types", headers=headers(auth, language))
    assert response.status_code == 200, response.text
    return response.json()


def type_of(entries: list[Any], key: str) -> Any:
    return next(entry for entry in entries if entry["key"] == key)


def asset_body(**values: Any) -> dict[str, Any]:
    """The public asset DTO uses camelCase; the shared fixture uses snake_case."""
    payload = asset_values(**values)
    payload["quickCode"] = payload.pop("quick_code")
    return payload


def create_asset(client: TestClient, auth: dict[str, str], **values: Any) -> dict[str, Any]:
    response = client.post(f"{API}/assets", json=asset_body(**values), headers=headers(auth))
    assert response.status_code == 201, response.text
    return response.json()


def test_legacy_string_labels_stay_valid_and_report_an_empty_map(
    api: tuple[TestClient, dict[str, str]],
) -> None:
    client, auth = api

    saved = client.put(
        f"{API}/inventory/config/statuses/maintenance",
        json={
            "id": "maintenance",
            "label": "Mantenimiento",
            "tone": "warn",
            "final": False,
            "active": True,
        },
        headers=auth,
    )

    assert saved.status_code == 200, saved.text
    assert saved.json()["label"] == "Mantenimiento"
    assert saved.json()["labels"] == {}
    stored = status_of(config(client, auth), "maintenance")
    assert stored["label"] == "Mantenimiento"
    assert stored["labels"] == {}


def test_locale_map_round_trip_resolves_the_request_locale(
    api: tuple[TestClient, dict[str, str]],
) -> None:
    client, auth = api

    saved = client.put(
        f"{API}/inventory/config/statuses/maintenance",
        json={
            "id": "maintenance",
            "label": MAINTENANCE_LABELS,
            "tone": "warn",
            "final": False,
            "active": True,
        },
        headers=auth,
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["label"] == "En mantenimiento"
    assert saved.json()["labels"] == MAINTENANCE_LABELS

    spanish = status_of(config(client, auth, "es"), "maintenance")
    english = status_of(config(client, auth, "en"), "maintenance")
    assert spanish["id"] == english["id"] == "maintenance"
    assert spanish["label"] == "En mantenimiento"
    assert english["label"] == "Under maintenance"
    assert spanish["labels"] == english["labels"] == MAINTENANCE_LABELS

    # The public read payload is a valid write payload: the ids never move.
    echoed = client.put(
        f"{API}/inventory/config/statuses/maintenance",
        json={"tone": "warn", "final": False, "active": True, **english},
        headers=auth,
    )
    assert echoed.status_code == 200, echoed.text
    assert echoed.json()["labels"] == MAINTENANCE_LABELS


@pytest.mark.parametrize(
    "labels",
    [
        {"es": "En mantenimiento", "pt": "Em manutenção"},
        {"es": "En mantenimiento", "en": ""},
        {"en": "Under maintenance"},
        {"es": "   ", "en": "Under maintenance"},
    ],
    ids=["unknown-tag", "empty-text", "missing-source", "blank-source"],
)
def test_invalid_locale_maps_are_rejected_and_storage_is_unchanged(
    api: tuple[TestClient, dict[str, str]], labels: dict[str, str]
) -> None:
    client, auth = api
    before = config(client, auth, "es")

    rejected = client.put(
        f"{API}/inventory/config/statuses/maintenance",
        json={
            "id": "maintenance",
            "label": labels,
            "tone": "warn",
            "final": False,
            "active": True,
        },
        headers=auth,
    )

    assert rejected.status_code == 422, rejected.text
    assert config(client, auth, "es") == before


def test_categories_resolve_by_any_locale_label(
    api: tuple[TestClient, dict[str, str]],
) -> None:
    client, auth = api
    notebooks = category_of(config(client, auth), "notebooks")
    updated = client.put(
        f"{API}/inventory/config/categories/notebooks",
        json={
            **notebooks,
            "label": {"es": "Portátiles", "en": "Laptops"},
            "transitions": {"in_use": ["retired"]},
        },
        headers=auth,
    )
    assert updated.status_code == 200, updated.text

    assert category_of(config(client, auth), "notebooks")["label"] == "Portátiles"
    assert category_of(config(client, auth, "en"), "notebooks")["label"] == "Laptops"
    # The stored category text is never rewritten; both locale labels resolve to
    # the same catalog row, so its local transition rule applies to each of them.
    for index, label_text in enumerate(("Portátiles", "Laptops")):
        asset = create_asset(client, auth, quick_code=f"NB-LBL-{index}", category=label_text)
        assert asset["category"] == label_text
        rejected = client.patch(
            f"{API}/assets/{asset['id']}", json={"status": "in_storage"}, headers=auth
        )
        assert rejected.status_code == 422, (label_text, rejected.text)
        allowed = client.patch(
            f"{API}/assets/{asset['id']}", json={"status": "retired"}, headers=auth
        )
        assert allowed.status_code == 200, (label_text, allowed.text)


def test_user_preference_overrides_accept_language(
    api: tuple[TestClient, dict[str, str]],
) -> None:
    client, auth = api
    saved = client.put(
        f"{API}/inventory/config/statuses/maintenance",
        json={
            "id": "maintenance",
            "label": MAINTENANCE_LABELS,
            "tone": "warn",
            "final": False,
            "active": True,
        },
        headers=auth,
    )
    assert saved.status_code == 200, saved.text

    preferred = client.patch(f"{API}/auth/me/preferences", json={"locale": "en"}, headers=auth)
    assert preferred.status_code == 200, preferred.text

    status_item = status_of(config(client, auth, "es"), "maintenance")
    assert status_item["label"] == "Under maintenance"


def test_fresh_installation_ships_built_in_es_en_labels(
    api: tuple[TestClient, dict[str, str]],
) -> None:
    client, auth = api
    payload = config(client, auth, "es")
    for group in ("fields", "categories", "statuses"):
        for item in payload[group]:
            labels = item["labels"]
            assert set(labels) >= {"es", "en"}, (group, item)
            assert labels["es"] == item["label"], (group, item)
            assert all(str(value).strip() for value in labels.values()), (group, item)

    english = config(client, auth, "en")
    english_status = next(item for item in english["statuses"] if item["id"] == "maintenance")
    assert english_status["label"] == "Under maintenance"

    for entry in types_of(client, auth, "es"):
        assert set(entry["forwardLabels"]) >= {"es", "en"}, entry
        assert set(entry["inverseLabels"]) >= {"es", "en"}, entry
        assert entry["forwardLabels"]["es"] == entry["forwardLabel"]
    assert type_of(types_of(client, auth, "en"), "installed_in")["forwardLabel"] == "Installed in"


def test_relationship_types_accept_strings_and_locale_maps(
    api: tuple[TestClient, dict[str, str]],
) -> None:
    client, auth = api
    legacy = client.post(
        f"{API}/relationship-types",
        json={"key": "runs_on", "forwardLabel": "Se ejecuta en", "inverseLabel": "Ejecuta"},
        headers=auth,
    )
    assert legacy.status_code == 201, legacy.text
    assert legacy.json()["forwardLabels"] == {}
    assert legacy.json()["inverseLabels"] == {}

    mapped = client.post(
        f"{API}/relationship-types",
        json={
            "key": "mirrors",
            "forwardLabel": {"es": "Replica a", "en": "Mirrors"},
            "inverseLabel": {"es": "Replicado por", "en": "Mirrored by"},
        },
        headers=auth,
    )
    assert mapped.status_code == 201, mapped.text
    assert mapped.json()["key"] == "mirrors"
    assert mapped.json()["forwardLabel"] == "Replica a"

    spanish = type_of(types_of(client, auth, "es"), "mirrors")
    english = type_of(types_of(client, auth, "en"), "mirrors")
    assert spanish["forwardLabel"] == "Replica a"
    assert english["forwardLabel"] == "Mirrors"
    assert english["inverseLabel"] == "Mirrored by"
    assert english["forwardLabels"] == {"es": "Replica a", "en": "Mirrors"}

    patched = client.patch(
        f"{API}/relationship-types/mirrors",
        json={"forwardLabel": "Se replica en"},
        headers=auth,
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["forwardLabel"] == "Se replica en"
    assert patched.json()["forwardLabels"] == {}


def test_invalid_relationship_locale_maps_leave_the_type_unchanged(
    api: tuple[TestClient, dict[str, str]],
) -> None:
    client, auth = api
    before = type_of(types_of(client, auth, "es"), "connected_to")

    rejected = client.patch(
        f"{API}/relationship-types/connected_to",
        json={"forwardLabel": {"es": "Conectado a", "pt": "Ligado a"}},
        headers=auth,
    )

    assert rejected.status_code == 422, rejected.text
    assert type_of(types_of(client, auth, "es"), "connected_to") == before


def test_fixed_state_ids_gain_localized_labels_without_changing_ids(
    api: tuple[TestClient, dict[str, str]],
) -> None:
    client, auth = api
    asset = create_asset(client, auth, status="maintenance")
    assert asset["status"] == "maintenance"
    assert asset["statusLabel"] == "En mantenimiento"

    english = client.get(f"{API}/assets/{asset['id']}", headers=headers(auth, "en"))
    assert english.status_code == 200, english.text
    assert english.json()["status"] == "maintenance"
    assert english.json()["statusLabel"] == "Under maintenance"

    intervention = client.post(f"{API}/interventions", json={"assetId": asset["id"]}, headers=auth)
    assert intervention.status_code == 201, intervention.text
    assert intervention.json()["type"] == "corrective"
    assert intervention.json()["typeLabel"] == t("api.interventions.type.corrective", "es")
    assert intervention.json()["statusLabel"] == t("api.interventions.state.open", "es")

    incident = client.post(
        f"{API}/incidents",
        json={"primaryAssetId": asset["id"], "description": "No enciende"},
        headers=auth,
    )
    assert incident.status_code == 201, incident.text
    assert incident.json()["priorityLabel"] == t("api.interventions.priority.normal", "es")
    assert incident.json()["statusLabel"] == t("api.interventions.state.open", "es")

    plan = client.post(
        f"{API}/maintenance/plans",
        json={"assetId": asset["id"], "dueOn": "2026-05-01"},
        headers=auth,
    )
    assert plan.status_code == 201, plan.text
    assert plan.json()["status"] == "active"
    assert plan.json()["statusLabel"] == t("api.maintenance.status.active", "es")

    english_intervention = client.get(
        f"{API}/interventions/{intervention.json()['id']}", headers=headers(auth, "en")
    )
    assert english_intervention.status_code == 200, english_intervention.text
    assert english_intervention.json()["type"] == "corrective"
    assert english_intervention.json()["typeLabel"] == t("api.interventions.type.corrective", "en")
    assert english_intervention.json()["statusLabel"] == t("api.interventions.state.open", "en")

    english_incident = client.get(
        f"{API}/incidents/{incident.json()['id']}", headers=headers(auth, "en")
    )
    assert english_incident.status_code == 200, english_incident.text
    assert english_incident.json()["priorityLabel"] == t("api.interventions.priority.normal", "en")
    assert english_incident.json()["statusLabel"] == t("api.interventions.state.open", "en")

    english_plan = client.get(
        f"{API}/maintenance/plans/{plan.json()['id']}", headers=headers(auth, "en")
    )
    assert english_plan.status_code == 200, english_plan.text
    assert english_plan.json()["status"] == "active"
    assert english_plan.json()["statusLabel"] == t("api.maintenance.status.active", "en")


def test_fixed_state_catalog_keys_cover_both_core_locales() -> None:
    for state in ("in_use", "in_storage", "maintenance", "retired"):
        spanish = t(f"api.inventory.lifecycle.{state}", "es")
        english = t(f"api.inventory.lifecycle.{state}", "en")
        assert spanish != "Text unavailable."
        assert english != "Text unavailable."
        assert spanish != english
    assert t("api.inventory.lifecycle.maintenance", "es") == "En mantenimiento"
    assert t("api.inventory.lifecycle.maintenance", "en") == "Under maintenance"
    for state in ("open", "in_progress", "completed", "cancelled"):
        assert t(f"api.interventions.state.{state}", "es") != "Text unavailable."
        assert t(f"api.interventions.state.{state}", "en") != "Text unavailable."
    for state in ("pending", "upcoming", "overdue"):
        assert t(f"api.maintenance.state.{state}", "es") != "Text unavailable."
        assert t(f"api.maintenance.state.{state}", "en") != "Text unavailable."


def test_migration_maps_built_in_labels_and_keeps_edited_ones(
    settings_factory: Callable[..., Settings],
) -> None:
    """0041 backfills only untouched seeds, so an existing installation keeps its text."""
    settings = settings_factory()
    upgrade = run_cli(
        [
            "-m",
            "alembic",
            "-c",
            str(BACKEND_ROOT / "alembic.ini"),
            "upgrade",
            "0038_i18n_preferences",
        ],
        settings,
    )
    assert upgrade.returncode == 0, upgrade.stderr
    engine = create_engine_from_settings(settings)
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE relationship_types SET forward_label = 'Cableado a' "
                "WHERE key = 'connected_to'"
            )
        )
        connection.execute(
            text(
                "UPDATE inventory_catalog SET payload = :payload "
                "WHERE kind = 'statuses' AND key = 'maintenance'"
            ),
            {
                "payload": json.dumps(
                    {
                        "id": "maintenance",
                        "label": "En taller",
                        "tone": "warn",
                        "final": False,
                        "active": True,
                    }
                )
            },
        )
    engine.dispose()

    assert run_migrations(settings).returncode == 0
    engine = create_engine_from_settings(settings)
    try:
        with engine.connect() as connection:
            forward_label, forward_labels = connection.execute(
                text(
                    "SELECT forward_label, forward_labels FROM relationship_types "
                    "WHERE key = 'connected_to'"
                )
            ).one()
            payload = json.loads(
                connection.execute(
                    text(
                        "SELECT payload FROM inventory_catalog "
                        "WHERE kind = 'statuses' AND key = 'maintenance'"
                    )
                ).scalar_one()
            )
            seeded = connection.execute(
                text("SELECT forward_labels FROM relationship_types WHERE key = 'installed_in'")
            ).scalar_one()
    finally:
        engine.dispose()

    # Raw SQL returns the JSON columns as text; the API decodes them.
    assert forward_label == "Cableado a"
    assert json.loads(forward_labels) == {"es": "Cableado a", "en": "Connected to"}
    assert json.loads(seeded) == {"es": "Instalado en", "en": "Installed in"}
    assert payload["label"] == "En taller"
    assert payload["labels"] == {"es": "En taller", "en": "Under maintenance"}
