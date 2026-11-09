"""Official product identity without overwriting installation-specific branding."""

# Fixtures are imported and requested by name by pytest.
# ruff: noqa: F811

from copy import deepcopy

from itsm.appearance.builtin import BUILTIN_ASSETS, BUILTIN_IDS, builtin_presets
from itsm.appearance.models import AppearanceState
from tests.test_phase10_appearance import (  # noqa: F401
    active,
    api,
    apply,
    catalog,
    create,
    preset_payload,
)


def test_official_builtin_identity_and_artwork():
    presets = builtin_presets("/api/v1")
    assert all(presets[key]["branding"]["appName"] == "Hadar IT" for key in BUILTIN_IDS)
    assert presets["generic"]["name"] == "Hadar IT"
    assert all(b"Hadar IT" in content for _, content in BUILTIN_ASSETS.values())


def test_legacy_builtin_snapshot_is_presented_as_hadar_without_rewriting_custom_brand(api, catalog):
    client, headers = api
    legacy = deepcopy(builtin_presets("/api/v1")["generic"])
    legacy["name"] = "Asset Manager"
    legacy["branding"]["appName"] = "Asset Manager"
    with catalog.session() as session:
        session.add(
            AppearanceState(id=1, active_id="generic", active=legacy, revision=0, updated_by="test")
        )
        session.commit()
    assert active(client)["active"]["branding"]["appName"] == "Hadar IT"
    with catalog.session() as session:
        state = session.get(AppearanceState, 1)
        changed = deepcopy(state.active)
        changed["branding"]["organizationName"] = "Organización propia"
        state.active = changed
        session.commit()
    identity = active(client)["active"]["branding"]
    assert identity["appName"] == "Asset Manager"
    assert identity["organizationName"] == "Organización propia"
    payload = preset_payload("Personalizado")
    payload["branding"]["appName"] = "Departamento propio"
    saved = create(client, headers, payload)
    apply(client, headers, saved["id"])
    assert active(client)["active"]["branding"]["appName"] == "Departamento propio"
