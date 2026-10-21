"""The real runtime, never editable metadata, owns lifecycle policy hints."""

from __future__ import annotations

import pytest


@pytest.mark.parametrize("environment", ["development", "test", "production"])
def test_operations_policy_matches_runtime_and_cannot_be_reconfigured(
    settings_factory, signed_in_client, environment
):
    settings = settings_factory(environment=environment)
    client, auth = signed_in_client(settings)
    before = client.get("/api/v1/inventory/config").json()
    production = environment == "production"
    assert before["operations"] == {
        "environment": environment,
        "purge": {
            "confirmationRequired": True,
            "humanOnly": True,
            "permission": "assets.purge" if production else "assets.edit",
            "archivedRequired": production,
            "typedIdRequired": production,
            "reasonRequired": production,
        },
    }
    rejected = client.put(
        "/api/v1/inventory/config/rules/identification",
        json={"environment": "development"},
        headers=auth,
    )
    assert rejected.status_code == 422
    assert client.get("/api/v1/inventory/config").json() == before
