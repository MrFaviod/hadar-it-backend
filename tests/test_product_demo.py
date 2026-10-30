"""Public demo installation and outbound isolation, using disposable state only."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.identity.service import IdentityService
from itsm.inventory.service import InventoryService
from sqlalchemy.orm import Session

PASSWORD = "Demo-Test-Only-Password-42"


def initialize(path: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    env.update(ITSM_ENVIRONMENT="test", ITSM_BOOTSTRAP_PASSWORD=PASSWORD)
    env.update(overrides)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "itsm.demo",
            "init",
            "--directory",
            str(path),
            "--username",
            "demo.owner",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_demo_creates_coherent_canonical_installation(tmp_path: Path) -> None:
    directory = tmp_path / "demo"
    production = tmp_path / "production.db"
    production.write_bytes(b"production sentinel")
    result = initialize(directory, ITSM_DATABASE_URL=f"sqlite:///{production}")
    assert result.returncode == 0, result.stdout + result.stderr
    assert production.read_bytes() == b"production sentinel"
    payload = json.loads(result.stdout)
    assert payload["mode"] == "demo"
    assert payload["assets"] == 8
    assert result.stderr == ""
    assert PASSWORD not in result.stdout
    settings = Settings(_env_file=None, database_url=f"sqlite:///{directory / 'demo.db'}")
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            principal = IdentityService(session, settings).login("demo.owner", PASSWORD).principal
            assets = InventoryService(session, settings).search(principal)
            assert assets.total == 8
            assert {item.category for item in assets.items} >= {
                "servidores",
                "switches",
                "camaras",
                "virtualizacion",
            }
            assert all(item.site_id for item in assets.items)
            assert any(item.responsible_person_id for item in assets.items)
            assert any(not item.responsible_person_id for item in assets.items)
            from itsm.directory.service import DirectoryService
            from itsm.interventions.service import InterventionService
            from itsm.maintenance.service import MaintenanceService
            from itsm.relationships.service import RelationshipService
            from itsm.workflows.warranties import WarrantyService

            directory_service = DirectoryService(session, settings)
            assert directory_service.list_locations(principal, level="site").total == 2
            people = directory_service.list_people(principal)
            assert people.total == 2
            person_ids = {person.id for person in people.items}
            assert all(
                item.responsible_person_id in person_ids
                for item in assets.items
                if item.responsible_person_id
            )
            relations = RelationshipService(session, settings).list(principal)
            assert relations.total == 6
            assert sum(item.type_key == "hosted_in" for item in relations.items) == 2
            known_ids = {item.id for item in assets.items}
            assert all(
                item.source_id in known_ids and item.target_id in known_ids
                for item in relations.items
            )
            incidents = InterventionService(session, settings).list_incidents(
                principal, active=True
            )
            assert incidents.total == 2
            assert all(item.primary_asset_id in known_ids for item in incidents.items)
            plans = MaintenanceService(session, settings).list_plans(principal)
            assert plans.total >= 2
            assert all(item.asset_id in known_ids for item in plans.items)
            warranties = WarrantyService(session, settings).list(principal)
            assert len(warranties["items"]) == 3
            assert warranties["hasMore"] is False
            operator = IdentityService(session, settings).login("demo.operator", PASSWORD)
            assert operator.principal.username == "demo.operator"
            assert operator.principal.role_id == "operator"
    finally:
        engine.dispose()


def test_demo_directory_special_characters_cannot_redirect_database(tmp_path: Path) -> None:
    directory = tmp_path / "demo?query#fragment"
    sibling = tmp_path / "demo"
    sibling.mkdir()
    existing = sibling / "demo.db"
    existing.write_bytes(b"existing database must not change")
    result = initialize(directory, ITSM_DATABASE_ECHO="true")
    assert result.returncode == 1, result.stdout + result.stderr
    assert result.stdout == ""
    assert json.loads(result.stderr)["message"] == "demo directory contains URL delimiters"
    assert list(tmp_path.iterdir()) == [sibling]
    assert existing.read_bytes() == b"existing database must not change"
    assert PASSWORD not in result.stdout


def test_demo_refuses_existing_directory_without_changing_it(tmp_path: Path) -> None:
    directory = tmp_path / "real"
    directory.mkdir()
    existing = directory / "production.db"
    existing.write_bytes(b"existing installation must not change")
    result = initialize(directory)
    assert result.returncode == 1
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "status": "error",
        "code": "demo_refused",
        "message": "demo directory must not already exist",
    }
    assert list(directory.iterdir()) == [existing]
    assert existing.read_bytes() == b"existing installation must not change"


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"ITSM_ENVIRONMENT": "production"}, "demo initialization is forbidden in production"),
        ({"ITSM_BOOTSTRAP_PASSWORD": ""}, "ITSM_BOOTSTRAP_PASSWORD is required"),
    ],
)
def test_demo_refuses_before_creating_state(tmp_path: Path, overrides: dict, message: str) -> None:
    directory = tmp_path / "refused"
    result = initialize(directory, **overrides)
    assert result.returncode == 1
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "status": "error",
        "code": "demo_refused",
        "message": message,
    }
    assert not directory.exists()


def test_durable_demo_blocks_external_dispatch_but_keeps_internal_inbox(tmp_path: Path) -> None:
    from itsm.notifications.service import NotificationService, process_notifications
    from tests.test_phase8_notifications import _smtp_server, _smtp_url

    directory = tmp_path / "demo-notifications"
    initialized = initialize(directory)
    assert initialized.returncode == 0, initialized.stdout + initialized.stderr
    smtp = _smtp_server("accept")
    # Deliberately no demo process flag: persisted identity must survive restart.
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{directory / 'demo.db'}",
        monitoring_secrets={"demo-smtp": _smtp_url(smtp.server_address[1])},
    )
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            principal = IdentityService(session, settings).login("demo.owner", PASSWORD).principal
            service = NotificationService(session, settings)
            config = service.get_config(principal)
            external = service.save_channel(
                principal,
                {
                    "kind": "smtp",
                    "name": "Demo external test",
                    "secretRef": "demo-smtp",
                    "enabled": True,
                    "config": {},
                },
            )
            service.test_channel(principal, external["id"])
            service.test_channel(principal, config["defaults"]["internalChannelId"])
            result = process_notifications(settings)
            assert result["suppressed"] == 1
            assert result["delivered"] == 1
            assert smtp.connections == 0
            assert smtp.messages == []
            inbox = service.list_inbox(principal)
            assert inbox["total"] == 1
            assert inbox["items"][0]["title"] == "Prueba de notificación"
            repeated = process_notifications(settings)
            assert repeated["delivered"] == repeated["suppressed"] == 0
            assert smtp.connections == 0
            assert service.list_inbox(principal)["total"] == 1
    finally:
        engine.dispose()
        smtp.shutdown()
        smtp.server_close()
