"""Credential key ring: rotation, status, restore and backup fingerprints.

The command checks drive the real ``python -m itsm.credentials`` process against
a migrated SQLite database, so exit codes and JSON payloads are the artefacts an
operator sees. No test expects key material, a plaintext credential or a
ciphertext in command output; the assertions check that absence explicitly.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from itsm.agent_integrations.models import AgentProvider
from itsm.agent_integrations.providers import (
    CredentialUnavailable,
    credential_key_fingerprints,
    credential_key_state,
    credential_storage_available,
    seal_credential,
    unseal_credential,
)
from itsm.ai_gateway.models import AiGatewayLease
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from pydantic import ValidationError
from tests.conftest import BACKEND_ROOT, run_migrations, worker_environment
from tests.test_ops_sqlite import run_ops

CLI = "itsm.credentials"
CREDENTIALS_KEY = "ITSM_AI_CREDENTIAL_KEYS"
LEGACY_KEY = "ITSM_AI_CREDENTIAL_KEY"

PRIMARY = Fernet.generate_key().decode()
LEGACY = Fernet.generate_key().decode()
FOREIGN = Fernet.generate_key().decode()
PLAINTEXT = "sk-credential-plaintext-never-printed"


def payload(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    stream = result.stdout.strip() or result.stderr.strip()
    return json.loads(stream.splitlines()[-1])


def run_cli(
    args: list[str],
    settings: Settings,
    *,
    keys: str | None = None,
    legacy: str | None = None,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    env = worker_environment(settings)
    env.pop(CREDENTIALS_KEY, None)
    env.pop(LEGACY_KEY, None)
    if keys is not None:
        env[CREDENTIALS_KEY] = keys
    if legacy is not None:
        env[LEGACY_KEY] = legacy
    return subprocess.run(
        [sys.executable, "-m", CLI, *args],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def migrated(settings_factory: Callable[..., Settings]) -> Settings:
    settings = settings_factory()
    assert run_migrations(settings).returncode == 0
    return settings


def add_provider(settings: Settings, ciphertext: str, *, scope: str = "global") -> str:
    provider_id = str(uuid4())
    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            session.add(
                AgentProvider(
                    id=provider_id,
                    name="ring provider",
                    scope=scope,
                    owner_id=None,
                    base_url="https://api.example.com/v1",
                    models=["model-a"],
                    api_key_ciphertext=ciphertext,
                    enabled=True,
                )
            )
            session.commit()
    finally:
        engine.dispose()
    return provider_id


def provider_ciphertext(settings: Settings, provider_id: str) -> str | None:
    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            row = session.get(AgentProvider, provider_id)
            assert row is not None
            return row.api_key_ciphertext
    finally:
        engine.dispose()


def add_lease(settings: Settings, ciphertext: str, *, expires_in: timedelta) -> str:
    lease_id = str(uuid4())
    created = datetime.now(UTC)
    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            session.add(
                AiGatewayLease(
                    id=lease_id,
                    token_hash=f"{uuid4().hex}{uuid4().hex}"[:64],
                    actor_id=str(uuid4()),
                    run_id=str(uuid4()),
                    parent_reservation_id=str(uuid4()),
                    funding="personal",
                    provider_id=str(uuid4()),
                    provider_scope="personal",
                    provider_name="ring provider",
                    model="model-a",
                    engine="pydantic",
                    context_tokens=1024,
                    output_tokens=256,
                    selection_ciphertext=ciphertext,
                    allow_private=False,
                    created_at=created,
                    expires_at=created + expires_in,
                )
            )
            session.commit()
    finally:
        engine.dispose()
    return lease_id


def lease_ciphertext(settings: Settings, lease_id: str) -> str:
    engine = create_engine_from_settings(settings)
    try:
        with create_session_factory(engine)() as session:
            row = session.get(AiGatewayLease, lease_id)
            assert row is not None
            return row.selection_ciphertext
    finally:
        engine.dispose()


# --------------------------------------------------------------------------- #
# Ring parsing and fingerprints
# --------------------------------------------------------------------------- #


def test_legacy_sealed_credential_is_readable_with_a_new_primary_key(
    settings_factory: Callable[..., Settings],
) -> None:
    token = seal_credential(settings_factory(ai_credential_key=LEGACY), PLAINTEXT)

    ring = settings_factory(ai_credential_keys=f"{PRIMARY},{LEGACY}")

    assert unseal_credential(ring, token) == PLAINTEXT
    assert credential_key_state(ring, token) == "older"


def test_legacy_key_is_appended_for_decryption_when_both_settings_are_set(
    settings_factory: Callable[..., Settings],
) -> None:
    token = seal_credential(settings_factory(ai_credential_key=LEGACY), PLAINTEXT)

    ring = settings_factory(ai_credential_keys=PRIMARY, ai_credential_key=LEGACY)

    assert unseal_credential(ring, token) == PLAINTEXT
    assert credential_key_state(ring, token) == "older"
    assert len(credential_key_fingerprints(ring)) == 2


def test_duplicate_legacy_key_is_not_appended_twice(
    settings_factory: Callable[..., Settings],
) -> None:
    ring = settings_factory(ai_credential_keys=f"{PRIMARY},{LEGACY}", ai_credential_key=LEGACY)

    assert len(credential_key_fingerprints(ring)) == 2


def test_fingerprints_are_short_non_reversible_and_stable(
    settings_factory: Callable[..., Settings],
) -> None:
    ring = settings_factory(ai_credential_keys=f"{PRIMARY},{LEGACY}")

    fingerprints = credential_key_fingerprints(ring)

    assert len(fingerprints) == 2
    assert fingerprints[0] != fingerprints[1]
    for fingerprint, key in zip(fingerprints, (PRIMARY, LEGACY), strict=True):
        assert len(fingerprint) == 12
        assert all(character in "0123456789abcdef" for character in fingerprint)
        assert key not in fingerprint
        assert fingerprint != key[:12]
    assert credential_key_fingerprints(ring) == fingerprints


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_ring_setting_is_disabled(
    settings_factory: Callable[..., Settings], blank: str
) -> None:
    settings = settings_factory(ai_credential_keys=blank)

    assert settings.ai_credential_keys is None
    assert credential_storage_available(settings) is False
    with pytest.raises(CredentialUnavailable):
        seal_credential(settings, PLAINTEXT)


def test_malformed_ring_key_is_rejected_by_position_without_echoing_the_key(
    settings_factory: Callable[..., Settings],
) -> None:
    malformed = "not-a-fernet-key-nor-a-secret"

    with pytest.raises(ValidationError) as raised:
        settings_factory(ai_credential_keys=f"{PRIMARY},{malformed}")

    message = str(raised.value)
    assert "ai_credential_keys entry 2" in message
    assert malformed not in message


def test_ring_is_read_from_the_comma_separated_process_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ITSM_DATABASE_URL", "sqlite:////tmp/ring-env.db")
    monkeypatch.setenv("ITSM_TASK_SQLITE_PATH", "/tmp/ring-env-tasks.db")
    monkeypatch.setenv(CREDENTIALS_KEY, f" {PRIMARY} , {LEGACY} ")

    settings = Settings(_env_file=None)

    assert len(credential_key_fingerprints(settings)) == 2
    assert settings.ai_credential_keys is not None
    assert PRIMARY in settings.sensitive_values()
    assert LEGACY in settings.sensitive_values()


def test_unavailable_storage_reports_unavailable_state(
    settings_factory: Callable[..., Settings],
) -> None:
    token = seal_credential(settings_factory(ai_credential_key=LEGACY), PLAINTEXT)

    assert credential_key_state(settings_factory(), token) == "unavailable"


# --------------------------------------------------------------------------- #
# Status and rotation through the real CLI
# --------------------------------------------------------------------------- #


def test_status_reports_primary_counts_and_exits_zero(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    token = seal_credential(settings_factory(ai_credential_keys=PRIMARY), PLAINTEXT)
    add_provider(settings, token)

    result = run_cli(["status"], settings, keys=PRIMARY)

    assert result.returncode == 0, result.stdout + result.stderr
    body = payload(result)
    assert body["status"] == "ok"
    assert body["credentialStorageAvailable"] is True
    assert body["providers"]["global"] == {
        "total": 1,
        "primary": 1,
        "older": 0,
        "unreadable": 0,
    }
    assert body["providers"]["personal"]["total"] == 0
    assert body["gatewayLeases"]["unexpired"]["total"] == 0
    assert body["activeFingerprints"] == credential_key_fingerprints(
        settings_factory(ai_credential_keys=PRIMARY)
    )
    assert body["unreadableRows"] == []


def test_status_reports_older_key_rows_and_exits_zero(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    token = seal_credential(settings_factory(ai_credential_key=LEGACY), PLAINTEXT)
    add_provider(settings, token)

    result = run_cli(["status"], settings, keys=PRIMARY, legacy=LEGACY)

    assert result.returncode == 0, result.stdout + result.stderr
    assert payload(result)["providers"]["global"]["older"] == 1


def test_status_reports_unreadable_rows_and_exits_nonzero(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    provider_id = add_provider(
        settings, seal_credential(settings_factory(ai_credential_key=FOREIGN), PLAINTEXT)
    )

    result = run_cli(["status"], settings, keys=PRIMARY)

    assert result.returncode == 1
    body = payload(result)
    assert body["status"] == "unreadable_credentials"
    assert body["providers"]["global"]["unreadable"] == 1
    assert body["unreadableRows"] == [
        {"table": "agent_providers", "id": provider_id, "scope": "global"}
    ]


def test_status_reports_unavailable_storage_and_exits_nonzero(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    add_provider(settings, seal_credential(settings_factory(ai_credential_key=LEGACY), PLAINTEXT))

    result = run_cli(["status"], settings)

    assert result.returncode == 1
    body = payload(result)
    assert body["credentialStorageAvailable"] is False
    assert body["activeFingerprints"] == []
    assert body["providers"]["global"]["unreadable"] == 1


def test_rotate_reencrypts_legacy_ciphertext_and_survives_removing_the_old_key(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    provider_id = add_provider(
        settings, seal_credential(settings_factory(ai_credential_key=LEGACY), PLAINTEXT)
    )
    before = provider_ciphertext(settings, provider_id)

    result = run_cli(["rotate"], settings, keys=f"{PRIMARY},{LEGACY}")

    assert result.returncode == 0, result.stdout + result.stderr
    body = payload(result)
    assert body["rotated"] == {"providers": 1, "gatewayLeases": 0}
    assert body["unreadableRows"] == []
    after = provider_ciphertext(settings, provider_id)
    assert after is not None and after != before
    new_only = settings_factory(ai_credential_keys=PRIMARY)
    assert unseal_credential(new_only, after) == PLAINTEXT
    assert credential_key_state(new_only, after) == "primary"


def test_rotate_is_idempotent(settings_factory: Callable[..., Settings]) -> None:
    settings = migrated(settings_factory)
    add_provider(settings, seal_credential(settings_factory(ai_credential_key=LEGACY), PLAINTEXT))
    first = run_cli(["rotate"], settings, keys=f"{PRIMARY},{LEGACY}")
    assert first.returncode == 0, first.stdout + first.stderr

    second = run_cli(["rotate"], settings, keys=f"{PRIMARY},{LEGACY}")

    assert second.returncode == 0, second.stdout + second.stderr
    body = payload(second)
    assert body["rotated"] == {"providers": 0, "gatewayLeases": 0}
    assert body["pendingRotation"] == {"providers": 0, "gatewayLeases": 0}
    assert body["unchanged"] == {"providers": 1, "gatewayLeases": 0}


def test_rotate_dry_run_reports_pending_rotation_without_writing(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    provider_id = add_provider(
        settings, seal_credential(settings_factory(ai_credential_key=LEGACY), PLAINTEXT)
    )
    before = provider_ciphertext(settings, provider_id)

    result = run_cli(["rotate", "--dry-run"], settings, keys=f"{PRIMARY},{LEGACY}")

    assert result.returncode == 0, result.stdout + result.stderr
    body = payload(result)
    assert body["dryRun"] is True
    assert body["rotated"] == {"providers": 0, "gatewayLeases": 0}
    assert body["pendingRotation"] == {"providers": 1, "gatewayLeases": 0}
    assert provider_ciphertext(settings, provider_id) == before


def test_rotate_reports_unreadable_rows_and_leaves_them_untouched(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    provider_id = add_provider(
        settings, seal_credential(settings_factory(ai_credential_key=FOREIGN), PLAINTEXT)
    )
    before = provider_ciphertext(settings, provider_id)

    result = run_cli(["rotate"], settings, keys=f"{PRIMARY},{LEGACY}")

    assert result.returncode == 1
    body = payload(result)
    assert body["status"] == "unreadable_credentials"
    assert body["unreadableRows"] == [
        {"table": "agent_providers", "id": provider_id, "scope": "global"}
    ]
    assert provider_ciphertext(settings, provider_id) == before
    assert body["providers"]["global"]["total"] == 1


def test_rotate_refuses_without_a_configured_key_ring(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    provider_id = add_provider(
        settings, seal_credential(settings_factory(ai_credential_key=LEGACY), PLAINTEXT)
    )
    before = provider_ciphertext(settings, provider_id)

    result = run_cli(["rotate"], settings)

    assert result.returncode == 2
    assert "not configured" in result.stderr
    assert provider_ciphertext(settings, provider_id) == before


def test_unexpired_gateway_leases_are_rotated_and_expired_ones_are_left_alone(
    settings_factory: Callable[..., Settings],
) -> None:
    settings = migrated(settings_factory)
    legacy = settings_factory(ai_credential_key=LEGACY)
    live_id = add_lease(settings, seal_credential(legacy, PLAINTEXT), expires_in=timedelta(hours=1))
    expired_id = add_lease(
        settings, seal_credential(legacy, PLAINTEXT), expires_in=timedelta(hours=-1)
    )
    expired_before = lease_ciphertext(settings, expired_id)

    result = run_cli(["rotate"], settings, keys=f"{PRIMARY},{LEGACY}")

    assert result.returncode == 0, result.stdout + result.stderr
    assert payload(result)["rotated"] == {"providers": 0, "gatewayLeases": 1}
    new_only = settings_factory(ai_credential_keys=PRIMARY)
    assert unseal_credential(new_only, lease_ciphertext(settings, live_id)) == PLAINTEXT
    assert lease_ciphertext(settings, expired_id) == expired_before
    status = run_cli(["status"], settings, keys=f"{PRIMARY},{LEGACY}")
    assert payload(status)["gatewayLeases"]["unexpired"]["total"] == 1


@pytest.mark.parametrize("command", ["status", "rotate"])
def test_commands_never_print_keys_plaintext_or_ciphertext(
    settings_factory: Callable[..., Settings], command: str
) -> None:
    settings = migrated(settings_factory)
    token = seal_credential(settings_factory(ai_credential_key=LEGACY), PLAINTEXT)
    add_provider(settings, token)

    result = run_cli([command], settings, keys=f"{PRIMARY},{LEGACY}")

    output = result.stdout + result.stderr
    assert PRIMARY not in output
    assert LEGACY not in output
    assert PLAINTEXT not in output
    assert token not in output


# --------------------------------------------------------------------------- #
# Backup manifest fingerprints and restore warnings
# --------------------------------------------------------------------------- #


def test_backup_manifest_records_key_fingerprints_but_never_keys(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    ring = f"{PRIMARY},{LEGACY}"

    created = run_ops(["backup"], settings, backup_root, extra_env={CREDENTIALS_KEY: ring})

    assert created.returncode == 0, created.stdout + created.stderr
    body = payload(created)
    manifest = body["backup"]
    expected = credential_key_fingerprints(settings_factory(ai_credential_keys=ring))
    assert manifest["aiCredentialKeyFingerprints"] == expected
    disk = json.loads((Path(body["path"]) / "manifest.json").read_text())
    assert disk["aiCredentialKeyFingerprints"] == expected
    serialized = json.dumps(body) + json.dumps(disk)
    assert PRIMARY not in serialized
    assert LEGACY not in serialized


def test_verify_warns_when_the_current_ring_lacks_a_recorded_fingerprint(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    created = run_ops(
        ["backup"],
        settings,
        backup_root,
        extra_env={CREDENTIALS_KEY: f"{PRIMARY},{LEGACY}"},
    )
    assert created.returncode == 0, created.stdout + created.stderr
    backup_id = payload(created)["backup"]["id"]
    recorded_legacy = credential_key_fingerprints(
        settings_factory(ai_credential_keys=f"{PRIMARY},{LEGACY}")
    )[1]

    checked = run_ops(
        ["verify", backup_id], settings, backup_root, extra_env={CREDENTIALS_KEY: PRIMARY}
    )

    assert checked.returncode == 0, checked.stdout + checked.stderr
    body = payload(checked)
    assert body["verified"] is True
    assert body["credentialKeys"]["missing"] == [recorded_legacy]
    assert any("fingerprint" in warning for warning in body["warnings"])


def test_verify_reports_no_warning_when_the_ring_covers_every_fingerprint(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    ring = f"{PRIMARY},{LEGACY}"
    created = run_ops(["backup"], settings, backup_root, extra_env={CREDENTIALS_KEY: ring})
    assert created.returncode == 0, created.stdout + created.stderr
    backup_id = payload(created)["backup"]["id"]

    checked = run_ops(
        ["verify", backup_id], settings, backup_root, extra_env={CREDENTIALS_KEY: ring}
    )

    assert checked.returncode == 0, checked.stdout + checked.stderr
    body = payload(checked)
    assert body["credentialKeys"]["missing"] == []
    assert body["warnings"] == []


def test_restore_warns_when_the_backup_ring_is_not_available(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    created = run_ops(
        ["backup"],
        settings,
        backup_root,
        extra_env={CREDENTIALS_KEY: f"{PRIMARY},{LEGACY}"},
    )
    assert created.returncode == 0, created.stdout + created.stderr
    backup_id = payload(created)["backup"]["id"]
    target = tmp_path / "restored.db"

    restored = run_ops(["restore", backup_id, "--target-file", str(target)], settings, backup_root)

    assert restored.returncode == 0, restored.stdout + restored.stderr
    body = payload(restored)
    assert body["credentialKeys"]["current"] == []
    assert len(body["credentialKeys"]["missing"]) == 2
    assert body["warnings"]
