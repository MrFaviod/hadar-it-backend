"""Backup verification must prove the AI credential key ring is usable (R4-F8).

A restore can bring back provider rows sealed with a key the current process
does not have. Verification used to warn only, so the backup automation copied
and pruned artifacts while the restored installation could not read a single
provider credential. These checks drive the real ``python -m itsm.ops`` process
with different key rings to prove the condition is reported and actionable.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from itsm.config import Settings
from itsm.ops import store
from tests.conftest import BACKEND_ROOT, worker_environment
from tests.test_ops_sqlite import migrated, payload, run_ops

RECORDED_KEY = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
OTHER_KEY = "MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE="


def run_key_ops(
    args: list[str],
    settings: Settings,
    backup_root: Path,
    *,
    keys: str | None,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    env = worker_environment(settings)
    env["ITSM_OPS_BACKUP_ROOT"] = str(backup_root)
    if keys is not None:
        env["ITSM_AI_CREDENTIAL_KEYS"] = keys
    return subprocess.run(
        [sys.executable, "-m", "itsm.ops", *args],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_verify_fails_when_the_recorded_key_ring_is_missing(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    created = run_key_ops(["backup"], settings, backup_root, keys=RECORDED_KEY)
    assert created.returncode == 0, created.stderr
    identifier = payload(created)["backup"]["id"]

    verified = run_key_ops(["verify", identifier], settings, backup_root, keys=OTHER_KEY)

    body = payload(verified)
    assert verified.returncode == 1
    assert body["verified"] is False
    assert body["checks"]["credentialKeys"] == "missing"
    assert body["credentialKeys"]["status"] == "missing"
    assert body["credentialKeys"]["missing"]
    assert "ITSM_AI_CREDENTIAL_KEYS" in body["error"]
    assert "unreadable" in body["error"]
    assert store.load_artifact(backup_root, identifier).manifest.verified is False


def test_verify_passes_with_the_recorded_key_ring(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    created = run_key_ops(["backup"], settings, backup_root, keys=RECORDED_KEY)
    assert created.returncode == 0, created.stderr
    identifier = payload(created)["backup"]["id"]

    verified = run_key_ops(["verify", identifier], settings, backup_root, keys=RECORDED_KEY)

    body = payload(verified)
    assert verified.returncode == 0, verified.stderr
    assert body["verified"] is True
    assert body["credentialKeys"]["status"] == "ok"
    assert body["credentialKeys"]["missing"] == []
    assert body["credentialKeys"]["error"] is None


def test_a_backup_without_a_key_ring_is_reported_as_unrecorded(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    """No ring configured: nothing to compare, but the gap must be visible."""
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    created = run_key_ops(["backup"], settings, backup_root, keys=None)
    assert created.returncode == 0, created.stderr
    identifier = payload(created)["backup"]["id"]

    verified = run_key_ops(["verify", identifier], settings, backup_root, keys=None)

    body = payload(verified)
    assert body["credentialKeys"]["status"] == "unrecorded"
    assert "take a new backup" in (body["credentialKeys"]["warning"] or "")

    reported = payload(run_key_ops(["status"], settings, backup_root, keys=None))
    assert reported["credentialKeys"]["status"] == "unrecorded"


def test_the_published_summary_carries_the_key_ring_state() -> None:
    """Automation reads the public copy, so the gap has to survive the allow-list."""
    summary = store.public_summary(
        {
            "status": "failed",
            "credentialKeys": {
                "status": "missing",
                "missing": ["0123456789ab"],
                "recorded": ["0123456789ab"],
                "current": [],
                "warning": None,
                "error": "restore the ring",
            },
        }
    )

    assert summary["credentialKeys"] == {"status": "missing", "missing": ["0123456789ab"]}


def test_backup_still_succeeds_but_publishes_a_failed_verification(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    """A ring mismatch after the fact must reach the published status as failed."""
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    created = run_key_ops(["backup"], settings, backup_root, keys=RECORDED_KEY)
    assert created.returncode == 0, created.stderr
    identifier = payload(created)["backup"]["id"]
    mismatched = run_key_ops(["verify", identifier], settings, backup_root, keys=OTHER_KEY)
    assert mismatched.returncode == 1

    published = payload(run_key_ops(["status"], settings, backup_root, keys=OTHER_KEY))

    assert published["credentialKeys"]["status"] == "missing"
    assert published["lastBackup"]["verified"] is False


def test_a_plain_backup_round_trip_is_unaffected_by_the_key_gate(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    keyless = run_ops(["backup"], settings, backup_root)

    assert keyless.returncode == 0, keyless.stderr
    identifier = payload(keyless)["backup"]["id"]
    assert payload(run_ops(["verify", identifier], settings, backup_root))["verified"] is True


def test_restore_still_recovers_data_without_the_recorded_key_ring(
    settings_factory: Callable[..., Settings], tmp_path: Path
) -> None:
    """A missing ring is reported, but recovery must not be blocked by it."""
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    created = run_key_ops(["backup"], settings, backup_root, keys=RECORDED_KEY)
    assert created.returncode == 0, created.stderr
    identifier = payload(created)["backup"]["id"]
    target = tmp_path / "restored" / "app.db"
    target.parent.mkdir()

    restored = run_key_ops(
        ["restore", identifier, "--target-file", str(target)],
        settings,
        backup_root,
        keys=OTHER_KEY,
    )

    body = payload(restored)
    assert restored.returncode == 0, restored.stderr
    assert body["status"] == "ok"
    assert body["credentialKeys"]["status"] == "missing"
    assert target.is_file()
