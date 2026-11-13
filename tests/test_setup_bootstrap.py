"""Bootstrap setup service: sanitized status, one-time claim and sessions.

The setup application must answer with no database reachable at all. These
tests therefore only use the private bootstrap store, the FastAPI app factory
and the operator CLI; none of them imports ``itsm.main``.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from itsm.setup.api import create_setup_app, require_session_mutation
from itsm.setup.schemas import FORBIDDEN_STATUS_TOKENS, SANITIZED_STATUS_FIELDS
from itsm.setup.store import (
    SESSION_TTL_MINUTES,
    SetupConfigurationError,
    SetupStore,
    StoreUnsafe,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "http://testserver"
COOKIE_NAME = "itsm_setup_session"
STATUS_PATH = "/api/setup/v1/status"
CLAIM_PATH = "/api/setup/v1/claim"
SESSION_PATH = "/api/setup/v1/session"


class FakeClock:
    """Controllable UTC clock for expiry tests."""

    def __init__(self) -> None:
        self.now = datetime(2026, 1, 13, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: int) -> None:
        self.now += timedelta(**kwargs)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "private" / "setup-state"


@pytest.fixture(autouse=True)
def setup_environment(monkeypatch: pytest.MonkeyPatch, state_dir: Path) -> None:
    monkeypatch.setenv("ITSM_SETUP_STATE_DIR", str(state_dir))
    monkeypatch.setenv("RELEASE_MODE", "dev")
    monkeypatch.setenv("ITSM_AUTH_COOKIE_SECURE", "false")
    monkeypatch.delenv("ITSM_SETUP_ALLOWED_ORIGINS", raising=False)


@pytest.fixture
def store(state_dir: Path, clock: FakeClock) -> SetupStore:
    instance = SetupStore(state_dir, clock=clock)
    instance.ensure_ready()
    return instance


def build_app(state_dir: Path, clock: FakeClock):
    return create_setup_app(state_dir=state_dir, clock=clock)


def enable_claim(store: SetupStore) -> str:
    return store.enable_claim()


def claim(
    client: TestClient,
    credential: str,
    *,
    origin: str | None = ORIGIN,
    csrf: str | None = None,
):
    headers = {}
    if origin is not None:
        headers["Origin"] = origin
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    return client.post(CLAIM_PATH, json={"credential": credential}, headers=headers)


def run_cli(
    *arguments: str,
    state_dir: Path,
    mode: str = "dev",
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    environment.update(
        {
            "PYTHONPATH": str(BACKEND_ROOT),
            "RELEASE_MODE": mode,
            "ITSM_SETUP_STATE_DIR": str(state_dir),
            "ITSM_AUTH_COOKIE_SECURE": "false",
        }
    )
    if extra_env:
        environment.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "itsm.setup.cli", *arguments],
        cwd=BACKEND_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )


def cli_payload(result: subprocess.CompletedProcess[str]) -> dict:
    assert result.returncode == 0, (result.stdout, result.stderr)
    return json.loads(result.stdout.strip().splitlines()[-1])


# --------------------------------------------------------------------- imports
def test_setup_imports_and_serves_status_with_no_database(tmp_path: Path) -> None:
    state = tmp_path / "db-free-state"
    script = """
import gc
import json
import os
import sys
from fastapi.testclient import TestClient
from itsm.setup.api import create_setup_app
from itsm.setup.store import SetupStore

store = SetupStore(os.environ["ITSM_SETUP_STATE_DIR"])
store.ensure_ready()
store.enable_claim()
app = create_setup_app()
client = TestClient(app)
response = client.get("/api/setup/v1/status")
assert response.status_code == 200, response.text
payload = response.json()
assert payload["state"] == "unclaimed", payload
assert payload["setup_enabled"] is True, payload
assert payload["backend"] == "unknown", payload
assert "itsm.main" not in sys.modules
assert "itsm.database" not in sys.modules
assert "itsm.identity.api" not in sys.modules
from sqlalchemy.engine import Engine

engines = [item for item in gc.get_objects() if isinstance(item, Engine)]
assert not engines, engines
print(json.dumps(payload))
"""
    environment = {key: value for key, value in os.environ.items() if not key.startswith("ITSM_")}
    environment.update(
        {
            "PYTHONPATH": str(BACKEND_ROOT),
            "RELEASE_MODE": "dev",
            "ITSM_SETUP_STATE_DIR": str(state),
            "ITSM_DATABASE_URL": "postgresql+psycopg://itsm@127.0.0.1:1/unreachable",
        }
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["state"] == "unclaimed"
    assert payload["instance_id"]


# ---------------------------------------------------------------------- status
def test_status_is_sanitized_and_distinguishes_each_state(
    store: SetupStore, state_dir: Path, clock: FakeClock
) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        disabled = client.get(STATUS_PATH)
        assert disabled.status_code == 200
        body = disabled.json()
        assert set(body) == set(SANITIZED_STATUS_FIELDS)
        assert body["state"] == "disabled"
        assert body["setup_enabled"] is False
        assert body["claim_available"] is False
        assert body["backend"] == "unknown"
        assert body["mode"] == "dev"
        assert body["release_mode"] == "dev"
        assert body["instance_id"] is None
        serialized = json.dumps(body).lower()
        for forbidden in FORBIDDEN_STATUS_TOKENS:
            assert forbidden not in serialized, forbidden

    credential = enable_claim(store)
    with TestClient(app) as client:
        unclaimed = client.get(STATUS_PATH).json()
        assert unclaimed["state"] == "unclaimed"
        assert unclaimed["setup_enabled"] is True
        assert unclaimed["claim_available"] is True
        assert unclaimed["instance_id"]
        assert credential not in json.dumps(unclaimed)

        assert claim(client, credential).status_code == 200
        claimed = client.get(STATUS_PATH).json()
        assert claimed["state"] == "claimed"
        assert claimed["setup_enabled"] is True
        assert claimed["claim_available"] is False
        assert claimed["instance_id"] == unclaimed["instance_id"]
        assert credential not in json.dumps(claimed)


def test_anonymous_session_is_denied(state_dir: Path, clock: FakeClock) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        response = client.get(SESSION_PATH)
    assert response.status_code == 401
    assert response.json() == {"error": "authentication_required"}


def test_app_serves_disabled_status_before_the_state_directory_exists(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "not-created" / "setup-state"
    monkeypatch.setenv("ITSM_SETUP_STATE_DIR", str(missing))
    app = create_setup_app(clock=clock)
    with TestClient(app) as client:
        response = client.get(STATUS_PATH)
    assert response.status_code == 200
    assert response.json()["state"] == "disabled"
    assert response.json()["claim_available"] is False
    assert not missing.exists()


def test_claim_is_refused_while_setup_is_not_enabled(state_dir: Path, clock: FakeClock) -> None:
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        response = claim(client, "anything")
        assert response.status_code == 403
        assert response.json() == {"error": "setup_disabled"}


# ----------------------------------------------------------------------- claim
def test_claim_consumes_credential_and_issues_a_strict_cookie(
    store: SetupStore, state_dir: Path, clock: FakeClock
) -> None:
    credential = enable_claim(store)
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        response = claim(client, credential)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "claimed"
        assert body["mode"] == "dev"
        assert body["release_mode"] == "dev"
        assert body["csrf_token"]
        cookie = response.headers["set-cookie"].lower()
        assert f"{COOKIE_NAME}=" in cookie
        assert "path=/api/setup/v1" in cookie
        assert "httponly" in cookie
        assert "samesite=strict" in cookie
        assert f"max-age={SESSION_TTL_MINUTES * 60}" in cookie

        session = client.get(SESSION_PATH)
        assert session.status_code == 200, session.text
        assert session.json() == {
            "state": "claimed",
            "mode": "dev",
            "release_mode": "dev",
            "checks": [],
        }

        second = claim(client, credential)
        assert second.status_code == 409
        assert second.json() == {"error": "already_claimed"}


def test_claim_requires_origin(store, state_dir, clock) -> None:
    credential = enable_claim(store)
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        missing = claim(client, credential, origin=None)
        assert missing.status_code == 403
        assert missing.json() == {"error": "origin_not_allowed"}
        wrong = claim(client, credential, origin="http://elsewhere.test")
        assert wrong.status_code == 403
        assert client.get(STATUS_PATH).json()["state"] == "unclaimed"
        accepted = claim(client, credential)
        assert accepted.status_code == 200


def test_configured_origin_allowlist_is_exact(
    store: SetupStore, state_dir: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ITSM_SETUP_ALLOWED_ORIGINS", "https://setup.example,https://admin.example")
    credential = enable_claim(store)
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        assert claim(client, credential, origin="https://evil.example").status_code == 403
        accepted = claim(client, credential, origin="https://setup.example")
        assert accepted.status_code == 200


def test_wrong_credentials_lock_until_operator_rotation(
    store: SetupStore, state_dir: Path, clock: FakeClock
) -> None:
    credential = enable_claim(store)
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        for _ in range(4):
            assert claim(client, "not-the-credential").status_code == 401
        assert client.get(STATUS_PATH).json()["claim_available"] is True
        fifth = claim(client, "not-the-credential")
        assert fifth.status_code == 401
        assert client.get(STATUS_PATH).json()["claim_available"] is False
        locked = claim(client, credential)
        assert locked.status_code == 429
        assert locked.json() == {"error": "claim_locked"}

    restarted = build_app(state_dir, clock)
    with TestClient(restarted) as client:
        assert claim(client, credential).status_code == 429

    rotated = store.rotate_claim()
    assert rotated != credential
    with TestClient(restarted) as client:
        assert claim(client, credential).status_code == 401
        assert claim(client, rotated).status_code == 200


def test_recovery_reauthorizes_without_resetting_state_or_instance(
    store: SetupStore, state_dir: Path, clock: FakeClock
) -> None:
    credential = enable_claim(store)
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        assert claim(client, credential).status_code == 200
        before = client.get(STATUS_PATH).json()
        recovery = store.issue_recovery()
        recovered = claim(client, recovery)
        assert recovered.status_code == 200
        assert recovered.json()["state"] == "claimed"
        after = client.get(STATUS_PATH).json()
        assert after == before
        assert claim(client, recovery).status_code == 409


def test_session_mutations_require_origin_and_csrf(
    store: SetupStore, state_dir: Path, clock: FakeClock
) -> None:
    credential = enable_claim(store)
    app = build_app(state_dir, clock)

    @app.post("/api/setup/v1/session/probe")
    def session_probe(session=Depends(require_session_mutation)) -> dict:
        return {"status": "ok"}

    with TestClient(app) as client:
        claimed = claim(client, credential)
        assert claimed.status_code == 200
        csrf = claimed.json()["csrf_token"]
        assert client.post("/api/setup/v1/session/probe").status_code == 403
        wrong = client.post(
            "/api/setup/v1/session/probe",
            headers={"Origin": ORIGIN, "X-CSRF-Token": "wrong"},
        )
        assert wrong.status_code == 403
        no_origin = client.post("/api/setup/v1/session/probe", headers={"X-CSRF-Token": csrf})
        assert no_origin.status_code == 403
        accepted = client.post(
            "/api/setup/v1/session/probe",
            headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        )
        assert accepted.status_code == 200
        assert accepted.json() == {"status": "ok"}


def test_session_expires_with_the_injected_clock(
    store: SetupStore, state_dir: Path, clock: FakeClock
) -> None:
    credential = enable_claim(store)
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        assert claim(client, credential).status_code == 200
        clock.advance(minutes=SESSION_TTL_MINUTES - 1)
        assert client.get(SESSION_PATH).status_code == 200
        clock.advance(minutes=2)
        expired = client.get(SESSION_PATH)
        assert expired.status_code == 401
        assert expired.json() == {"error": "authentication_required"}


def test_restart_keeps_state_and_session(store, state_dir, clock) -> None:
    credential = enable_claim(store)
    first = build_app(state_dir, clock)
    with TestClient(first) as client:
        assert claim(client, credential).status_code == 200
        token = client.cookies.get(COOKIE_NAME)
    assert token

    second = build_app(state_dir, clock)
    with TestClient(second, cookies={COOKIE_NAME: token}) as client:
        assert client.get(SESSION_PATH).status_code == 200
        assert client.get(STATUS_PATH).json()["state"] == "claimed"
    secrets_file = (state_dir / "secrets.json").read_text(encoding="utf-8")
    assert token not in secrets_file


# ------------------------------------------------------------------ persistence
def test_two_concurrent_claims_produce_exactly_one_session(
    store: SetupStore, state_dir: Path, clock: FakeClock
) -> None:
    credential = enable_claim(store)
    app = build_app(state_dir, clock)
    barrier = threading.Barrier(2)
    results: list[int] = []
    results_lock = threading.Lock()

    def attempt() -> None:
        with TestClient(app) as client:
            barrier.wait(timeout=10)
            response = claim(client, credential)
            with results_lock:
                results.append(response.status_code)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(results) == [200, 409]
    assert SetupStore(state_dir, clock=clock).public_state()["state"] == "claimed"
    private = json.loads((state_dir / "secrets.json").read_text(encoding="utf-8"))
    assert len(private["sessions"]) == 1


def test_private_directory_and_files_use_restrictive_modes(
    store: SetupStore, state_dir: Path, clock: FakeClock
) -> None:
    credential = enable_claim(store)
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        assert claim(client, credential).status_code == 200
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    for name in ("state.json", "secrets.json", "enabled.json", "journal.jsonl", "lock"):
        path = state_dir / name
        assert path.is_file(), name
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, name


def test_symlinked_state_directory_is_refused(tmp_path: Path, clock: FakeClock) -> None:
    real = tmp_path / "real-state"
    real.mkdir(mode=0o700)
    link = tmp_path / "linked-state"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(StoreUnsafe):
        create_setup_app(state_dir=link, clock=clock)
    with pytest.raises(StoreUnsafe):
        SetupStore(link, clock=clock).ensure_ready()


def test_symlinked_store_file_is_refused(store: SetupStore, state_dir: Path) -> None:
    store.enable_claim()
    target = state_dir.parent / "state-copy.json"
    target.write_text("{}", encoding="utf-8")
    state_file = state_dir / "state.json"
    if state_file.exists():
        state_file.unlink()
    state_file.symlink_to(target)
    with pytest.raises(StoreUnsafe):
        store.public_state()


def test_claim_credential_never_reaches_logs_or_the_store(
    store: SetupStore, state_dir: Path, clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    credential = enable_claim(store)
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        assert claim(client, credential).status_code == 200
        status = client.get(STATUS_PATH)
    assert status.status_code == 200
    assert credential not in status.text
    assert credential not in caplog.text
    shared = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            state_dir / "state.json",
            state_dir / "secrets.json",
            state_dir / "journal.jsonl",
        )
    )
    assert credential not in shared

    journal = [json.loads(line) for line in (state_dir / "journal.jsonl").read_text().splitlines()]
    assert journal[-1]["action"] == "claim"
    assert journal[-1]["revision"] >= 1
    assert journal[-1]["idempotency_key"]


def test_store_hashes_the_credential_and_keeps_public_state_separate(
    store: SetupStore, state_dir: Path
) -> None:
    credential = enable_claim(store)
    private = json.loads((state_dir / "secrets.json").read_text(encoding="utf-8"))
    public = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
    assert private["claim"]["hash"] != credential
    assert private["claim"]["hash"].startswith("$argon2id$")
    assert "claim" not in public
    assert "sessions" not in public


def test_demo_mode_is_refused(tmp_path, clock, monkeypatch) -> None:
    monkeypatch.setenv("RELEASE_MODE", "demo")
    with pytest.raises(SetupConfigurationError):
        create_setup_app(state_dir=tmp_path / "demo-state", clock=clock)
    assert not (tmp_path / "demo-state").exists()

    result = run_cli("enable-claim", state_dir=tmp_path / "demo-cli", mode="demo")
    assert result.returncode != 0
    assert "demo" in result.stderr.lower()
    assert not (tmp_path / "demo-cli" / "enabled.json").exists()


def test_claim_validation_errors_are_sanitized(store, state_dir, clock) -> None:
    enable_claim(store)
    app = build_app(state_dir, clock)
    with TestClient(app) as client:
        response = client.post(CLAIM_PATH, json={}, headers={"Origin": ORIGIN})
    assert response.status_code == 422
    assert response.json() == {"error": "invalid_request"}


def test_cookie_is_secure_when_configured(
    store: SetupStore, state_dir: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential = enable_claim(store)
    monkeypatch.setenv("ITSM_AUTH_COOKIE_SECURE", "true")
    app = build_app(state_dir, clock)
    with TestClient(app, base_url="https://testserver") as client:
        response = client.post(
            CLAIM_PATH,
            json={"credential": credential},
            headers={"Origin": "https://testserver"},
        )
    assert response.status_code == 200
    assert "secure" in response.headers["set-cookie"].lower()


# ------------------------------------------------------------------------- CLI
def test_cli_enable_rotate_and_recover(tmp_path: Path) -> None:
    state = tmp_path / "cli-state"
    first = cli_payload(run_cli("enable-claim", "--state-dir", str(state), state_dir=state))
    credential = first["credential"]
    assert first["state"] == "unclaimed"
    assert (state / "enabled.json").is_file()

    rotated = cli_payload(run_cli("rotate-claim", state_dir=state))
    assert rotated["credential"] != credential

    app = build_app(state, FakeClock())
    with TestClient(app) as client:
        assert claim(client, credential).status_code == 401
        assert claim(client, rotated["credential"]).status_code == 200
        instance_id = client.get(STATUS_PATH).json()["instance_id"]

    already = run_cli("enable-claim", state_dir=state)
    assert already.returncode != 0
    assert json.loads(already.stderr.strip().splitlines()[-1])["code"] == "already_claimed"

    recovery = cli_payload(run_cli("recover", state_dir=state))
    with TestClient(app) as client:
        recovered = claim(client, recovery["credential"])
        assert recovered.status_code == 200
        status = client.get(STATUS_PATH).json()
        assert status["state"] == "claimed"
        assert status["instance_id"] == instance_id


def test_cli_recover_requires_a_claimed_installation(tmp_path: Path) -> None:
    state = tmp_path / "unclaimed-cli"
    cli_payload(run_cli("enable-claim", state_dir=state))
    result = run_cli("recover", state_dir=state)
    assert result.returncode != 0
    assert json.loads(result.stderr.strip().splitlines()[-1])["code"] == "not_claimed"


def test_cli_never_prints_the_credential_on_stderr(tmp_path: Path) -> None:
    state = tmp_path / "quiet-cli"
    result = run_cli("enable-claim", state_dir=state)
    credential = cli_payload(result)["credential"]
    assert credential not in result.stderr
    assert credential in result.stdout
