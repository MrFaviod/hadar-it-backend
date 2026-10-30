"""Public demo exposure limits: request rate, login rate, bodies, sessions, storage.

Covers S16 (the public demo survives abusive or automated visitors: bounded
requests, bodies and sessions, plus a shared attachment quota). Every limit in
this file is enforced by the backend and configured through ``ITSM_DEMO_*``
settings; ``prod`` and ``dev`` keep no limiter at all.

The HTTP assertions run against a real app started in ``demo`` release mode over
a migrated, seeded demo installation. Bucket internals are only inspected where
a deterministic clock is required (in-flight concurrency).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.demo.seed import seed
from itsm.limits import DemoLimits, client_key
from itsm.release_mode import RELEASE_MODE_ENV
from sqlalchemy import text
from sqlalchemy.orm import Session
from tests.conftest import run_migrations

ORIGIN = "http://testserver"
API = "/api/v1"
VISITOR = {"username": "admin", "password": "admin"}
INSTALLER_PASSWORD = "Demo-Installer-Pass-2026"

SAMPLE_PDF = b"%PDF-1.7\n" + b"demo" * 40 + b"\n%%EOF\n"
PADDED_PDF = SAMPLE_PDF + b" " * 520


def demo_settings(directory: Path) -> Settings:
    (directory / "tasks").mkdir(parents=True, exist_ok=True)
    return Settings(
        _env_file=None,
        environment="test",
        database_url=f"sqlite:///{directory / 'demo.db'}",
        task_sqlite_path=directory / "tasks" / "huey.db",
        attachment_storage_path=directory / "blobs",
        auth_origin=ORIGIN,
        auth_cookie_secure=False,
        log_level="WARNING",
        demo_rate_limit_per_minute=6000,
        demo_rate_limit_burst=6000,
        demo_login_rate_per_minute=1000,
        demo_login_rate_burst=1000,
    )


@contextmanager
def started(settings: Settings, mode: str = "demo") -> Iterator[TestClient]:
    from itsm.main import create_app

    previous = os.environ.get(RELEASE_MODE_ENV)
    os.environ[RELEASE_MODE_ENV] = mode
    client: TestClient | None = None
    try:
        client = TestClient(create_app(settings))
        client.__enter__()
    finally:
        if previous is None:
            os.environ.pop(RELEASE_MODE_ENV, None)
        else:
            os.environ[RELEASE_MODE_ENV] = previous
    try:
        yield client
    finally:
        client.__exit__(None, None, None)


def variant(base: Settings, **overrides: object) -> Settings:
    """A copy of the seeded installation settings with limit knobs applied."""
    return base.model_copy(update=overrides)


def migrate_and_seed(settings: Settings) -> None:
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            assert seed(session, settings, "demo.owner", INSTALLER_PASSWORD)["mode"] == "demo"
    finally:
        engine.dispose()


def visitor_login(client: TestClient) -> Response:
    return client.post(f"{API}/auth/login", json=VISITOR, headers={"Origin": ORIGIN})


def visitor_headers(client: TestClient) -> dict[str, str]:
    response = visitor_login(client)
    assert response.status_code == 200, response.text
    return {"Origin": ORIGIN, "X-CSRF-Token": str(response.json()["csrfToken"])}


def assert_limited(response: Response, status: int, code: str, *, retryable: bool = True) -> None:
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code
    if retryable:
        assert int(response.headers["retry-after"]) >= 1


def first_asset(client: TestClient, headers: dict[str, str]) -> str:
    listed = client.get(f"{API}/assets?limit=1", headers=headers)
    assert listed.status_code == 200, listed.text
    return str(listed.json()["items"][0]["id"])


def upload(
    client: TestClient, headers: dict[str, str], asset_id: str, data: bytes, name: str
) -> Response:
    return client.post(
        f"{API}/assets/{asset_id}/attachments",
        params={"filename": name, "category": "document"},
        content=data,
        headers={**headers, "Content-Type": "application/pdf"},
    )


@pytest.fixture(scope="module")
def demo_base(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    directory = tmp_path_factory.mktemp("demo-limits")
    settings = demo_settings(directory)
    migrate_and_seed(settings)
    return settings


def test_request_rate_limit_returns_429_after_the_burst(
    demo_base: Settings, tmp_path: Path
) -> None:
    settings = variant(
        demo_base,
        attachment_storage_path=tmp_path / "blobs",
        demo_rate_limit_per_minute=4,
        demo_rate_limit_burst=3,
    )
    with started(settings) as client:
        for _ in range(3):
            assert client.get(f"{API}/health/live").status_code == 200
        assert_limited(client.get(f"{API}/health/live"), 429, "rate_limited")


def test_default_request_budget_accepts_normal_shell_boot(demo_base: Settings) -> None:
    settings = variant(
        demo_base,
        demo_rate_limit_per_minute=Settings.model_fields["demo_rate_limit_per_minute"].default,
        demo_rate_limit_burst=Settings.model_fields["demo_rate_limit_burst"].default,
    )
    with started(settings) as client:
        for _ in range(35):
            response = client.get(f"{API}/health/live")
            assert response.status_code == 200, response.text


def test_login_attempts_have_a_stricter_bucket(demo_base: Settings, tmp_path: Path) -> None:
    settings = variant(
        demo_base,
        attachment_storage_path=tmp_path / "blobs",
        demo_login_rate_per_minute=2,
        demo_login_rate_burst=1,
    )
    with started(settings) as client:
        wrong = client.post(
            f"{API}/auth/login",
            json={"username": "admin", "password": "not-the-password"},
            headers={"Origin": ORIGIN},
        )
        assert wrong.status_code == 401, wrong.text
        repeated = client.post(f"{API}/auth/login", json=VISITOR, headers={"Origin": ORIGIN})
        assert repeated.status_code == 429, repeated.text
        assert repeated.json()["error"]["code"] == "login_rate_limited"
        assert int(repeated.headers["retry-after"]) >= 1


def test_oversized_request_body_is_rejected_before_the_route_runs(
    demo_base: Settings, tmp_path: Path
) -> None:
    settings = variant(
        demo_base,
        attachment_storage_path=tmp_path / "blobs",
        demo_max_request_body_bytes=2048,
    )
    with started(settings) as client:
        headers = visitor_headers(client)
        oversized = client.post(
            f"{API}/assets",
            content=b"x" * 4096,
            headers={**headers, "Content-Type": "application/json"},
        )
        assert_limited(oversized, 413, "payload_too_large", retryable=False)
        assert client.get(f"{API}/assets?limit=1", headers=headers).status_code == 200


def test_attachments_keep_their_own_body_limit(demo_base: Settings, tmp_path: Path) -> None:
    settings = variant(
        demo_base,
        attachment_storage_path=tmp_path / "blobs",
        demo_max_request_body_bytes=512,
        demo_attachment_max_bytes=4096,
        attachment_max_bytes=10 * 1024 * 1024,
    )
    with started(settings) as client:
        headers = visitor_headers(client)
        asset_id = first_asset(client, headers)
        accepted = upload(client, headers, asset_id, SAMPLE_PDF, "ficha.pdf")
        assert accepted.status_code == 201, accepted.text
        oversized = upload(client, headers, asset_id, SAMPLE_PDF * 40, "grande.pdf")
        assert_limited(oversized, 413, "payload_too_large", retryable=False)


def test_attachment_storage_quota_is_shared_and_bounded(
    demo_base: Settings, tmp_path: Path
) -> None:
    settings = variant(
        demo_settings(tmp_path),
        demo_max_request_body_bytes=4096,
        demo_attachment_max_bytes=4096,
        demo_attachment_quota_bytes=1200,
    )
    migrate_and_seed(settings)
    with started(settings) as client:
        headers = visitor_headers(client)
        asset_id = first_asset(client, headers)
        assert upload(client, headers, asset_id, PADDED_PDF, "uno.pdf").status_code == 201
        over_quota = upload(client, headers, asset_id, PADDED_PDF, "dos.pdf")
        assert_limited(over_quota, 413, "storage_quota_exceeded")

        listed = client.get(f"{API}/assets/{asset_id}/attachments", headers=headers)
        assert listed.status_code == 200
        assert [item["filename"] for item in listed.json()["items"]] == ["uno.pdf"]


def test_active_sessions_are_capped_and_the_oldest_is_evicted(tmp_path: Path) -> None:
    settings = demo_settings(tmp_path)
    settings = variant(settings, demo_max_active_sessions=2)
    migrate_and_seed(settings)
    with started(settings) as client:
        cookies: list[str] = []
        for _ in range(3):
            response = client.post(
                f"{API}/auth/login",
                json=VISITOR,
                headers={"Origin": ORIGIN},
            )
            assert response.status_code == 200, response.text
            cookies.append(response.cookies[settings.auth_cookie_name])

        oldest = client.get(
            f"{API}/auth/me",
            headers={"Cookie": f"{settings.auth_cookie_name}={cookies[0]}"},
        )
        assert oldest.status_code == 401

        newest = client.get(
            f"{API}/auth/me",
            headers={"Cookie": f"{settings.auth_cookie_name}={cookies[-1]}"},
        )
        assert newest.status_code == 200, newest.text

        engine = create_engine_from_settings(settings)
        try:
            with Session(engine) as session:
                active = session.execute(
                    text("SELECT COUNT(*) FROM identity_sessions WHERE revoked_at IS NULL")
                ).scalar_one()
        finally:
            engine.dispose()
        assert active == 2


def test_concurrent_requests_are_bounded(tmp_path: Path) -> None:
    settings = variant(demo_settings(tmp_path), demo_max_in_flight=1)
    limits = DemoLimits(settings)
    assert limits.acquire_slot() is True
    assert limits.acquire_slot() is False
    limits.release_slot()
    assert limits.acquire_slot() is True
    limits.release_slot()


def test_forwarded_for_is_only_trusted_behind_a_trusted_proxy() -> None:
    headers = {"x-forwarded-for": "203.0.113.9, 10.0.0.7"}
    assert client_key(trusted_proxy=False, headers=headers, client_host="127.0.0.1") == "127.0.0.1"
    assert client_key(trusted_proxy=True, headers=headers, client_host="127.0.0.1") == "10.0.0.7"


def test_limits_are_constructed_only_in_demo_mode(
    demo_base: Settings, settings_factory: Callable[..., Settings]
) -> None:
    from itsm.demo.restrictions import build_demo_restrictions
    from itsm.release_mode import capabilities_for

    for mode in ("prod", "dev"):
        assert build_demo_restrictions(demo_base, capabilities_for(mode)) is None

    development = settings_factory()
    applied = run_migrations(development)
    assert applied.returncode == 0, applied.stderr
    with started(development, "dev") as client:
        assert client.app.state.demo_limits is None
        assert client.app.state.demo_restrictions is None
        assert client.get(f"{API}/health/live").status_code == 200
