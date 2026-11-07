"""Business quota ledger: durable policies, admission, settlement and reports."""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.agent_integrations.models import AgentDailyUsage, AgentProvider
from itsm.ai_usage.models import AiUsageReservation
from itsm.ai_usage.service import (
    AiUsageService,
    QuotaExceeded,
    UsageEvidence,
)
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.identity.models import IdentityAuditEvent
from itsm.identity.service import (
    BootstrapRefused,
    IdentityService,
    PermissionDenied,
    Principal,
    ValidationFailed,
)
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session
from tests.conftest import (
    ADMIN_NAME,
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    run_migrations,
)

USER_USERNAME = "quota.user"
USER_NAME = "Quota User"
USER_PASSWORD = "ordinary-password-2026"


@dataclass
class Clock:
    current: datetime

    def __call__(self) -> datetime:
        return self.current

    def set(self, value: datetime) -> None:
        self.current = value


@dataclass
class Harness:
    settings: Settings
    engine: Engine
    clock: Clock
    service: AiUsageService
    admin: Principal
    user: Principal

    def new_service(self) -> AiUsageService:
        engine = create_engine_from_settings(self.settings)
        return AiUsageService(
            self.settings,
            create_session_factory(engine),
            now=self.clock,
        )

    def with_session(self) -> Session:
        return Session(self.engine)


def _principals(settings: Settings, engine: Engine) -> tuple[Principal, Principal]:
    with Session(engine) as session:
        identities = IdentityService(session, settings)
        with contextlib.suppress(BootstrapRefused):
            identities.bootstrap_superadmin(ADMIN_USERNAME, ADMIN_NAME, ADMIN_PASSWORD)
        admin = identities.login(ADMIN_USERNAME, ADMIN_PASSWORD).principal
        identities.create_user(
            admin,
            username=USER_USERNAME,
            name=USER_NAME,
            role_id="user",
            password=USER_PASSWORD,
        )
        user = identities.login(USER_USERNAME, USER_PASSWORD).principal
    return admin, user


@pytest.fixture
def harness(
    settings_factory: Callable[..., Settings],
    tmp_path_factory: pytest.TempPathFactory,
) -> Callable[..., Harness]:
    def make(**overrides: Any) -> Harness:
        home = tmp_path_factory.mktemp("quota-harness")
        (home / "tasks").mkdir()
        overrides.setdefault("database_url", f"sqlite:///{home / 'app.db'}")
        overrides.setdefault("task_sqlite_path", home / "tasks" / "huey.db")
        settings = settings_factory(**overrides)
        applied = run_migrations(settings)
        assert applied.returncode == 0, applied.stderr
        engine = create_engine_from_settings(settings)
        clock = Clock(datetime(2026, 3, 1, 12, 0, tzinfo=UTC))
        service = AiUsageService(
            settings,
            create_session_factory(engine),
            now=clock,
        )
        admin, user = _principals(settings, engine)
        return Harness(
            settings=settings,
            engine=engine,
            clock=clock,
            service=service,
            admin=admin,
            user=user,
        )

    return make


def _reserve(
    service: AiUsageService,
    actor_id: str,
    *,
    funding: str = "company",
    tokens: int = 10,
    **kwargs: Any,
) -> Any:
    kwargs.setdefault("provider_id", None)
    kwargs.setdefault("provider_scope", None)
    kwargs.setdefault("provider_name", None)
    kwargs.setdefault("model", None)
    kwargs.setdefault("engine", None)
    return service.reserve(
        actor_id,
        funding=funding,
        reserved_tokens=tokens,
        **kwargs,
    )


def _measured(total: int, **overrides: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "totalTokens": total,
        "precision": "measured",
        "source": "provider",
    }
    evidence.update(overrides)
    return evidence


def _company(service: AiUsageService, actor_id: str) -> dict[str, Any]:
    return service.me(actor_id)["funding"]["company"]


def test_two_independent_sessions_never_over_admit(harness: Callable[..., Harness]) -> None:
    h = harness(agent_daily_token_budget=100)
    barrier = threading.Barrier(2)
    outcomes: list[Any] = []
    lock = threading.Lock()

    def attempt(service: AiUsageService) -> None:
        barrier.wait(timeout=10)
        try:
            grant = _reserve(service, h.user.actor_id, tokens=60)
        except QuotaExceeded as exc:
            outcome: Any = exc
        else:
            outcome = grant
        with lock:
            outcomes.append(outcome)

    services = [h.new_service(), h.new_service()]
    threads = [threading.Thread(target=attempt, args=(service,)) for service in services]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not any(thread.is_alive() for thread in threads)
    grants = [item for item in outcomes if not isinstance(item, Exception)]
    denials = [item for item in outcomes if isinstance(item, QuotaExceeded)]
    assert len(grants) == 1, outcomes
    assert len(denials) == 1, outcomes
    assert denials[0].remaining_tokens == 0
    assert _company(h.service, h.user.actor_id)["reservedTokens"] == 60


def test_two_users_are_isolated(harness: Callable[..., Harness]) -> None:
    h = harness(agent_daily_token_budget=100)
    _reserve(h.service, h.user.actor_id, tokens=100)
    grant = _reserve(h.service, h.admin.actor_id, tokens=100)
    assert grant.remaining_tokens == 0
    assert _company(h.service, h.user.actor_id)["reservedTokens"] == 100
    assert _company(h.service, h.admin.actor_id)["reservedTokens"] == 100


def test_limited_default_zero_override_and_unlimited_inheritance(
    harness: Callable[..., Harness],
) -> None:
    unlimited = harness(agent_daily_token_budget=0)
    assert unlimited.service.policy(unlimited.admin)["companyLimitSource"] == "legacy_config"
    assert unlimited.service.policy(unlimited.admin)["companyDailyLimit"] is None
    _reserve(unlimited.service, unlimited.user.actor_id, tokens=10_000_000)

    h = harness(agent_daily_token_budget=100)
    h.service.set_override(h.admin, h.user.actor_id, daily_limit=0)
    with pytest.raises(QuotaExceeded):
        _reserve(h.service, h.user.actor_id, tokens=1)
    assert _company(h.service, h.user.actor_id)["availableTokens"] == 0

    h.service.set_override(h.admin, h.user.actor_id, daily_limit=None)
    unlimited_grant = _reserve(h.service, h.user.actor_id, tokens=1_000_000)
    h.service.release(
        unlimited_grant.reservation_id,
        reason="test reset before finite override",
        trusted_no_upstream=True,
    )

    h.service.set_override(h.admin, h.user.actor_id, daily_limit=5)
    _reserve(h.service, h.user.actor_id, tokens=5)
    with pytest.raises(QuotaExceeded):
        _reserve(h.service, h.user.actor_id, tokens=1)

    # Another person still inherits the configured company default.
    _reserve(h.service, h.admin.actor_id, tokens=100)
    h.service.delete_override(h.admin, h.user.actor_id)
    with pytest.raises(QuotaExceeded):
        _reserve(h.service, h.admin.actor_id, tokens=1)


def test_company_and_personal_funds_are_separate(harness: Callable[..., Harness]) -> None:
    h = harness(agent_daily_token_budget=10)
    _reserve(h.service, h.user.actor_id, tokens=10)
    with pytest.raises(QuotaExceeded):
        _reserve(h.service, h.user.actor_id, tokens=1)

    personal = _reserve(h.service, h.user.actor_id, funding="personal", tokens=1_000_000)
    assert personal.funding == "personal"
    summary = h.service.me(h.user.actor_id)
    assert summary["funding"]["company"]["reservedTokens"] == 10
    assert summary["funding"]["company"]["consumedTokens"] == 0
    assert summary["funding"]["personal"]["reservedTokens"] == 1_000_000
    assert summary["funding"]["personal"]["limitTokens"] is None
    assert summary["funding"]["personal"]["unlimited"] is True

    # A personal hold never becomes company consumption.
    h.service.settle(personal.reservation_id, _measured(4))
    summary = h.service.me(h.user.actor_id)
    assert summary["funding"]["personal"]["consumedTokens"] == 4
    assert summary["funding"]["company"]["consumedTokens"] == 0


def test_reserve_and_settle_are_idempotent_across_restart(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=100)
    first = _reserve(h.service, h.user.actor_id, tokens=50, idempotency_key="call-1")
    replay = _reserve(h.service, h.user.actor_id, tokens=50, idempotency_key="call-1")
    assert replay.replayed is True
    assert replay.reservation_id == first.reservation_id
    assert _company(h.service, h.user.actor_id)["reservedTokens"] == 50

    settled = h.service.settle(first.reservation_id, _measured(42))
    assert settled.as_dict()["state"] == "settled"
    assert settled.tokens == 42

    restarted = h.new_service()
    again = restarted.settle(first.reservation_id, _measured(42))
    assert again.idempotent is True
    assert again.tokens == 42
    summary = restarted.me(h.user.actor_id)["funding"]["company"]
    assert summary["consumedTokens"] == 42
    assert summary["reservedTokens"] == 0


def test_unknown_outcome_holds_until_explicit_release(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=100)
    grant = _reserve(h.service, h.user.actor_id, tokens=50)

    unknown = h.service.settle(
        grant.reservation_id,
        {"precision": "unavailable", "source": "none"},
    )
    assert unknown.unresolved is True
    assert unknown.tokens is None
    summary = _company(h.service, h.user.actor_id)
    assert summary["reservedTokens"] == 50
    assert summary["consumedTokens"] == 0
    pending = h.service.pending_admin(h.admin)
    assert pending["items"][0]["state"] == "unresolved"
    assert pending["items"][0]["lastEvidence"]["precision"] == "unavailable"

    with pytest.raises(ValidationFailed):
        h.service.release(grant.reservation_id, reason="no upstream")
    with pytest.raises(ValidationFailed):
        h.service.release(
            grant.reservation_id,
            reason=" ",
            trusted_no_upstream=True,
        )

    released = h.service.release(
        grant.reservation_id,
        reason="provider dispatch failed before any request",
        trusted_no_upstream=True,
    )
    assert released.as_dict()["state"] == "released"
    summary = _company(h.service, h.user.actor_id)
    assert summary["reservedTokens"] == 0
    assert summary["consumedTokens"] == 0

    again = h.service.release(
        grant.reservation_id,
        reason="provider dispatch failed before any request",
        trusted_no_upstream=True,
    )
    assert again.idempotent is True
    assert h.service.pending_admin(h.admin)["items"] == []


def test_admin_resolution_is_authorized_audited_and_requires_evidence(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=100)
    grant = _reserve(h.service, h.user.actor_id, tokens=30)
    h.service.settle(grant.reservation_id, {"precision": "unavailable", "source": "none"})

    with pytest.raises(PermissionDenied):
        h.service.report(h.user)
    with pytest.raises(PermissionDenied):
        h.service.update_policy(h.user, company_daily_limit=1)
    machine = Principal(
        actor_id="machine-agent",
        kind="machine",
        username="machine-agent",
        display_name="Machine Agent",
        role_id="superadmin",
        delegated_by=h.admin.actor_id,
    )
    with pytest.raises(PermissionDenied):
        h.service.policy(machine)
    with pytest.raises(PermissionDenied):
        h.service.report(machine)
    with pytest.raises(PermissionDenied):
        h.service.resolve(
            h.user,
            grant.reservation_id,
            outcome="settled",
            evidence=_measured(1),
        )

    with pytest.raises(ValidationFailed):
        h.service.resolve(
            h.admin,
            grant.reservation_id,
            outcome="settled",
            evidence={"precision": "unavailable", "source": "none"},
        )
    with pytest.raises(ValidationFailed):
        h.service.resolve(h.admin, grant.reservation_id, outcome="released")

    resolved = h.service.resolve(
        h.admin,
        grant.reservation_id,
        outcome="settled",
        evidence=_measured(25),
        reason="provider invoice reconciled by owner",
    )
    assert resolved.tokens == 25
    summary = _company(h.service, h.user.actor_id)
    assert summary["consumedTokens"] == 25
    assert summary["reservedTokens"] == 0

    with Session(h.engine) as session:
        actions = session.execute(
            select(IdentityAuditEvent.action, IdentityAuditEvent.outcome)
        ).all()
    assert ("ai.usage.reservation.resolve", "success") in actions
    assert any(outcome == "denied" for _, outcome in actions)


def test_parent_only_child_reserve_inherits_actor_and_funding(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=100)
    parent = _reserve(
        h.service,
        h.user.actor_id,
        funding="personal",
        tokens=5,
        run_id="run-parent-only",
        provider_id="provider-1",
        provider_scope="personal",
        provider_name="Personal",
        model="m1",
        engine="hermes",
    )
    h.service.release(
        parent.reservation_id,
        reason="sentinel resolved before first paid call",
        trusted_no_upstream=True,
    )
    child = h.service.reserve(
        None,
        parent_reservation_id=parent.reservation_id,
        reserved_tokens=3,
    )
    assert child.funding == "personal"
    assert child.run_id == parent.run_id
    assert child.period_day == parent.period_day
    with Session(h.engine) as session:
        stored = session.get(AiUsageReservation, child.reservation_id)
        assert stored is not None
        assert stored.actor_id == h.user.actor_id
        assert stored.provider_id == "provider-1"
        assert stored.model == "m1"
        assert stored.engine == "hermes"


def test_original_period_inheritance_for_run_children(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=100)
    h.clock.set(datetime(2026, 3, 1, 23, 50, tzinfo=UTC))
    sentinel = _reserve(
        h.service,
        h.user.actor_id,
        tokens=1,
        run_id="run-1",
        provider_id="provider-1",
        provider_scope="global",
        provider_name="Acme AI",
        model="acme-large",
        engine="opencode",
        idempotency_key="run-1",
    )
    assert sentinel.period_day == "2026-03-01"

    child = _reserve(
        h.service,
        h.user.actor_id,
        tokens=60,
        run_id="run-1",
        parent_reservation_id=sentinel.reservation_id,
        provider_id="provider-1",
        provider_scope="global",
        provider_name="Acme AI",
        model="acme-large",
        engine="opencode",
        idempotency_key="call-1",
    )
    assert (child.period_day, child.timezone) == (sentinel.period_day, sentinel.timezone)
    with pytest.raises(ValidationFailed):
        _reserve(
            h.service,
            h.user.actor_id,
            tokens=1,
            run_id="run-1",
            parent_reservation_id=sentinel.reservation_id,
            provider_id="provider-2",
        )

    h.clock.set(datetime(2026, 3, 2, 0, 10, tzinfo=UTC))
    settled = h.service.settle(child.reservation_id, _measured(55))
    assert settled.period_day == "2026-03-01"
    today = _company(h.service, h.user.actor_id)
    assert h.service.me(h.user.actor_id)["periodDay"] == "2026-03-02"
    assert today["consumedTokens"] == 0
    # The new day starts fresh while the settled call stays in its original day.
    _reserve(h.service, h.user.actor_id, tokens=100)
    report = h.service.report(
        h.admin,
        day_from="2026-03-01",
        day_to="2026-03-01",
        group_by=("day",),
    )
    assert report["totals"]["settledTokens"] == 55
    released = h.service.release(
        sentinel.reservation_id,
        reason="first paid call established upstream work",
        trusted_no_upstream=True,
    )
    assert released.as_dict()["state"] == "released"


def test_timezone_change_is_pending_until_safe_boundary(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=100)
    h.clock.set(datetime(2026, 3, 1, 23, 30, tzinfo=UTC))
    _reserve(h.service, h.user.actor_id, tokens=100)

    policy = h.service.update_policy(h.admin, timezone="Pacific/Kiritimati")
    assert policy["timezone"] == "UTC"
    assert policy["pendingTimezone"] == "Pacific/Kiritimati"
    assert policy["pendingEffectiveDay"] == "2026-03-02"

    summary = h.service.me(h.user.actor_id)
    assert summary["timezone"] == "UTC"
    assert summary["periodDay"] == "2026-03-01"
    assert summary["funding"]["company"]["availableTokens"] == 0
    with pytest.raises(QuotaExceeded):
        _reserve(h.service, h.user.actor_id, tokens=1)

    h.clock.set(datetime(2026, 3, 2, 0, 10, tzinfo=UTC))
    summary = h.service.me(h.user.actor_id)
    assert summary["timezone"] == "Pacific/Kiritimati"
    assert summary["pendingTimezone"] is None
    assert summary["periodDay"] == "2026-03-02"
    assert summary["funding"]["company"]["availableTokens"] == 100
    _reserve(h.service, h.user.actor_id, tokens=100)


def test_iana_day_key_respects_dst_transitions(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=100)
    h.clock.set(datetime(2026, 3, 8, 6, 30, tzinfo=UTC))
    h.service.update_policy(h.admin, timezone="America/New_York")

    h.clock.set(datetime(2026, 3, 9, 5, 0, tzinfo=UTC))
    assert h.service.me(h.user.actor_id)["periodDay"] == "2026-03-09"
    _reserve(h.service, h.user.actor_id, tokens=40)
    h.clock.set(datetime(2026, 3, 9, 15, 0, tzinfo=UTC))
    assert h.service.me(h.user.actor_id)["periodDay"] == "2026-03-09"
    assert _company(h.service, h.user.actor_id)["reservedTokens"] == 40
    h.clock.set(datetime(2026, 3, 10, 4, 30, tzinfo=UTC))
    assert h.service.me(h.user.actor_id)["periodDay"] == "2026-03-10"
    assert _company(h.service, h.user.actor_id)["reservedTokens"] == 0

    fall = harness(agent_daily_token_budget=100)
    fall.clock.set(datetime(2026, 10, 31, 12, 0, tzinfo=UTC))
    fall.service.update_policy(fall.admin, timezone="America/New_York")
    fall.clock.set(datetime(2026, 11, 1, 4, 30, tzinfo=UTC))
    assert fall.service.me(fall.user.actor_id)["periodDay"] == "2026-11-01"
    _reserve(fall.service, fall.user.actor_id, tokens=10)
    fall.clock.set(datetime(2026, 11, 1, 6, 30, tzinfo=UTC))
    assert fall.service.me(fall.user.actor_id)["periodDay"] == "2026-11-01"
    _reserve(fall.service, fall.user.actor_id, tokens=10)
    fall.clock.set(datetime(2026, 11, 2, 5, 30, tzinfo=UTC))
    assert fall.service.me(fall.user.actor_id)["periodDay"] == "2026-11-02"


def test_legacy_daily_usage_is_visible_and_carried_as_company(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=100)
    with Session(h.engine) as session:
        session.add(
            AgentDailyUsage(
                id=f"2026-03-01:{h.user.actor_id}",
                owner_id=h.user.actor_id,
                day="2026-03-01",
                measured_tokens=30,
                reported_tokens=10,
            )
        )
        session.add(
            AgentDailyUsage(
                id=f"2026-02-28:{h.user.actor_id}",
                owner_id=h.user.actor_id,
                day="2026-02-28",
                measured_tokens=99,
                reported_tokens=0,
            )
        )
        session.commit()

    summary = h.service.me(h.user.actor_id)
    assert summary["funding"]["company"]["legacyTokens"] == 40
    assert summary["funding"]["company"]["availableTokens"] == 60
    assert summary["funding"]["personal"]["legacyTokens"] == 0

    report = h.service.report(h.admin)
    legacy = [item for item in report["items"] if item["legacy"]]
    assert len(legacy) == 2
    row = next(item for item in legacy if item["day"] == "2026-03-01")
    assert row["userId"] == h.user.actor_id
    assert row["funding"] == "company"
    assert row["state"] == "legacy"
    assert row["providerId"] is None
    assert row["model"] is None
    assert row["precision"] == "unavailable"
    assert row["source"] == "legacy"
    assert row["settledTokens"] == 40
    assert row["legacyMeasuredTokens"] == 30
    assert row["legacyReportedTokens"] == 10
    assert report["totals"]["legacyTokens"] == 139


def test_legacy_carry_overlaps_utc_days_across_dst_period(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=100)
    h.clock.set(datetime(2026, 10, 31, 12, 0, tzinfo=UTC))
    h.service.update_policy(h.admin, timezone="America/New_York")
    h.clock.set(datetime(2026, 11, 1, 4, 30, tzinfo=UTC))

    summary = h.service.me(h.user.actor_id)
    assert summary["periodDay"] == "2026-11-01"
    assert summary["timezone"] == "America/New_York"

    with Session(h.engine) as session:
        for day, measured in (
            ("2026-10-31", 99),
            ("2026-11-01", 10),
            ("2026-11-02", 20),
        ):
            session.add(
                AgentDailyUsage(
                    id=f"{day}:{h.user.actor_id}",
                    owner_id=h.user.actor_id,
                    day=day,
                    measured_tokens=measured,
                    reported_tokens=0,
                )
            )
        session.commit()

    summary = h.service.me(h.user.actor_id)
    assert summary["funding"]["company"]["legacyTokens"] == 30
    assert summary["funding"]["company"]["availableTokens"] == 70
    with pytest.raises(QuotaExceeded):
        _reserve(h.service, h.user.actor_id, tokens=71)
    _reserve(h.service, h.user.actor_id, tokens=70)

    report = h.service.report(h.admin)
    legacy = [item for item in report["items"] if item["legacy"]]
    assert len(legacy) == 3
    assert {item["day"] for item in legacy} == {
        "2026-10-31",
        "2026-11-01",
        "2026-11-02",
    }
    assert all(item["state"] == "legacy" for item in legacy)
    assert report["totals"]["legacyTokens"] == 129


def test_report_groups_filters_and_preserves_nullable_precision(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=10_000)
    provider = _reserve(
        h.service,
        h.user.actor_id,
        tokens=200,
        provider_id="provider-1",
        provider_scope="global",
        provider_name="Acme AI",
        model="acme-large",
        engine="opencode",
    )
    h.service.settle(
        provider.reservation_id,
        _measured(
            100,
            inputTokens=80,
            outputTokens=20,
            cacheReadTokens=50,
            cacheIncludedInInput=True,
        ),
    )
    engine_call = _reserve(
        h.service,
        h.user.actor_id,
        funding="personal",
        tokens=100,
        provider_id="provider-2",
        provider_scope="personal",
        provider_name="Local",
        model="local-model",
        engine="hermes",
    )
    h.service.settle(
        engine_call.reservation_id,
        {
            "inputTokens": 10,
            "outputTokens": 5,
            "cacheReadTokens": 2,
            "cacheWriteTokens": 3,
            "reasoningTokens": 4,
            "cacheIncludedInInput": False,
            "reasoningIncludedInOutput": False,
            "precision": "estimated",
            "source": "engine",
            "estimationMethod": "chars/4-v1",
        },
    )
    unresolved = _reserve(
        h.service,
        h.user.actor_id,
        tokens=7,
        provider_id="provider-1",
        provider_scope="global",
        provider_name="Acme AI",
        model="acme-large",
        engine="opencode",
    )
    h.service.settle(unresolved.reservation_id, {"precision": "unavailable", "source": "none"})

    report = h.service.report(
        h.admin,
        group_by=("user", "provider", "model", "engine", "funding"),
    )
    items = report["items"]
    measured = [
        item for item in items if item["precision"] == "measured" and item["state"] == "settled"
    ]
    assert len(measured) == 1
    assert measured[0]["settledTokens"] == 100
    assert measured[0]["inputTokens"] == 80
    assert measured[0]["cacheReadTokens"] == 50
    assert measured[0]["cacheIncludedInInput"] is True
    assert measured[0]["providerName"] == "Acme AI"

    estimated = [item for item in items if item["precision"] == "estimated"]
    assert len(estimated) == 1
    assert estimated[0]["settledTokens"] == 24
    assert estimated[0]["estimationMethod"] == "chars/4-v1"
    assert estimated[0]["reasoningTokens"] == 4
    assert estimated[0]["funding"] == "personal"

    pending = [item for item in items if item["state"] == "unresolved"]
    assert len(pending) == 1
    assert pending[0]["reservedTokens"] == 7
    assert pending[0]["settledTokens"] == 0
    assert pending[0]["inputTokens"] is None
    assert pending[0]["outputTokens"] is None
    assert report["precision"]["measured"] == 100
    assert report["precision"]["estimated"] == 24

    filtered = h.service.report(h.admin, provider_id="provider-2")
    assert {item["providerId"] for item in filtered["items"]} == {"provider-2"}
    assert filtered["totals"]["settledTokens"] == 24

    with Session(h.engine) as session:
        row = session.get(AgentProvider, "provider-1")
        assert row is None
    # Receipts retain the provider snapshot even after the provider disappears.
    assert measured[0]["providerScope"] == "global"


def test_provider_snapshot_survives_provider_deletion(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=1000)
    with Session(h.engine) as session:
        session.add(
            AgentProvider(
                id="provider-1",
                name="Acme AI",
                scope="global",
                base_url="https://ai.example.test",
                models=["acme-large"],
                enabled=True,
            )
        )
        session.commit()
    grant = _reserve(
        h.service,
        h.user.actor_id,
        tokens=50,
        provider_id="provider-1",
        provider_scope="global",
        provider_name="Acme AI",
        model="acme-large",
        engine="opencode",
    )
    h.service.settle(grant.reservation_id, _measured(20))
    with Session(h.engine) as session:
        session.execute(delete(AgentProvider).where(AgentProvider.id == "provider-1"))
        session.commit()

    report = h.service.report(h.admin, provider_id="provider-1")
    assert report["totals"]["settledTokens"] == 20
    assert report["items"][0]["providerName"] == "Acme AI"
    assert report["items"][0]["providerScope"] == "global"


def test_policy_reduction_never_hides_consumption(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=100)
    grant = _reserve(h.service, h.user.actor_id, tokens=80)
    h.service.settle(grant.reservation_id, _measured(80))
    policy = h.service.update_policy(h.admin, company_daily_limit=20)
    assert policy["companyDailyLimit"] == 20

    summary = _company(h.service, h.user.actor_id)
    assert summary["consumedTokens"] == 80
    assert summary["limitTokens"] == 20
    assert summary["availableTokens"] == 0
    with pytest.raises(QuotaExceeded):
        _reserve(h.service, h.user.actor_id, tokens=1)
    report = h.service.report(h.admin)
    assert report["totals"]["settledTokens"] == 80


def test_evidence_requires_explicit_inclusion_for_derived_totals(
    harness: Callable[..., Harness],
) -> None:
    evidence = UsageEvidence.from_mapping(
        {
            "inputTokens": 10,
            "outputTokens": 5,
            "cacheReadTokens": 2,
            "cacheWriteTokens": 3,
            "reasoningTokens": 4,
            "cacheIncludedInInput": False,
            "reasoningIncludedInOutput": False,
            "precision": "measured",
            "source": "provider",
        }
    )
    assert evidence.total() == 24

    # Total is authoritative: cache information never gets added twice.
    authoritative = UsageEvidence.from_mapping(
        _measured(
            100, inputTokens=80, outputTokens=20, cacheReadTokens=50, cacheIncludedInInput=True
        )
    )
    assert authoritative.total() == 100

    withheld = UsageEvidence.from_mapping(
        {
            "inputTokens": 10,
            "outputTokens": 5,
            "cacheReadTokens": 2,
            "precision": "measured",
            "source": "provider",
        }
    )
    assert withheld.total() is None
    assert (
        UsageEvidence.from_mapping({"precision": "unavailable", "source": "none"}).total() is None
    )


def test_me_and_admin_api_payloads_and_forbidden_effects(
    harness: Callable[..., Harness],
    signed_in_client: Callable[..., tuple[TestClient, dict[str, str]]],
) -> None:
    h = harness(agent_daily_token_budget=100)
    client, headers = signed_in_client(h.settings)

    me = client.get(f"{h.settings.api_prefix}/agent/usage/me")
    assert me.status_code == 200
    body = me.json()
    assert body["funding"]["company"]["limitTokens"] == 100
    assert body["funding"]["personal"]["unlimited"] is True

    policy = client.get(f"{h.settings.api_prefix}/agent/usage/policy")
    assert policy.status_code == 200
    assert policy.json()["companyDailyLimit"] == 100
    updated = client.put(
        f"{h.settings.api_prefix}/agent/usage/policy",
        json={"companyDailyLimit": 100, "timezone": "Europe/Madrid"},
        headers=headers,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["companyDailyLimit"] == 100
    assert updated.json()["timezone"] == "UTC"
    assert updated.json()["pendingTimezone"] == "Europe/Madrid"

    override = client.put(
        f"{h.settings.api_prefix}/agent/usage/overrides/{h.user.actor_id}",
        json={"dailyLimit": 5},
        headers=headers,
    )
    assert override.status_code == 200, override.text
    assert override.json()["overrides"][0]["scope"] == "company"
    assert override.json()["overrides"][0]["dailyLimit"] == 5
    removed = client.delete(
        f"{h.settings.api_prefix}/agent/usage/overrides/{h.user.actor_id}",
        headers=headers,
    )
    assert removed.status_code == 200
    assert removed.json()["overrides"] == []

    report = client.get(f"{h.settings.api_prefix}/agent/usage/report")
    assert report.status_code == 200
    assert "items" in report.json()

    no_public_reserve = client.post(f"{h.settings.api_prefix}/agent/usage/reservations")
    assert no_public_reserve.status_code in {404, 405}

    grant = _reserve(h.service, h.user.actor_id, tokens=5)
    assert client.get(f"{h.settings.api_prefix}/agent/usage/pending").status_code == 200

    with TestClient(client.app) as user_client:
        login = user_client.post(
            f"{h.settings.api_prefix}/auth/login",
            json={"username": USER_USERNAME, "password": USER_PASSWORD},
            headers={"Origin": h.settings.auth_origin},
        )
        assert login.status_code == 200, login.text
        user_headers = {
            "X-CSRF-Token": login.json()["csrfToken"],
            "Origin": h.settings.auth_origin,
        }
        assert user_client.get(f"{h.settings.api_prefix}/agent/usage/me").status_code == 200
        forbidden = user_client.get(f"{h.settings.api_prefix}/agent/usage/report")
        assert forbidden.status_code == 403
        forbidden_write = user_client.put(
            f"{h.settings.api_prefix}/agent/usage/policy",
            json={"companyDailyLimit": 1000},
            headers=user_headers,
        )
        assert forbidden_write.status_code == 403
        forbidden_resolve = user_client.post(
            f"{h.settings.api_prefix}/agent/usage/reservations/{grant.reservation_id}/resolve",
            json={"outcome": "released", "reason": "not allowed"},
            headers=user_headers,
        )
        assert forbidden_resolve.status_code == 403

    assert h.service.policy(h.admin)["companyDailyLimit"] == 100
    assert h.service.pending_admin(h.admin)["items"][0]["state"] == "pending"


def test_validation_rejects_invalid_policy_and_evidence(
    harness: Callable[..., Harness],
) -> None:
    h = harness(agent_daily_token_budget=100)
    with pytest.raises(ValidationFailed):
        h.service.update_policy(h.admin, company_daily_limit=-1)
    with pytest.raises(ValidationFailed):
        h.service.update_policy(h.admin, company_daily_limit=True)  # type: ignore[arg-type]
    with pytest.raises(ValidationFailed):
        h.service.update_policy(h.admin, timezone="Mars/Olympus")
    with pytest.raises(ValidationFailed):
        h.service.set_override(h.admin, "missing-user", daily_limit=5)
    with pytest.raises(ValidationFailed):
        _reserve(h.service, h.user.actor_id, funding="shared", tokens=1)
    with pytest.raises(ValidationFailed):
        _reserve(h.service, h.user.actor_id, tokens=0)
    personal = _reserve(h.service, h.user.actor_id, funding="personal", tokens=1)
    with pytest.raises(ValidationFailed):
        h.service.settle(
            personal.reservation_id,
            {"totalTokens": -1, "precision": "measured", "source": "provider"},
        )
