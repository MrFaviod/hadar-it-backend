"""ITSM-owned AI usage quota ledger.

Admission is a single conditional ``UPDATE`` on a durable per-actor/funding/day
counter, so independent processes and SQL sessions cannot over-admit. Settled
usage and unknown outcomes are separate terminal states; a failed provider call
never silently becomes zero usage.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import case, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from itsm.agent_integrations.models import AgentDailyUsage
from itsm.ai_usage.models import (
    COMPANY,
    PENDING,
    PERSONAL,
    POLICY_ID,
    RELEASED,
    SETTLED,
    UNRESOLVED,
    AiUsageBalance,
    AiUsageQuotaOverride,
    AiUsageQuotaPolicy,
    AiUsageReceipt,
    AiUsageReservation,
)
from itsm.config import Settings
from itsm.identity.clock import utcnow
from itsm.identity.models import Identity
from itsm.identity.service import (
    HUMAN_ACTOR_KIND,
    IdentityService,
    PermissionDenied,
    ValidationFailed,
)
from itsm.system.authorization import require_system_authority

PRECISIONS = ("measured", "estimated", "unavailable")
SOURCES = ("provider", "engine", "estimate", "none")
DEFAULT_GROUP_BY = ("user", "provider", "model", "engine", "funding", "day")
GROUPABLE = set(DEFAULT_GROUP_BY)
PROVIDER_SCOPES = ("global", "personal")
# Personal-funded work has no token limit at all; the legacy personal policy
# columns and override rows stay stored but are never consulted for admission.
PERSONAL_LIMIT_SOURCE = "record_only"
PERSONAL_LIMIT_NOT_APPLICABLE = "not_applicable"
PERMISSION = "system.providers"
_DAY_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class _Unset:
    def __repr__(self) -> str:
        return "UNSET"


UNSET = _Unset()


class QuotaExceeded(Exception):
    """Admission denied: no reservation exists and no provider work may start."""

    code = "quota_exceeded"

    def __init__(self, remaining_tokens: int = 0, *, period_day: str | None = None) -> None:
        super().__init__("daily AI usage quota exhausted")
        self.remaining_tokens = remaining_tokens
        self.period_day = period_day


class PersonalBudgetUnsupported(ValidationFailed):
    """Personal-funded work is record-only; a personal daily limit is not a contract."""

    code = "personal_budget_unsupported"

    def __init__(self, message: str = "personal daily token limits are not supported") -> None:
        super().__init__(message)


@dataclass(frozen=True)
class Period:
    day: str
    timezone: str
    pending_timezone: str | None
    pending_effective_day: str | None


@dataclass(frozen=True)
class LimitState:
    limit: int | None
    source: str


@dataclass(frozen=True)
class UsageEvidence:
    """Normalized evidence. Missing components are unknown, never zero."""

    total_tokens: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_read_tokens: int | None = None
    cache_write_tokens: int | None = None
    reasoning_tokens: int | None = None
    precision: str = "unavailable"
    source: str = "none"
    total_source: str | None = None
    estimation_method: str | None = None
    cache_included_in_input: bool | None = None
    reasoning_included_in_output: bool | None = None

    @classmethod
    def from_mapping(cls, evidence: Mapping[str, Any]) -> UsageEvidence:
        if not isinstance(evidence, Mapping):
            raise ValidationFailed("usage evidence must be an object")
        aliases = {
            "totalTokens": "total_tokens",
            "total_tokens": "total_tokens",
            "inputTokens": "input_tokens",
            "input_tokens": "input_tokens",
            "outputTokens": "output_tokens",
            "output_tokens": "output_tokens",
            "cacheReadTokens": "cache_read_tokens",
            "cache_read_tokens": "cache_read_tokens",
            "cacheWriteTokens": "cache_write_tokens",
            "cache_write_tokens": "cache_write_tokens",
            "reasoningTokens": "reasoning_tokens",
            "reasoning_tokens": "reasoning_tokens",
            "precision": "precision",
            "source": "source",
            "totalSource": "total_source",
            "total_source": "total_source",
            "estimationMethod": "estimation_method",
            "estimation_method": "estimation_method",
            "cacheIncludedInInput": "cache_included_in_input",
            "cache_included_in_input": "cache_included_in_input",
            "inputIncludesCache": "cache_included_in_input",
            "reasoningIncludedInOutput": "reasoning_included_in_output",
            "reasoning_included_in_output": "reasoning_included_in_output",
            "outputIncludesReasoning": "reasoning_included_in_output",
        }
        values: dict[str, Any] = {}
        for key, value in evidence.items():
            target = aliases.get(key)
            if target is None:
                raise ValidationFailed(f"unknown usage evidence field: {key}")
            if target in values and values[target] != value:
                raise ValidationFailed(f"conflicting usage evidence field: {target}")
            values[target] = value

        for field in ("total_tokens", "input_tokens", "output_tokens"):
            _validate_token_count(values.get(field), field)
        for field in ("cache_read_tokens", "cache_write_tokens", "reasoning_tokens"):
            _validate_token_count(values.get(field), field)
        precision = values.get("precision", "unavailable")
        if precision not in PRECISIONS:
            raise ValidationFailed("precision must be measured, estimated or unavailable")
        source = values.get("source", "none")
        if source not in SOURCES:
            raise ValidationFailed("source must be provider, engine, estimate or none")
        total_source = values.get("total_source")
        if total_source is not None and total_source not in ("provider", "derived"):
            raise ValidationFailed("totalSource must be provider or derived")
        method = values.get("estimation_method")
        if method is not None and (not isinstance(method, str) or not method.strip()):
            raise ValidationFailed("estimation method must be a non-empty string")
        counts = tuple(
            values.get(field)
            for field in (
                "total_tokens",
                "input_tokens",
                "output_tokens",
                "cache_read_tokens",
                "cache_write_tokens",
                "reasoning_tokens",
            )
        )
        if precision == "measured" and source not in {"provider", "engine"}:
            raise ValidationFailed("measured evidence must come from a provider or engine")
        if precision == "estimated":
            if source != "estimate":
                raise ValidationFailed("estimated evidence must use the estimate source")
            if not method:
                raise ValidationFailed("estimated usage requires an estimation method")
        if precision == "unavailable":
            if source == "estimate" or method is not None:
                raise ValidationFailed("unavailable evidence cannot contain an estimate")
            if any(count is not None for count in counts):
                raise ValidationFailed("unavailable evidence must not carry token values")
        for flag_field in ("cache_included_in_input", "reasoning_included_in_output"):
            flag = values.get(flag_field)
            if flag is not None and not isinstance(flag, bool):
                raise ValidationFailed(f"{flag_field} must be a boolean or null")
        return cls(**values)

    def total(self) -> int | None:
        if self.total_tokens is not None:
            return self.total_tokens
        components = (
            self.input_tokens,
            self.output_tokens,
            self.cache_read_tokens,
            self.cache_write_tokens,
            self.reasoning_tokens,
        )
        if any(component is None for component in components):
            return None
        if self.cache_included_in_input is None or self.reasoning_included_in_output is None:
            return None
        assert self.input_tokens is not None
        assert self.output_tokens is not None
        assert self.cache_read_tokens is not None
        assert self.cache_write_tokens is not None
        assert self.reasoning_tokens is not None
        total = self.input_tokens + self.output_tokens
        if self.cache_included_in_input is False:
            total += self.cache_read_tokens + self.cache_write_tokens
        if self.reasoning_included_in_output is False:
            total += self.reasoning_tokens
        return total

    def resolved_total(self) -> int | None:
        if self.precision not in ("measured", "estimated") or self.source == "none":
            return None
        return self.total()


@dataclass(frozen=True)
class ReservationGrant:
    reservation_id: str
    replayed: bool
    funding: str
    run_id: str | None
    period_day: str
    timezone: str
    reserved_tokens: int
    limit_tokens: int | None
    consumed_tokens: int
    reserved_tokens_total: int
    legacy_tokens: int
    remaining_tokens: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "reservationId": self.reservation_id,
            "replayed": self.replayed,
            "funding": self.funding,
            "runId": self.run_id,
            "periodDay": self.period_day,
            "timezone": self.timezone,
            "reservedTokens": self.reserved_tokens,
            "limitTokens": self.limit_tokens,
            "consumedTokens": self.consumed_tokens,
            "reservedTokensTotal": self.reserved_tokens_total,
            "legacyTokens": self.legacy_tokens,
            "remainingTokens": self.remaining_tokens,
        }


@dataclass(frozen=True)
class SettlementResult:
    reservation_id: str
    state: str
    idempotent: bool
    tokens: int | None
    precision: str
    source: str
    estimation_method: str | None
    period_day: str
    timezone: str
    run_id: str | None
    unresolved: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "reservationId": self.reservation_id,
            "state": self.state,
            "idempotent": self.idempotent,
            "tokens": self.tokens,
            "precision": self.precision,
            "source": self.source,
            "estimationMethod": self.estimation_method,
            "periodDay": self.period_day,
            "timezone": self.timezone,
            "runId": self.run_id,
            "unresolved": self.unresolved,
        }


def _validate_token_count(value: Any, field: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationFailed(f"{field} must be a non-negative integer or null")


def _validate_limit(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationFailed("daily limit must be a non-negative integer or null")
    return value


def _validate_day(value: str, field: str) -> str:
    if not isinstance(value, str) or not _DAY_PATTERN.match(value):
        raise ValidationFailed(f"{field} must be an ISO day (YYYY-MM-DD)")
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise ValidationFailed(f"{field} must be a valid ISO day") from exc
    return value


def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValidationFailed(f"unknown IANA timezone: {name}") from exc


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _as_utc(value).isoformat()


def _legacy_utc_days(day: str, timezone: str) -> tuple[str, ...]:
    """UTC legacy day keys whose daily interval overlaps the local period day."""
    zone = _zone(timezone)
    start_date = date.fromisoformat(day)
    start = datetime.combine(start_date, datetime.min.time(), tzinfo=zone).astimezone(UTC)
    end = datetime.combine(
        start_date + timedelta(days=1), datetime.min.time(), tzinfo=zone
    ).astimezone(UTC)
    cursor = start.date()
    last = (end - timedelta(microseconds=1)).date()
    days: list[str] = []
    while cursor <= last:
        days.append(cursor.isoformat())
        cursor += timedelta(days=1)
    return tuple(days)


class AiUsageService:
    """Business quota layer. Owns one transaction per reserve/settle call."""

    def __init__(
        self,
        settings: Settings,
        session_factory: sessionmaker[Session],
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._now = now or utcnow

    @contextmanager
    def _session(self) -> Iterator[Session]:
        session = self._session_factory()
        try:
            yield session
        finally:
            session.close()

    def _now_utc(self) -> datetime:
        return _as_utc(self._now())

    # -- policy and period -------------------------------------------------

    def _policy(self, db: Session) -> AiUsageQuotaPolicy:
        row = db.get(AiUsageQuotaPolicy, POLICY_ID)
        if row is None:
            row = AiUsageQuotaPolicy(
                id=POLICY_ID,
                company_daily_limit=None,
                company_configured=False,
                personal_daily_limit=None,
                personal_configured=True,
                timezone="UTC",
            )
            db.add(row)
            db.flush()
        return row

    def _period(self, db: Session) -> Period:
        policy = self._policy(db)
        now = self._now_utc()
        active = policy.timezone or "UTC"
        try:
            active_zone = _zone(active)
        except ValidationFailed:
            active = "UTC"
            active_zone = ZoneInfo("UTC")
            policy.timezone = active
        today = now.astimezone(active_zone).date()
        pending = policy.pending_timezone
        effective = policy.pending_effective_day
        if pending:
            try:
                candidate = now.astimezone(_zone(pending)).date()
            except ValidationFailed:
                policy.pending_timezone = None
                policy.pending_effective_day = None
                pending = None
                effective = None
            else:
                try:
                    effective_day = (
                        date.fromisoformat(effective) if effective else today + timedelta(days=1)
                    )
                except ValueError:
                    effective_day = today + timedelta(days=1)
                    policy.pending_effective_day = effective_day.isoformat()
                    effective = effective_day.isoformat()
                if today >= effective_day and candidate >= today:
                    policy.timezone = pending
                    policy.pending_timezone = None
                    policy.pending_effective_day = None
                    policy.updated_at = now
                    db.flush()
                    return Period(candidate.isoformat(), pending, None, None)
        return Period(today.isoformat(), active, pending, effective)

    def _effective_limit(self, db: Session, actor_id: str, funding: str) -> LimitState:
        if funding == PERSONAL:
            # Record-only funding: no company policy, legacy personal policy or
            # personal override may ever deny a personal-funded call.
            return LimitState(None, PERSONAL_LIMIT_SOURCE)
        override = db.scalar(
            select(AiUsageQuotaOverride).where(
                AiUsageQuotaOverride.user_id == actor_id,
                AiUsageQuotaOverride.scope == funding,
            )
        )
        if override is not None:
            return LimitState(override.daily_limit, "override")
        policy = self._policy(db)
        if policy.company_configured:
            return LimitState(policy.company_daily_limit, "default")
        configured = self._settings.agent_daily_token_budget
        # Preserve legacy config semantics: <= 0 was unlimited.
        return LimitState(configured if configured > 0 else None, "legacy_config")

    def _legacy_tokens(self, db: Session, actor_id: str, day: str, timezone: str) -> int:
        days = _legacy_utc_days(day, timezone)
        value = db.scalar(
            select(
                func.coalesce(
                    func.sum(AgentDailyUsage.measured_tokens + AgentDailyUsage.reported_tokens),
                    0,
                )
            ).where(
                AgentDailyUsage.owner_id == actor_id,
                AgentDailyUsage.day.in_(days),
            )
        )
        return int(value or 0)

    def _policy_payload(self, db: Session, *, include_overrides: bool = True) -> dict[str, Any]:
        period = self._period(db)
        policy = self._policy(db)
        configured = self._settings.agent_daily_token_budget
        company_limit = (
            policy.company_daily_limit
            if policy.company_configured
            else (configured if configured > 0 else None)
        )
        payload: dict[str, Any] = {
            "companyDailyLimit": company_limit,
            "companyLimitSource": "policy" if policy.company_configured else "legacy_config",
            "personalDailyLimit": None,
            "personalLimitSource": PERSONAL_LIMIT_NOT_APPLICABLE,
            "timezone": period.timezone,
            "pendingTimezone": period.pending_timezone,
            "pendingEffectiveDay": period.pending_effective_day,
            "serverTime": self._now_utc().isoformat(),
        }
        if include_overrides:
            payload["overrides"] = self._override_rows(db)
        return payload

    def _override_rows(self, db: Session) -> list[dict[str, Any]]:
        rows = db.scalars(
            select(AiUsageQuotaOverride)
            .where(AiUsageQuotaOverride.scope == COMPANY)
            .order_by(AiUsageQuotaOverride.user_id, AiUsageQuotaOverride.scope)
        ).all()
        return [
            {
                "userId": row.user_id,
                "scope": row.scope,
                "dailyLimit": row.daily_limit,
                "updatedAt": _iso(row.updated_at),
            }
            for row in rows
        ]

    def _audit(self, db: Session, principal: Any, action: str, resource: str) -> None:
        IdentityService(db, self._settings).record_operation(
            principal,
            action=action,
            resource=resource,
            outcome="success",
        )

    def _require_admin(self, db: Session, principal: Any, resource: str) -> None:
        if principal.kind != HUMAN_ACTOR_KIND:
            raise PermissionDenied(
                "AI usage administration requires a signed-in installation owner"
            )
        require_system_authority(db, self._settings, principal, PERMISSION, resource)

    def policy(self, principal: Any) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, "ai-usage:policy")
            payload = self._policy_payload(db)
            db.commit()
            return payload

    def update_policy(
        self,
        principal: Any,
        *,
        company_daily_limit: Any = UNSET,
        personal_daily_limit: Any = UNSET,
        timezone: Any = UNSET,
        cancel_timezone_change: bool = False,
    ) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, "ai-usage:policy")
            if personal_daily_limit is not UNSET:
                raise PersonalBudgetUnsupported()
            policy = self._policy(db)
            now = self._now_utc()
            self._period(db)
            if company_daily_limit is not UNSET:
                policy.company_daily_limit = _validate_limit(company_daily_limit)
                policy.company_configured = True
            if cancel_timezone_change and timezone is not UNSET:
                raise ValidationFailed("timezone and cancelTimezoneChange cannot be combined")
            if cancel_timezone_change:
                policy.pending_timezone = None
                policy.pending_effective_day = None
            elif timezone is not UNSET:
                if not isinstance(timezone, str):
                    raise ValidationFailed("timezone must be an IANA timezone name")
                target = _zone(timezone)
                if target.key == policy.timezone:
                    policy.pending_timezone = None
                    policy.pending_effective_day = None
                else:
                    active_today = now.astimezone(_zone(policy.timezone)).date()
                    candidate = now.astimezone(target).date()
                    effective = max(active_today + timedelta(days=1), candidate)
                    policy.pending_timezone = target.key
                    policy.pending_effective_day = effective.isoformat()
            policy.updated_at = now
            db.flush()
            payload = self._policy_payload(db)
            self._audit(db, principal, "ai.usage.policy.update", "ai-usage:policy")
            return payload

    def list_overrides(self, principal: Any) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, "ai-usage:overrides")
            rows = self._override_rows(db)
            db.commit()
            return {"overrides": rows}

    def set_override(
        self,
        principal: Any,
        user_id: str,
        *,
        daily_limit: Any,
        scope: str = COMPANY,
    ) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, f"ai-usage:override:{scope}:{user_id}")
            self._validate_scope(scope)
            if scope == PERSONAL:
                raise PersonalBudgetUnsupported()
            limit = _validate_limit(daily_limit)
            if not isinstance(user_id, str) or not user_id.strip():
                raise ValidationFailed("user id is required")
            if db.get(Identity, user_id) is None:
                raise ValidationFailed("unknown user")
            row = db.get(AiUsageQuotaOverride, f"{scope}:{user_id}")
            now = self._now_utc()
            if row is None:
                row = AiUsageQuotaOverride(
                    id=f"{scope}:{user_id}",
                    user_id=user_id,
                    scope=scope,
                    daily_limit=limit,
                )
                db.add(row)
            else:
                row.daily_limit = limit
                row.updated_at = now
            db.flush()
            payload = {"overrides": self._override_rows(db)}
            self._audit(
                db,
                principal,
                "ai.usage.override.update",
                f"ai-usage:override:{scope}:{user_id}",
            )
            return payload

    def delete_override(
        self, principal: Any, user_id: str, *, scope: str = COMPANY
    ) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, f"ai-usage:override:{scope}:{user_id}")
            self._validate_scope(scope)
            if scope == PERSONAL:
                raise PersonalBudgetUnsupported()
            row = db.get(AiUsageQuotaOverride, f"{scope}:{user_id}")
            if row is not None:
                db.delete(row)
                db.flush()
            payload = {"overrides": self._override_rows(db)}
            self._audit(
                db,
                principal,
                "ai.usage.override.delete",
                f"ai-usage:override:{scope}:{user_id}",
            )
            return payload

    # -- reservation admission --------------------------------------------

    def _validate_scope(self, scope: str) -> None:
        if scope not in (COMPANY, PERSONAL):
            raise ValidationFailed("funding scope must be company or personal")

    def _inherit(self, field: str, parent_value: Any, value: Any) -> Any:
        if value is None:
            return parent_value
        if value != parent_value:
            raise ValidationFailed(f"{field} does not match the parent reservation")
        return value

    def reserve(
        self,
        actor_id: str | None,
        *,
        funding: str | None = None,
        reserved_tokens: int,
        provider_id: str | None = None,
        provider_scope: str | None = None,
        provider_name: str | None = None,
        model: str | None = None,
        engine: str | None = None,
        run_id: str | None = None,
        parent_reservation_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> ReservationGrant:
        if (
            isinstance(reserved_tokens, bool)
            or not isinstance(reserved_tokens, int)
            or reserved_tokens < 1
        ):
            raise ValidationFailed("reserved tokens must be a positive integer")
        if provider_scope is not None and provider_scope not in PROVIDER_SCOPES:
            raise ValidationFailed("provider scope must be global or personal")
        if idempotency_key is not None and (
            not isinstance(idempotency_key, str) or not idempotency_key.strip()
        ):
            raise ValidationFailed("idempotency key must be a non-empty string")
        if run_id is not None and (not isinstance(run_id, str) or not run_id.strip()):
            raise ValidationFailed("run id must be a non-empty string")

        with self._session() as db:
            policy = self._policy(db)
            period = self._period(db)

            if parent_reservation_id is not None:
                parent = db.get(AiUsageReservation, parent_reservation_id)
                if parent is None:
                    raise ValidationFailed("parent reservation not found")
                if actor_id is None:
                    actor_id = parent.actor_id
                elif parent.actor_id != actor_id:
                    raise ValidationFailed("parent reservation belongs to another actor")
                if funding is None:
                    funding = parent.funding
                elif parent.funding != funding:
                    raise ValidationFailed("funding does not match the parent reservation")
                provider_id = self._inherit("provider", parent.provider_id, provider_id)
                provider_scope = self._inherit(
                    "provider scope", parent.provider_scope, provider_scope
                )
                provider_name = self._inherit("provider name", parent.provider_name, provider_name)
                model = self._inherit("model", parent.model, model)
                engine = self._inherit("engine", parent.engine, engine)
                run_id = self._inherit("run", parent.run_id, run_id)
                period = Period(
                    parent.period_day,
                    parent.timezone,
                    policy.pending_timezone,
                    policy.pending_effective_day,
                )

            if not isinstance(actor_id, str) or not actor_id.strip():
                raise ValidationFailed("actor id is required")
            if funding is None:
                raise ValidationFailed("funding is required")
            self._validate_scope(funding)
            limit_state = self._effective_limit(db, actor_id, funding)

            existing = None
            if idempotency_key is not None:
                existing = db.scalar(
                    select(AiUsageReservation).where(
                        AiUsageReservation.actor_id == actor_id,
                        AiUsageReservation.idempotency_key == idempotency_key,
                    )
                )
            if existing is not None:
                if existing.funding != funding or existing.reserved_tokens != reserved_tokens:
                    raise ValidationFailed(
                        "idempotency key was already used with different reservation terms"
                    )
                for label, provided, stored in (
                    ("provider", provider_id, existing.provider_id),
                    ("model", model, existing.model),
                    ("engine", engine, existing.engine),
                    ("run", run_id, existing.run_id),
                ):
                    if provided is not None and provided != stored:
                        raise ValidationFailed(
                            f"idempotency key was already used with a different {label}"
                        )
                db.commit()
                balance = db.get(
                    AiUsageBalance, _balance_id(actor_id, funding, existing.period_day)
                )
                legacy = (
                    self._legacy_tokens(db, actor_id, existing.period_day, existing.timezone)
                    if funding == COMPANY
                    else 0
                )
                return self._grant(
                    existing,
                    limit_state.limit,
                    balance,
                    legacy,
                    replayed=True,
                )

            db.commit()
            balance, legacy = self._admit(
                db,
                actor_id=actor_id,
                funding=funding,
                day=period.day,
                timezone=period.timezone,
                limit=limit_state.limit,
                reserved_tokens=reserved_tokens,
            )
            reservation = AiUsageReservation(
                id=str(uuid4()),
                actor_id=actor_id,
                funding=funding,
                provider_id=provider_id,
                provider_scope=provider_scope,
                provider_name=provider_name,
                model=model,
                engine=engine,
                run_id=run_id,
                parent_reservation_id=parent_reservation_id,
                idempotency_key=idempotency_key,
                period_day=period.day,
                timezone=period.timezone,
                reserved_tokens=reserved_tokens,
                status=PENDING,
                created_at=self._now_utc(),
                updated_at=self._now_utc(),
            )
            db.add(reservation)
            db.flush()
            grant = self._grant(reservation, limit_state.limit, balance, legacy, replayed=False)
            db.commit()
            return grant

    def _admit(
        self,
        db: Session,
        *,
        actor_id: str,
        funding: str,
        day: str,
        timezone: str,
        limit: int | None,
        reserved_tokens: int,
    ) -> tuple[AiUsageBalance, int]:
        identifier = _balance_id(actor_id, funding, day)
        now = self._now_utc()
        legacy_days = _legacy_utc_days(day, timezone)
        legacy_expr = (
            select(
                func.coalesce(
                    func.sum(AgentDailyUsage.measured_tokens + AgentDailyUsage.reported_tokens),
                    0,
                )
            )
            .where(
                AgentDailyUsage.owner_id == actor_id,
                AgentDailyUsage.day.in_(legacy_days),
            )
            .scalar_subquery()
        )
        conditions = [AiUsageBalance.id == identifier]
        if limit is not None:
            legacy_term = legacy_expr if funding == COMPANY else 0
            conditions.append(
                AiUsageBalance.consumed_tokens + AiUsageBalance.reserved_tokens + legacy_term
                <= limit - reserved_tokens
            )
        statement = (
            update(AiUsageBalance)
            .where(*conditions)
            .values(
                reserved_tokens=AiUsageBalance.reserved_tokens + reserved_tokens,
                updated_at=now,
            )
        )
        result = db.execute(statement)
        if result.rowcount == 1:
            balance = db.get(AiUsageBalance, identifier)
            assert balance is not None
            legacy = self._legacy_tokens(db, actor_id, day, timezone) if funding == COMPANY else 0
            return balance, legacy

        existing = db.get(AiUsageBalance, identifier)
        if existing is not None:
            raise QuotaExceeded(0, period_day=day)
        legacy = self._legacy_tokens(db, actor_id, day, timezone) if funding == COMPANY else 0
        if limit is not None and legacy + reserved_tokens > limit:
            raise QuotaExceeded(0, period_day=day)
        balance = AiUsageBalance(
            id=identifier,
            user_id=actor_id,
            scope=funding,
            day=day,
            consumed_tokens=0,
            reserved_tokens=reserved_tokens,
            created_at=now,
            updated_at=now,
        )
        db.add(balance)
        db.flush()
        return balance, legacy

    def _grant(
        self,
        reservation: AiUsageReservation,
        limit: int | None,
        balance: AiUsageBalance | None,
        legacy: int,
        *,
        replayed: bool,
    ) -> ReservationGrant:
        consumed = balance.consumed_tokens if balance is not None else 0
        reserved_total = (
            balance.reserved_tokens if balance is not None else reservation.reserved_tokens
        )
        remaining = None if limit is None else max(0, limit - consumed - reserved_total - legacy)
        return ReservationGrant(
            reservation_id=reservation.id,
            replayed=replayed,
            funding=reservation.funding,
            run_id=reservation.run_id,
            period_day=reservation.period_day,
            timezone=reservation.timezone,
            reserved_tokens=reservation.reserved_tokens,
            limit_tokens=limit,
            consumed_tokens=consumed,
            reserved_tokens_total=reserved_total,
            legacy_tokens=legacy,
            remaining_tokens=remaining,
        )

    # -- settlement and reconciliation ------------------------------------

    def settle(self, reservation_id: str, evidence: Mapping[str, Any]) -> SettlementResult:
        parsed = UsageEvidence.from_mapping(evidence)
        with self._session() as db:
            result = self._settle_core(db, reservation_id, parsed)
            db.commit()
            return result

    def release(
        self,
        reservation_id: str,
        *,
        reason: str,
        trusted_no_upstream: bool = False,
    ) -> SettlementResult:
        if not trusted_no_upstream:
            raise ValidationFailed(
                "release requires explicit trusted_no_upstream=True (never on timeout)"
            )
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationFailed("release requires a non-empty reason")
        with self._session() as db:
            result = self._release_core(db, reservation_id, reason=reason, resolved_by=None)
            db.commit()
            return result

    def _settle_core(
        self,
        db: Session,
        reservation_id: str,
        evidence: UsageEvidence,
        *,
        reason: str | None = None,
        resolved_by: str | None = None,
    ) -> SettlementResult:
        reservation = db.get(AiUsageReservation, reservation_id)
        if reservation is None:
            raise ValidationFailed("unknown reservation")
        amount = evidence.resolved_total()
        if reservation.status in (SETTLED, RELEASED):
            receipt = self._receipt(db, reservation_id)
            db.commit()
            return self._result(reservation, receipt, idempotent=True)
        if reservation.status == UNRESOLVED and amount is None:
            receipt = self._receipt(db, reservation_id)
            db.commit()
            return self._result(reservation, receipt, idempotent=True)

        db.commit()
        now = self._now_utc()
        if amount is None:
            statement = (
                update(AiUsageReservation)
                .where(
                    AiUsageReservation.id == reservation_id,
                    AiUsageReservation.status.in_((PENDING, UNRESOLVED)),
                )
                .values(
                    status=UNRESOLVED,
                    settled_tokens=None,
                    precision=evidence.precision,
                    source=evidence.source,
                    estimation_method=evidence.estimation_method,
                    resolved_at=now,
                    updated_at=now,
                )
            )
        else:
            statement = (
                update(AiUsageReservation)
                .where(
                    AiUsageReservation.id == reservation_id,
                    AiUsageReservation.status.in_((PENDING, UNRESOLVED)),
                )
                .values(
                    status=SETTLED,
                    settled_tokens=amount,
                    precision=evidence.precision,
                    source=evidence.source,
                    estimation_method=evidence.estimation_method,
                    resolved_at=now,
                    updated_at=now,
                )
            )
        result = db.execute(statement)
        if result.rowcount != 1:
            reservation = db.get(AiUsageReservation, reservation_id)
            assert reservation is not None
            receipt = self._receipt(db, reservation_id)
            db.commit()
            return self._result(reservation, receipt, idempotent=True)

        reservation = db.get(AiUsageReservation, reservation_id)
        assert reservation is not None
        db.refresh(reservation)
        if amount is not None:
            self._adjust_balance(db, reservation, consumed=amount, now=now)
            self._upsert_receipt(
                db,
                reservation,
                state=SETTLED,
                evidence=evidence,
                total_tokens=amount,
                reason=reason,
                resolved_by=resolved_by,
                now=now,
            )
        else:
            self._upsert_receipt(
                db,
                reservation,
                state=UNRESOLVED,
                evidence=evidence,
                total_tokens=evidence.total_tokens,
                reason=reason,
                resolved_by=resolved_by,
                now=now,
            )
        db.flush()
        receipt = self._receipt(db, reservation_id)
        return self._result(reservation, receipt, idempotent=False)

    def _release_core(
        self,
        db: Session,
        reservation_id: str,
        *,
        reason: str,
        resolved_by: str | None,
    ) -> SettlementResult:
        reservation = db.get(AiUsageReservation, reservation_id)
        if reservation is None:
            raise ValidationFailed("unknown reservation")
        if reservation.status == SETTLED:
            raise ValidationFailed("a settled reservation cannot be released")
        if reservation.status == RELEASED:
            receipt = self._receipt(db, reservation_id)
            db.commit()
            return self._result(reservation, receipt, idempotent=True)
        db.commit()
        now = self._now_utc()
        statement = (
            update(AiUsageReservation)
            .where(
                AiUsageReservation.id == reservation_id,
                AiUsageReservation.status.in_((PENDING, UNRESOLVED)),
            )
            .values(status=RELEASED, resolved_at=now, updated_at=now)
        )
        result = db.execute(statement)
        if result.rowcount != 1:
            reservation = db.get(AiUsageReservation, reservation_id)
            assert reservation is not None
            receipt = self._receipt(db, reservation_id)
            db.commit()
            return self._result(reservation, receipt, idempotent=True)
        reservation = db.get(AiUsageReservation, reservation_id)
        assert reservation is not None
        db.refresh(reservation)
        self._adjust_balance(db, reservation, consumed=0, now=now)
        receipt = self._receipt(db, reservation_id)
        if receipt is None:
            self._upsert_receipt(
                db,
                reservation,
                state=RELEASED,
                evidence=None,
                total_tokens=None,
                reason=reason,
                resolved_by=resolved_by,
                now=now,
            )
        else:
            receipt.state = RELEASED
            receipt.reason = reason
            receipt.resolved_by = resolved_by
            receipt.updated_at = now
        db.flush()
        receipt = self._receipt(db, reservation_id)
        return self._result(reservation, receipt, idempotent=False)

    def _receipt(self, db: Session, reservation_id: str) -> AiUsageReceipt | None:
        return db.scalar(
            select(AiUsageReceipt).where(AiUsageReceipt.reservation_id == reservation_id)
        )

    def _adjust_balance(
        self, db: Session, reservation: AiUsageReservation, *, consumed: int, now: datetime
    ) -> None:
        identifier = _balance_id(reservation.actor_id, reservation.funding, reservation.period_day)
        statement = (
            update(AiUsageBalance)
            .where(AiUsageBalance.id == identifier)
            .values(
                consumed_tokens=AiUsageBalance.consumed_tokens + consumed,
                reserved_tokens=case(
                    (
                        AiUsageBalance.reserved_tokens >= reservation.reserved_tokens,
                        AiUsageBalance.reserved_tokens - reservation.reserved_tokens,
                    ),
                    else_=0,
                ),
                updated_at=now,
            )
        )
        result = db.execute(statement)
        if result.rowcount == 0:
            db.add(
                AiUsageBalance(
                    id=identifier,
                    user_id=reservation.actor_id,
                    scope=reservation.funding,
                    day=reservation.period_day,
                    consumed_tokens=consumed,
                    reserved_tokens=0,
                    created_at=now,
                    updated_at=now,
                )
            )
            db.flush()

    def _upsert_receipt(
        self,
        db: Session,
        reservation: AiUsageReservation,
        *,
        state: str,
        evidence: UsageEvidence | None,
        total_tokens: int | None,
        reason: str | None,
        resolved_by: str | None,
        now: datetime,
    ) -> AiUsageReceipt:
        receipt = self._receipt(db, reservation.id)
        if receipt is None:
            receipt = AiUsageReceipt(
                id=str(uuid4()),
                reservation_id=reservation.id,
                actor_id=reservation.actor_id,
                funding=reservation.funding,
                provider_id=reservation.provider_id,
                provider_scope=reservation.provider_scope,
                provider_name=reservation.provider_name,
                model=reservation.model,
                engine=reservation.engine,
                run_id=reservation.run_id,
                period_day=reservation.period_day,
                timezone=reservation.timezone,
                state=state,
                precision=evidence.precision if evidence is not None else "unavailable",
                source=evidence.source if evidence is not None else "none",
                created_at=now,
                updated_at=now,
            )
            db.add(receipt)
        receipt.state = state
        receipt.updated_at = now
        if evidence is not None:
            receipt.input_tokens = evidence.input_tokens
            receipt.output_tokens = evidence.output_tokens
            receipt.cache_read_tokens = evidence.cache_read_tokens
            receipt.cache_write_tokens = evidence.cache_write_tokens
            receipt.reasoning_tokens = evidence.reasoning_tokens
            receipt.total_tokens = total_tokens
            receipt.precision = evidence.precision
            receipt.source = evidence.source
            receipt.total_source = evidence.total_source
            receipt.estimation_method = evidence.estimation_method
            receipt.cache_included_in_input = evidence.cache_included_in_input
            receipt.reasoning_included_in_output = evidence.reasoning_included_in_output
        receipt.reason = reason
        receipt.resolved_by = resolved_by
        db.flush()
        return receipt

    def _result(
        self,
        reservation: AiUsageReservation,
        receipt: AiUsageReceipt | None,
        *,
        idempotent: bool,
    ) -> SettlementResult:
        state = reservation.status
        tokens: int | None
        if state == SETTLED:
            tokens = reservation.settled_tokens
        elif state == RELEASED:
            tokens = 0
        else:
            tokens = None
        return SettlementResult(
            reservation_id=reservation.id,
            state=state,
            idempotent=idempotent,
            tokens=tokens,
            precision=receipt.precision if receipt is not None else "unavailable",
            source=receipt.source if receipt is not None else "none",
            estimation_method=receipt.estimation_method if receipt is not None else None,
            period_day=reservation.period_day,
            timezone=reservation.timezone,
            run_id=reservation.run_id,
            unresolved=state == UNRESOLVED,
        )

    def pending(
        self,
        *,
        run_id: str | None = None,
        user_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValidationFailed("limit must be between 1 and 500")
        with self._session() as db:
            statement = select(AiUsageReservation).where(
                AiUsageReservation.status.in_((PENDING, UNRESOLVED))
            )
            if run_id is not None:
                statement = statement.where(AiUsageReservation.run_id == run_id)
            if user_id is not None:
                statement = statement.where(AiUsageReservation.actor_id == user_id)
            rows = db.scalars(statement.order_by(AiUsageReservation.created_at).limit(limit)).all()
            items = [self._pending_item(db, row) for row in rows]
            db.commit()
            return items

    def _pending_item(self, db: Session, row: AiUsageReservation) -> dict[str, Any]:
        receipt = self._receipt(db, row.id)
        evidence = None
        if receipt is not None:
            evidence = {
                "totalTokens": receipt.total_tokens,
                "precision": receipt.precision,
                "source": receipt.source,
                "estimationMethod": receipt.estimation_method,
                "resolvedAt": _iso(receipt.updated_at),
            }
        return {
            "reservationId": row.id,
            "runId": row.run_id,
            "parentReservationId": row.parent_reservation_id,
            "userId": row.actor_id,
            "funding": row.funding,
            "providerId": row.provider_id,
            "providerName": row.provider_name,
            "providerScope": row.provider_scope,
            "model": row.model,
            "engine": row.engine,
            "reservedTokens": row.reserved_tokens,
            "periodDay": row.period_day,
            "timezone": row.timezone,
            "createdAt": _iso(row.created_at),
            "state": row.status,
            "lastEvidence": evidence,
        }

    def pending_admin(self, principal: Any, **filters: Any) -> dict[str, Any]:
        with self._session() as db:
            self._require_admin(db, principal, "ai-usage:pending")
            db.commit()
        return {"items": self.pending(**filters)}

    def resolve(
        self,
        principal: Any,
        reservation_id: str,
        *,
        outcome: str,
        evidence: Mapping[str, Any] | None = None,
        reason: str | None = None,
    ) -> SettlementResult:
        with self._session() as db:
            self._require_admin(db, principal, f"ai-usage:reservation:{reservation_id}:resolve")
            if outcome not in (SETTLED, RELEASED):
                raise ValidationFailed("outcome must be settled or released")
            parsed = UsageEvidence.from_mapping(evidence or {}) if outcome == SETTLED else None
            if outcome == SETTLED and (parsed is None or parsed.resolved_total() is None):
                raise ValidationFailed(
                    "settlement requires trustworthy total tokens, precision and source"
                )
            if outcome == RELEASED and (not reason or not reason.strip()):
                raise ValidationFailed("release requires a non-empty reason")
            db.commit()
            if outcome == SETTLED:
                assert parsed is not None
                result = self._settle_core(
                    db,
                    reservation_id,
                    parsed,
                    reason=reason,
                    resolved_by=principal.actor_id,
                )
            else:
                assert reason is not None
                result = self._release_core(
                    db,
                    reservation_id,
                    reason=reason,
                    resolved_by=principal.actor_id,
                )
            self._audit(
                db,
                principal,
                "ai.usage.reservation.resolve",
                f"ai-usage:reservation:{reservation_id}",
            )
            return result

    # -- own summary and reports ------------------------------------------

    def me(self, actor_id: str) -> dict[str, Any]:
        if not isinstance(actor_id, str) or not actor_id.strip():
            raise ValidationFailed("actor id is required")
        with self._session() as db:
            period = self._period(db)
            company_limit = self._effective_limit(db, actor_id, COMPANY)
            personal_limit = self._effective_limit(db, actor_id, PERSONAL)
            company = self._funding_summary(
                db, actor_id, COMPANY, period.day, period.timezone, company_limit
            )
            personal = self._funding_summary(
                db, actor_id, PERSONAL, period.day, period.timezone, personal_limit
            )
            payload = {
                "userId": actor_id,
                "periodDay": period.day,
                "timezone": period.timezone,
                "pendingTimezone": period.pending_timezone,
                "pendingEffectiveDay": period.pending_effective_day,
                "funding": {"company": company, "personal": personal},
            }
            db.commit()
            return payload

    def _funding_summary(
        self,
        db: Session,
        actor_id: str,
        funding: str,
        day: str,
        timezone: str,
        limit: LimitState,
    ) -> dict[str, Any]:
        balance = db.get(AiUsageBalance, _balance_id(actor_id, funding, day))
        consumed = balance.consumed_tokens if balance is not None else 0
        reserved = balance.reserved_tokens if balance is not None else 0
        legacy = self._legacy_tokens(db, actor_id, day, timezone) if funding == COMPANY else 0
        pending_count = db.scalar(
            select(func.count(AiUsageReservation.id)).where(
                AiUsageReservation.actor_id == actor_id,
                AiUsageReservation.funding == funding,
                AiUsageReservation.period_day == day,
                AiUsageReservation.status.in_((PENDING, UNRESOLVED)),
            )
        )
        precision = {name: 0 for name in PRECISIONS}
        rows = db.execute(
            select(AiUsageReceipt.precision, func.sum(AiUsageReceipt.total_tokens))
            .where(
                AiUsageReceipt.actor_id == actor_id,
                AiUsageReceipt.funding == funding,
                AiUsageReceipt.period_day == day,
                AiUsageReceipt.state == SETTLED,
            )
            .group_by(AiUsageReceipt.precision)
        ).all()
        for name, total in rows:
            if name in precision:
                precision[name] += int(total or 0)
        available = (
            None if limit.limit is None else max(0, limit.limit - consumed - reserved - legacy)
        )
        return {
            "limitTokens": limit.limit,
            "limitSource": limit.source,
            "unlimited": limit.limit is None,
            "consumedTokens": consumed,
            "reservedTokens": reserved,
            "legacyTokens": legacy,
            "availableTokens": available,
            "pendingCount": int(pending_count or 0),
            "precision": precision,
        }

    def report(
        self,
        principal: Any,
        *,
        user_id: str | None = None,
        provider_id: str | None = None,
        model: str | None = None,
        engine: str | None = None,
        funding: str | None = None,
        day_from: str | None = None,
        day_to: str | None = None,
        group_by: Iterable[str] | None = None,
        include_legacy: bool = True,
    ) -> dict[str, Any]:
        if funding is not None:
            self._validate_scope(funding)
        if day_from is not None:
            _validate_day(day_from, "dayFrom")
        if day_to is not None:
            _validate_day(day_to, "dayTo")
        groups = tuple(group_by) if group_by is not None else DEFAULT_GROUP_BY
        unknown = set(groups) - GROUPABLE
        if unknown:
            raise ValidationFailed(f"unsupported report grouping: {', '.join(sorted(unknown))}")
        with self._session() as db:
            self._require_admin(db, principal, "ai-usage:report")
            period = self._period(db)
            items: dict[tuple[Any, ...], dict[str, Any]] = {}

            def filtered(statement: Any, entity: Any) -> Any:
                if user_id is not None:
                    statement = statement.where(entity.actor_id == user_id)
                if provider_id is not None:
                    statement = statement.where(entity.provider_id == provider_id)
                if model is not None:
                    statement = statement.where(entity.model == model)
                if engine is not None:
                    statement = statement.where(entity.engine == engine)
                if funding is not None:
                    statement = statement.where(entity.funding == funding)
                if day_from is not None:
                    statement = statement.where(entity.period_day >= day_from)
                if day_to is not None:
                    statement = statement.where(entity.period_day <= day_to)
                return statement

            receipts = db.scalars(filtered(select(AiUsageReceipt), AiUsageReceipt)).all()
            pending_statement = filtered(
                select(AiUsageReservation).where(AiUsageReservation.status == PENDING),
                AiUsageReservation,
            )

            for receipt in receipts:
                reservation = db.scalar(
                    select(AiUsageReservation).where(
                        AiUsageReservation.id == receipt.reservation_id
                    )
                )
                key = _report_key(
                    groups,
                    user=receipt.actor_id,
                    provider=receipt.provider_id,
                    model=receipt.model,
                    engine=receipt.engine,
                    funding=receipt.funding,
                    day=receipt.period_day,
                    precision=receipt.precision,
                    source=receipt.source,
                    state=receipt.state,
                    legacy=False,
                )
                item = items.setdefault(key, _empty_item())
                _apply_dimensions(item, key, groups)
                item["providerName"] = item["providerName"] or receipt.provider_name
                item["providerScope"] = item["providerScope"] or receipt.provider_scope
                item["precision"] = receipt.precision
                item["source"] = receipt.source
                item["state"] = receipt.state
                item["legacy"] = False
                item["estimationMethod"] = receipt.estimation_method
                _add_nullable(item, "inputTokens", receipt.input_tokens)
                _add_nullable(item, "outputTokens", receipt.output_tokens)
                _add_nullable(item, "cacheReadTokens", receipt.cache_read_tokens)
                _add_nullable(item, "cacheWriteTokens", receipt.cache_write_tokens)
                _add_nullable(item, "reasoningTokens", receipt.reasoning_tokens)
                if receipt.cache_included_in_input is not None:
                    item["cacheIncludedInInput"] = receipt.cache_included_in_input
                if receipt.reasoning_included_in_output is not None:
                    item["reasoningIncludedInOutput"] = receipt.reasoning_included_in_output
                item["totalSource"] = receipt.total_source
                item["receiptCount"] += 1
                if receipt.state == SETTLED:
                    item["settledTokens"] += int(receipt.total_tokens or 0)
                elif receipt.state == UNRESOLVED:
                    item["unresolvedCount"] += 1
                    if reservation is not None:
                        item["reservedTokens"] += reservation.reserved_tokens
                elif receipt.state == RELEASED:
                    item["releasedCount"] += 1

            pending_rows = db.scalars(pending_statement).all()
            for reservation in pending_rows:
                key = _report_key(
                    groups,
                    user=reservation.actor_id,
                    provider=reservation.provider_id,
                    model=reservation.model,
                    engine=reservation.engine,
                    funding=reservation.funding,
                    day=reservation.period_day,
                    precision="unavailable",
                    source="none",
                    state=PENDING,
                    legacy=False,
                )
                item = items.setdefault(key, _empty_item())
                _apply_dimensions(item, key, groups)
                item["providerName"] = item["providerName"] or reservation.provider_name
                item["providerScope"] = item["providerScope"] or reservation.provider_scope
                item["precision"] = "unavailable"
                item["source"] = "none"
                item["state"] = PENDING
                item["legacy"] = False
                item["reservedTokens"] += reservation.reserved_tokens
                item["pendingCount"] += 1

            legacy_rows: list[AgentDailyUsage] = []
            if (
                include_legacy
                and funding in (None, COMPANY)
                and provider_id is None
                and model is None
                and engine is None
            ):
                legacy_statement = select(AgentDailyUsage)
                if user_id is not None:
                    legacy_statement = legacy_statement.where(AgentDailyUsage.owner_id == user_id)
                if day_from is not None:
                    legacy_statement = legacy_statement.where(AgentDailyUsage.day >= day_from)
                if day_to is not None:
                    legacy_statement = legacy_statement.where(AgentDailyUsage.day <= day_to)
                legacy_rows = list(db.scalars(legacy_statement).all())
            for legacy in legacy_rows:
                key = _report_key(
                    groups,
                    user=legacy.owner_id,
                    provider=None,
                    model=None,
                    engine=None,
                    funding=COMPANY,
                    day=legacy.day,
                    precision="unavailable",
                    source="legacy",
                    state="legacy",
                    legacy=True,
                )
                item = items.setdefault(key, _empty_item())
                _apply_dimensions(item, key, groups)
                item["precision"] = "unavailable"
                item["source"] = "legacy"
                item["state"] = "legacy"
                item["legacy"] = True
                item["legacyMeasuredTokens"] = legacy.measured_tokens
                item["legacyReportedTokens"] = legacy.reported_tokens
                item["settledTokens"] += int(legacy.measured_tokens + legacy.reported_tokens)
                item["receiptCount"] += 1

            ordered = sorted(items.values(), key=_item_sort_key)
            totals = {
                "settledTokens": sum(item["settledTokens"] for item in ordered),
                "reservedTokens": sum(item["reservedTokens"] for item in ordered),
                "pendingCount": sum(item["pendingCount"] for item in ordered),
                "unresolvedCount": sum(item["unresolvedCount"] for item in ordered),
                "releasedCount": sum(item["releasedCount"] for item in ordered),
                "receiptCount": sum(item["receiptCount"] for item in ordered),
                "legacyTokens": sum(item["settledTokens"] for item in ordered if item["legacy"]),
            }
            precision_totals = {name: 0 for name in PRECISIONS}
            for item in ordered:
                if item["legacy"]:
                    precision_totals["unavailable"] += item["settledTokens"]
                elif item["state"] == SETTLED and item["precision"] in precision_totals:
                    precision_totals[item["precision"]] += item["settledTokens"]
            payload = {
                "timezone": period.timezone,
                "generatedAt": self._now_utc().isoformat(),
                "filters": {
                    "userId": user_id,
                    "providerId": provider_id,
                    "model": model,
                    "engine": engine,
                    "funding": funding,
                    "dayFrom": day_from,
                    "dayTo": day_to,
                    "includeLegacy": include_legacy,
                },
                "groupBy": list(groups),
                "items": ordered,
                "totals": totals,
                "precision": precision_totals,
            }
            db.commit()
            return payload


def _balance_id(actor_id: str, funding: str, day: str) -> str:
    return f"{funding}:{actor_id}:{day}"


def _report_key(
    groups: tuple[str, ...],
    *,
    user: str,
    provider: str | None,
    model: str | None,
    engine: str | None,
    funding: str,
    day: str,
    precision: str,
    source: str,
    state: str,
    legacy: bool,
) -> tuple[Any, ...]:
    return (
        user if "user" in groups else None,
        provider if "provider" in groups else None,
        model if "model" in groups else None,
        engine if "engine" in groups else None,
        funding if "funding" in groups else None,
        day if "day" in groups else None,
        precision,
        source,
        state,
        legacy,
    )


def _apply_dimensions(item: dict[str, Any], key: tuple[Any, ...], groups: tuple[str, ...]) -> None:
    slots = {
        "user": 0,
        "provider": 1,
        "model": 2,
        "engine": 3,
        "funding": 4,
        "day": 5,
    }
    fields = {
        "user": "userId",
        "provider": "providerId",
        "model": "model",
        "engine": "engine",
        "funding": "funding",
        "day": "day",
    }
    for name in groups:
        item[fields[name]] = key[slots[name]]


def _empty_item() -> dict[str, Any]:
    return {
        "userId": None,
        "providerId": None,
        "providerName": None,
        "providerScope": None,
        "model": None,
        "engine": None,
        "funding": None,
        "day": None,
        "precision": "unavailable",
        "source": "none",
        "state": PENDING,
        "legacy": False,
        "settledTokens": 0,
        "reservedTokens": 0,
        "pendingCount": 0,
        "unresolvedCount": 0,
        "releasedCount": 0,
        "receiptCount": 0,
        "inputTokens": None,
        "outputTokens": None,
        "cacheReadTokens": None,
        "cacheWriteTokens": None,
        "reasoningTokens": None,
        "cacheIncludedInInput": None,
        "reasoningIncludedInOutput": None,
        "totalSource": None,
        "estimationMethod": None,
        "legacyMeasuredTokens": None,
        "legacyReportedTokens": None,
    }


def _add_nullable(item: dict[str, Any], field: str, value: int | None) -> None:
    if value is None:
        return
    item[field] = int(item[field] or 0) + value


def _item_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        item["userId"] or "",
        item["day"] or "",
        item["funding"] or "",
        item["providerId"] or "",
        item["model"] or "",
        item["engine"] or "",
        item["state"],
        item["precision"],
        item["source"],
    )
