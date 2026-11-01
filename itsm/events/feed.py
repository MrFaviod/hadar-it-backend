"""Consumer side of the entity-change outbox: poll, ack, fail, reset, prune.

Ordering under concurrency
--------------------------
``sequence`` is allocated when the outbox row is inserted, while visibility only
happens at commit. A writer that allocated sequence 11 and commits after a writer
that already committed 12 makes 12 visible first. The feed therefore refuses to
deliver the newest part of the stream: an event is released only when

* it is at most ``max(sequence) - lag`` (a count-based holdback), or
* its ``occurred_at`` is older than ``grace_seconds`` (a time-based release, so
  a low-volume feed still delivers without newer events arriving).

``poll`` stops at the first held event, so the cursor never advances over an
event that may still appear with a lower sequence. ``ack`` is monotonic and
conditional on the stored cursor, so two workers cannot rewind it and a retried
``ack`` is a no-op. A permanent gap (an aborted transaction) is tolerated: the
feed delivers the next visible event instead of stalling forever, and the
documented reconciliation path covers anything an aborted commit never wrote.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from itsm.events.models import (
    CONSUMER_STATES,
    ENTITY_TYPES,
    EVENT_TYPES,
    FAILURE_CODES,
    EntityChangeEvent,
    EntityEventConsumer,
)
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.service import ValidationFailed

DEFAULT_LAG: Final[int] = 2
DEFAULT_GRACE_SECONDS: Final[float] = 2.0
DEFAULT_BACKOFF_SECONDS: Final[float] = 60.0
MAX_BACKOFF_SECONDS: Final[float] = 3600.0
MAX_POLL_LIMIT: Final[int] = 200
MAX_CONSUMER_ID: Final[int] = 96
MAX_ATTEMPTS: Final[int] = 10


class UnknownConsumer(LookupError):
    """Raised when a consumer was never registered by ``poll``."""


@dataclass(frozen=True)
class EntityEventView:
    """One delivered change; the consumer uses ``id`` to deduplicate replays."""

    id: str
    sequence: int
    entity_type: str
    entity_id: str
    event_type: str
    occurred_at: datetime
    actor_id: str | None
    changed_fields: tuple[str, ...]

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "sequence": self.sequence,
            "entityType": self.entity_type,
            "entityId": self.entity_id,
            "event": self.event_type,
            "occurredAt": as_utc(self.occurred_at).isoformat(),
            "actorId": self.actor_id,
            "changedFields": list(self.changed_fields),
        }


@dataclass(frozen=True)
class ConsumerStatus:
    """Visible cursor state; a stalled consumer is an operator-facing signal."""

    consumer: str
    last_sequence: int
    attempts: int
    last_error: str | None
    state: str
    retry_after: datetime | None
    updated_at: datetime

    @property
    def is_stalled(self) -> bool:
        return self.state == "stalled"

    def as_payload(self) -> dict[str, Any]:
        return {
            "consumer": self.consumer,
            "lastSequence": self.last_sequence,
            "attempts": self.attempts,
            "lastError": self.last_error,
            "state": self.state,
            "retryAfter": (
                None if self.retry_after is None else as_utc(self.retry_after).isoformat()
            ),
            "updatedAt": as_utc(self.updated_at).isoformat(),
        }


def _consumer_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationFailed("consumer must be a string", key="api.events.consumer_string")
    identifier = value.strip()
    if not identifier or len(identifier) > MAX_CONSUMER_ID:
        raise ValidationFailed(
            f"consumer must be 1-{MAX_CONSUMER_ID} characters",
            key="api.events.consumer_1_maximum_characters",
            params={"maximum": MAX_CONSUMER_ID},
        )
    return identifier


def _positive_int(value: Any, field: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationFailed(
            f"{field} must be an integer",
            key="api.validation.field_integer",
            params={"field": field},
        )
    if not 1 <= value <= maximum:
        raise ValidationFailed(
            f"{field} must be between 1 and {maximum}",
            key="api.events.field_between_1_maximum",
            params={"field": field, "maximum": maximum},
        )
    return value


def _sequence(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationFailed(
            f"{field} must be an integer",
            key="api.validation.field_integer",
            params={"field": field},
        )
    if value < 0:
        raise ValidationFailed(
            f"{field} must be zero or greater",
            key="api.events.field_zero_greater",
            params={"field": field},
        )
    return value


def _failure_code(value: Any) -> str:
    if not isinstance(value, str) or value not in FAILURE_CODES:
        raise ValidationFailed(
            "failure code is not a recognized delivery outcome",
            key="api.events.failure_code_not_recognized_delivery_outcome",
        )
    return value


def _status(row: EntityEventConsumer) -> ConsumerStatus:
    return ConsumerStatus(
        consumer=row.consumer_id,
        last_sequence=int(row.last_sequence),
        attempts=int(row.attempts),
        last_error=row.last_error,
        state=row.state,
        retry_after=row.retry_after,
        updated_at=row.updated_at,
    )


def _view(row: EntityChangeEvent) -> EntityEventView:
    fields = row.changed_fields if isinstance(row.changed_fields, list) else []
    return EntityEventView(
        id=row.id,
        sequence=int(row.sequence),
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        event_type=row.event_type,
        occurred_at=row.occurred_at,
        actor_id=row.actor_id,
        changed_fields=tuple(field for field in fields if isinstance(field, str)),
    )


class EntityEventFeed:
    """Small, dependency-free adapter over the two core-owned tables."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        lag: int = DEFAULT_LAG,
        grace_seconds: float = DEFAULT_GRACE_SECONDS,
        backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
        max_backoff_seconds: float = MAX_BACKOFF_SECONDS,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if lag < 0:
            raise ValueError("lag must be zero or greater")
        if backoff_seconds <= 0 or max_backoff_seconds < backoff_seconds:
            raise ValueError("backoff must be positive and bounded")
        self._sessions = session_factory
        self._lag = lag
        self._grace = float(grace_seconds)
        self._backoff = float(backoff_seconds)
        self._max_backoff = float(max_backoff_seconds)
        self._clock = clock

    # --------------------------------------------------------------- reading
    def poll(self, consumer: str, limit: int) -> list[EntityEventView]:
        """Return committed events after the cursor, in sequence order.

        The first consumer poll registers the cursor at zero; later polls only
        read. Held events are not skipped, they are postponed.
        """
        identifier = _consumer_id(consumer)
        size = _positive_int(limit, "limit", MAX_POLL_LIMIT)
        with self._sessions() as session:
            cursor = self._cursor(session, identifier)
            highest = session.execute(select(func.max(EntityChangeEvent.sequence))).scalar()
            if highest is None:
                return []
            ceiling = int(highest) - self._lag
            cutoff = self._clock() - timedelta(seconds=self._grace)
            statement = (
                select(EntityChangeEvent)
                .where(EntityChangeEvent.sequence > cursor)
                .order_by(EntityChangeEvent.sequence)
                .limit(size)
            )
            delivered: list[EntityEventView] = []
            for row in session.execute(statement).scalars():
                if int(row.sequence) > ceiling and as_utc(row.occurred_at) > cutoff:
                    break
                delivered.append(_view(row))
            return delivered

    def status(self, consumer: str) -> ConsumerStatus:
        identifier = _consumer_id(consumer)
        with self._sessions() as session:
            row = session.get(EntityEventConsumer, identifier)
            if row is None:
                raise UnknownConsumer(identifier)
            return _status(row)

    # -------------------------------------------------------------- progress
    def ack(self, consumer: str, through_sequence: int) -> ConsumerStatus:
        """Advance the cursor to ``through_sequence``; never rewinds.

        The update is conditional on the stored cursor, so a concurrent or
        retried acknowledgement is a no-op instead of a lost update.
        """
        identifier = _consumer_id(consumer)
        target = _sequence(through_sequence, "through_sequence")
        now = self._clock()
        with self._sessions() as session:
            if session.get(EntityEventConsumer, identifier) is None:
                raise UnknownConsumer(identifier)
            session.execute(
                update(EntityEventConsumer)
                .where(
                    EntityEventConsumer.consumer_id == identifier,
                    EntityEventConsumer.last_sequence < target,
                )
                .values(
                    last_sequence=target,
                    attempts=0,
                    last_error=None,
                    state="active",
                    retry_after=None,
                    updated_at=now,
                )
            )
            session.commit()
        return self.status(identifier)

    def fail(self, consumer: str, code: str, max_attempts: int) -> ConsumerStatus:
        """Record one failed delivery attempt and stall after ``max_attempts``."""
        identifier = _consumer_id(consumer)
        failure = _failure_code(code)
        budget = _positive_int(max_attempts, "max_attempts", MAX_ATTEMPTS)
        now = self._clock()
        with self._sessions() as session:
            row = session.get(EntityEventConsumer, identifier)
            if row is None:
                raise UnknownConsumer(identifier)
            row.attempts = int(row.attempts) + 1
            row.last_error = failure
            delay = min(self._backoff * (2 ** (row.attempts - 1)), self._max_backoff)
            row.retry_after = now + timedelta(seconds=delay)
            row.state = "stalled" if row.attempts >= budget else "active"
            row.updated_at = now
            session.commit()
            return _status(row)

    def reset(self, consumer: str) -> ConsumerStatus:
        """Clear the failure budget for an explicit operator retry.

        The cursor is preserved: delivery stays at-least-once, so a reset only
        reopens the consumer and never replays already acknowledged history.
        """
        identifier = _consumer_id(consumer)
        now = self._clock()
        with self._sessions() as session:
            row = session.get(EntityEventConsumer, identifier)
            if row is None:
                raise UnknownConsumer(identifier)
            row.attempts = 0
            row.last_error = None
            row.state = "active"
            row.retry_after = None
            row.updated_at = now
            session.commit()
            return _status(row)

    # ------------------------------------------------------------- retention
    def prune(
        self,
        older_than: datetime,
        keep_after_min_cursor: int | None = None,
    ) -> int:
        """Delete events older than a cutoff that every consumer already acked.

        The deletable ceiling is the lowest registered cursor (stalled
        consumers included: their retry still needs the events) and an optional
        operator floor. Nothing unacknowledged is ever deleted.
        """
        if not isinstance(older_than, datetime):
            raise ValidationFailed(
                "older_than must be a timestamp", key="api.events.older_than_timestamp"
            )
        cutoff = older_than
        floor = (
            None
            if keep_after_min_cursor is None
            else _sequence(keep_after_min_cursor, "keep_after_min_cursor")
        )
        with self._sessions() as session:
            lowest = session.execute(select(func.min(EntityEventConsumer.last_sequence))).scalar()
            if lowest is None:
                highest = session.execute(select(func.max(EntityChangeEvent.sequence))).scalar()
                ceiling = 0 if highest is None else int(highest)
            else:
                ceiling = int(lowest)
            if floor is not None:
                ceiling = min(ceiling, floor)
            result = session.execute(
                delete(EntityChangeEvent).where(
                    EntityChangeEvent.occurred_at < cutoff,
                    EntityChangeEvent.sequence <= ceiling,
                )
            )
            session.commit()
            return int(result.rowcount or 0)

    # ---------------------------------------------------------------- private
    def _cursor(self, session: Session, identifier: str) -> int:
        row = session.get(EntityEventConsumer, identifier)
        if row is not None:
            return int(row.last_sequence)
        session.add(
            EntityEventConsumer(
                consumer_id=identifier,
                last_sequence=0,
                attempts=0,
                state="active",
                updated_at=self._clock(),
            )
        )
        try:
            session.commit()
        except IntegrityError:  # another worker registered the same consumer first
            session.rollback()
            row = session.get(EntityEventConsumer, identifier)
            return 0 if row is None else int(row.last_sequence)
        return 0


__all__ = [
    "CONSUMER_STATES",
    "DEFAULT_BACKOFF_SECONDS",
    "DEFAULT_GRACE_SECONDS",
    "DEFAULT_LAG",
    "ENTITY_TYPES",
    "EVENT_TYPES",
    "MAX_POLL_LIMIT",
    "ConsumerStatus",
    "EntityEventFeed",
    "EntityEventView",
    "UnknownConsumer",
]
