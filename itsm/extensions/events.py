"""Worker entry point for extension event dispatch and periodic reconcile.

The module subscribes to the core transactional outbox and the host applies
declarative reference policies. Both are safe to repeat: a core event id is
exposed to sandboxed handlers for their own deduplication, and the reference
policy only writes when the stored state actually changes.
"""

from __future__ import annotations

from datetime import datetime
from functools import partial
from typing import Any

from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.extensions.host import ExtensionHostService
from itsm.extensions.notifications import enqueue_extension_notice


def process_extension_events(
    settings: Settings,
    as_of: datetime | None = None,
    *,
    lag: int = 2,
    grace_seconds: float = 2.0,
) -> dict[str, Any]:
    """Deliver due core events and run due reconciliations through the host.

    ``lag`` and ``grace_seconds`` are the outbox holdback that keeps the
    consumer from acknowledging an event whose earlier sibling sequence is
    still uncommitted in another transaction. Operational callers keep the
    defaults; the acceptance suite passes zero to observe delivery at once.
    """
    engine = create_engine_from_settings(settings)
    try:
        host = ExtensionHostService(
            settings,
            create_session_factory(engine),
            notify=partial(enqueue_extension_notice, settings=settings),
        )
        dispatched = host.dispatch_entity_events(now=as_of, lag=lag, grace_seconds=grace_seconds)
        reconciled = host.run_due_reconciles(now=as_of)
        return {**dispatched, "reconciled": reconciled["succeeded"]}
    finally:
        engine.dispose()


__all__ = ["process_extension_events"]
