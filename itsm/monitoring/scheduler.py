"""Periodic monitoring sync entry point for the existing Huey worker.

``sync_from_prometheus`` is the only new periodic task: without Alertmanager it
polls native Prometheus alerts and turns them into stable local alert records;
with Alertmanager configured it never polls alerts (the authenticated webhook is
the authority) but it always reconciles recurring maintenance windows into
native silences. Both paths reuse the existing session/engine helpers, never
start a scheduler of their own and never call notification delivery.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any

from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.logging import log_event
from itsm.monitoring.prometheus import MonitoringUnavailable, PrometheusAdapter
from itsm.monitoring.service import MonitoringService

logger = logging.getLogger("itsm.monitoring")


def sync_from_prometheus(
    settings: Settings,
    *,
    as_of: datetime | None = None,
    notifier: Callable[..., Any] | None = None,
) -> dict[str, int]:
    """Run one bounded monitoring sync; transient source failures are retried next tick."""
    engine = create_engine_from_settings(settings)
    stats: dict[str, int] = {}
    try:
        with create_session_factory(engine)() as session:
            service = MonitoringService(
                session,
                settings,
                source="prometheus",
                adapter=PrometheusAdapter(settings),
                notifier=notifier,
                now=(lambda: as_of) if as_of is not None else None,
            )
            if settings.alertmanager_url:
                stats.update(service.sync_maintenance_windows())
            else:
                try:
                    stats.update(service.poll_native_alerts())
                except MonitoringUnavailable:
                    stats["unavailable"] = 1
                    log_event(logger, "monitoring.prometheus_unavailable")
    finally:
        engine.dispose()
    return stats


__all__ = ["sync_from_prometheus"]
