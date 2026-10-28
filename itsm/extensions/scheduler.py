"""Worker entry point for durable approved native extension schedules."""

from __future__ import annotations

from datetime import datetime
from functools import partial

from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.extensions.host import ExtensionHostService
from itsm.extensions.notifications import enqueue_extension_notice


def process_extension_schedules(settings: Settings, as_of: datetime | None = None) -> dict[str, int]:
    """Run due work through the same host transactions and live permission checks."""
    engine = create_engine_from_settings(settings)
    try:
        host = ExtensionHostService(
            settings,
            create_session_factory(engine),
            notify=partial(enqueue_extension_notice, settings=settings),
        )
        return host.run_due_schedules(as_of)
    finally:
        engine.dispose()
