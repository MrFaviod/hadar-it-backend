"""Durable monitoring notifications: internal inbox plus optional Apprise."""

from __future__ import annotations

from itsm.notifications.models import NotificationBase
from itsm.notifications.service import (
    NotificationService,
    process_notifications,
    record_alert_event,
)

__all__ = [
    "NotificationBase",
    "NotificationService",
    "process_notifications",
    "record_alert_event",
]
