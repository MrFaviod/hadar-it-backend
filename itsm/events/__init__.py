"""Reliable entity-change feed: transactional outbox, cursors and references.

The core writes one ``entity_change_events`` row in the same transaction as the
asset or incident history it derives from, so an extension never has to poll the
core schema or hold a hidden dependency on the core database. Consumers keep a
monotonic cursor in ``entity_event_consumers``; see ``docs/entity-events.md``.
"""

from __future__ import annotations

from itsm.events.outbox import install_event_listeners

install_event_listeners()

__all__ = ["install_event_listeners"]
