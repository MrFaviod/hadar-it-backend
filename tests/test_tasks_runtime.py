"""Task runtime configuration: opt-in periodic demo scheduling."""

from __future__ import annotations

from collections.abc import Callable

from itsm.config import Settings
from itsm.tasks.runtime import build_runtime


def test_periodic_demo_is_disabled_by_default(
    settings_factory: Callable[..., Settings],
) -> None:
    runtime = build_runtime(settings_factory())

    assert runtime.demo.periodic is None


def test_periodic_demo_is_registered_when_configured(
    settings_factory: Callable[..., Settings],
) -> None:
    runtime = build_runtime(settings_factory(demo_periodic_minutes=1))

    assert runtime.demo.periodic is not None
