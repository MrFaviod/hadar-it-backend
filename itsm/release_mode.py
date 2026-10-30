"""Release modes: one codebase, one runtime mode per process.

The mode is selected by the unprefixed environment variable ``RELEASE_MODE`` and
must be exactly one of ``dev``, ``prod`` or ``demo``. Absent, empty or invalid
values refuse to start: there is no default mode and no capability fallback, so
a typo can never enable a permissive behaviour by accident (S1, S2).

Public interface:

* :func:`read_release_mode` — parse ``RELEASE_MODE`` or raise
  :class:`ReleaseModeError`.
* :func:`capabilities_for` — the frozen :class:`ModeCapabilities` of a mode.

Everything else in the backend must ask :func:`capabilities_for` instead of
re-reading the environment variable, so one process cannot observe two modes.
This module deliberately reads nothing else: database ownership lives in
:mod:`itsm.release_identity`.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

ReleaseMode = Literal["dev", "prod", "demo"]

RELEASE_MODE_ENV = "RELEASE_MODE"

#: Accepted values, in the order shown to operators in error messages.
RELEASE_MODES: tuple[ReleaseMode, ...] = ("dev", "prod", "demo")

#: Maximum length echoed back when the configured value is invalid.
_MAX_ECHOED_VALUE = 32


class ReleaseModeError(RuntimeError):
    """Startup is refused: the configured release mode is unusable.

    The message is written for the operator, never for an end user, and never
    contains credentials.
    """


@dataclass(frozen=True)
class ModeCapabilities:
    """What one release mode is allowed to do.

    The flags are intentionally coarse and are consumed by the features they
    gate; a flag is a permission, never an implementation.

    Attributes:
        allow_system_operations: Run the operator-configured system executor.
        allow_extension_install: Install or update extension packages.
        allow_external_notifications: Deliver notifications outside the instance.
        allow_ai_providers: Call real configured model providers.
        allow_agents_dev: Run development agents against this process.
        allow_seed: Prepare sample or demonstration data automatically.
        allow_destructive_reset: Reset or regenerate the data in this database.
        auto_migrate: Apply migrations automatically at startup instead of the
            controlled one-shot upgrade procedure.
    """

    allow_system_operations: bool
    allow_extension_install: bool
    allow_external_notifications: bool
    allow_ai_providers: bool
    allow_agents_dev: bool
    allow_seed: bool
    allow_destructive_reset: bool
    auto_migrate: bool


#: Frozen capability matrix. ``prod`` is conservative, ``demo`` disables every
#: dangerous capability and ``dev`` is permissive but still bound to a local
#: database by :mod:`itsm.release_identity`.
_CAPABILITIES: dict[ReleaseMode, ModeCapabilities] = {
    "dev": ModeCapabilities(
        allow_system_operations=True,
        allow_extension_install=True,
        allow_external_notifications=True,
        allow_ai_providers=True,
        allow_agents_dev=True,
        allow_seed=True,
        allow_destructive_reset=True,
        auto_migrate=True,
    ),
    "prod": ModeCapabilities(
        allow_system_operations=True,
        allow_extension_install=True,
        allow_external_notifications=True,
        allow_ai_providers=True,
        allow_agents_dev=False,
        allow_seed=False,
        allow_destructive_reset=False,
        auto_migrate=False,
    ),
    "demo": ModeCapabilities(
        allow_system_operations=False,
        allow_extension_install=False,
        allow_external_notifications=False,
        allow_ai_providers=False,
        allow_agents_dev=False,
        allow_seed=True,
        allow_destructive_reset=True,
        auto_migrate=False,
    ),
}


def read_release_mode(environ: Mapping[str, str] | None = None) -> ReleaseMode:
    """Return the configured release mode or refuse to start.

    Args:
        environ: Environment to read; defaults to the process environment.

    Returns:
        One of ``dev``, ``prod`` or ``demo``.

    Raises:
        ReleaseModeError: The variable is absent, empty or not an exact,
            lowercase mode name.
    """
    source = os.environ if environ is None else environ
    raw = source.get(RELEASE_MODE_ENV)
    accepted = ", ".join(RELEASE_MODES)
    if raw is None or raw == "":
        raise ReleaseModeError(
            f"{RELEASE_MODE_ENV} is required and must be one of: {accepted}; no default mode exists"
        )
    if raw not in RELEASE_MODES:
        shown = raw if len(raw) <= _MAX_ECHOED_VALUE else f"{raw[:_MAX_ECHOED_VALUE]}..."
        raise ReleaseModeError(
            f"{RELEASE_MODE_ENV}={shown!r} is invalid; expected exactly one of: {accepted}"
        )
    return cast(ReleaseMode, raw)


def capabilities_for(mode: ReleaseMode) -> ModeCapabilities:
    """Return the frozen capabilities of ``mode``.

    Args:
        mode: A parsed release mode.

    Returns:
        The immutable capability record for that mode.
    """
    return _CAPABILITIES[mode]
