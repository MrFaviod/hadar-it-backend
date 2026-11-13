"""Capability flags the running installation can actually evidence.

The documentation service only groups flags the caller supplies; it never invents
one. This module supplies the flags this process can observe from its own state:
the documentation pack it just loaded, whether an AI provider model is configured,
and whether extension modules are installed. A capability it cannot evidence is
returned as ``unknown`` instead of being reported as available.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

CAPABILITY_NAMES: tuple[str, ...] = ("documentation", "agent", "extensions")

#: Evidence the process can read without a database or a network call.
States = dict[str, str]


@dataclass(frozen=True)
class CapabilityEvidence:
    """Observed states plus the names this process could not evidence."""

    flags: States
    unknown: tuple[str, ...]


def capability_evidence(
    settings: Any = None,
    *,
    documentation_installed: bool = False,
) -> CapabilityEvidence:
    """Report only what configuration proves; never guess ``available`` or ``wip``.

    ``documentation_installed`` is set by the caller after the pack loaded, so the
    flag always reflects a real read rather than an assumption about the image.
    """
    flags: States = {}
    if documentation_installed:
        flags["documentation"] = "installed"
    if settings is not None:
        if str(getattr(settings, "agent_model", "") or "").strip():
            flags["agent"] = "configured"
        if getattr(settings, "agent_extension_modules", None):
            # Naming a module proves configuration, not that its host loaded it, so the
            # state stays below "installed" until an extension surface reports itself.
            flags["extensions"] = "configured"
    unknown = tuple(name for name in CAPABILITY_NAMES if name not in flags)
    return CapabilityEvidence(flags=flags, unknown=unknown)
