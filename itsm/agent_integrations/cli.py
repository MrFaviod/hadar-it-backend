"""Destination-host installer helper; executes exactly one scoped request."""

from __future__ import annotations

from collections.abc import Sequence

from itsm.agent_integrations.installer import main as _installer_main


def main(argv: Sequence[str] | None = None) -> int:
    """Run the installer helper without any remote-shell capability."""
    return _installer_main(argv)


__all__ = ["main"]
