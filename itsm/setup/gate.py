"""Read the installation completion marker for the setup process.

The marker lives in the application database and is read through
:mod:`itsm.installation`; this module only adapts it to the setup app without
ever importing :mod:`itsm.main` or trusting the private state directory alone.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from itsm.installation import InstallationState, state_from_environ


class InstallationGate:
    """Answer whether setup is still open, preferring the database marker."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ

    def current(self) -> InstallationState:
        source = os.environ if self._environ is None else self._environ
        return state_from_environ(source)


__all__ = ["InstallationGate"]
