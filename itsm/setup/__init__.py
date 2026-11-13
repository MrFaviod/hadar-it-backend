"""Independent setup and onboarding service for a new Hadar IT installation.

The setup application is deliberately separate from :mod:`itsm.main`: it never
opens the application database, never imports the domain API and answers even
while the backend and PostgreSQL are absent. Only ``dev`` and ``prod`` expose
it; the demo installation keeps its own path. The operator enables the service
and obtains a one-time claim credential from the local CLI.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
