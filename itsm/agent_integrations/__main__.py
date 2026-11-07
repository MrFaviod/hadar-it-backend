"""Allow ``python -m itsm.agent_integrations --request <path>``."""

from __future__ import annotations

from itsm.agent_integrations.cli import main

if __name__ == "__main__":  # pragma: no cover - process entrypoint
    raise SystemExit(main())
