"""Development maintenance CLI: ``python -m itsm.devtools <command>``.

The package only exists for the ``dev`` release mode. Every command refuses to
run for any other mode, and the destructive commands additionally require a
local database, a ``dev`` deployment identity claimed by a dev process and an
explicit confirmation naming the target (S3, S4, S5).
"""

from __future__ import annotations

from itsm.devtools.cli import main

__all__ = ["main"]
