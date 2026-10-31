"""The static admission scan must not read a capability name as SQL.

``assets.create`` is a permission/capability label, not a statement.  The
keyword-only heuristic refused it and blocked legitimate modules, so the check
now requires a structural keyword as well and skips capability literals.  This
is an authoring guard, never an isolation boundary (see the SDK guide).
"""

from __future__ import annotations

import pytest
from itsm.extensions.manifest import PackageError, inspect_package
from tests.test_extension_runtime_support import (
    PROBE_BACKEND,
    build_package,
    probe_manifest,
)


def test_capability_literals_are_not_mistaken_for_sql() -> None:
    """A capability label such as ``assets.create`` is not a SQL statement."""
    labels = (
        "def capability_labels(context):\n"
        "    return [context.authorize('assets.create'), 'assets.write', 'store.put']\n\n"
    )
    inspect_package(build_package(probe_manifest(), backend=labels + PROBE_BACKEND))

    for literal in ("SELECT name FROM sqlite_master", "UPDATE assets SET name = 'x'"):
        source = f"def extra_sql(context):\n    return {literal!r}\n\n"
        with pytest.raises(PackageError) as failure:
            inspect_package(build_package(probe_manifest(), backend=source + PROBE_BACKEND))
        assert "contract_gap_required" in str(failure.value)
