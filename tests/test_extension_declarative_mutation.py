"""Declarative writes are gated by their declared ``mutation`` flag.

A declarative ``put``/``delete`` changes the module's collection, so it must
declare ``mutation: true``; ``list``/``get`` must not.  The host opens the store
read-write only for an invoked declaration that carries the flag, which keeps a
read permission from buying a write through the declarative runtime.
"""

# ruff: noqa: F811 - the `env` fixture is imported and also named in signatures.

from __future__ import annotations

import pytest
from itsm.extensions.errors import ExtensionValidationFailed
from itsm.extensions.host import ExtensionHostService
from tests.test_extension_runtime_support import (  # noqa: F401 - fixtures
    DECLARATIVE_ID,
    build_package,
    declarative_manifest,
    env,
)


def test_declarative_put_without_the_mutation_flag_is_not_admitted(env) -> None:
    """R3-F4: a read permission cannot buy a write through a declarative kind."""
    declaration = declarative_manifest()
    for operation in declaration["operations"]:
        if operation["name"] == "put_note":
            operation["permission"] = "ext_declarative_notes.read"
            operation["mutation"] = False
    with pytest.raises(ExtensionValidationFailed) as failure:
        env.install(build_package(declaration, backend=None))
    assert "mutation" in str(failure.value)


def test_declarative_store_write_is_gated_by_the_mutation_flag(env, monkeypatch) -> None:
    env.install(build_package(declarative_manifest(), backend=None))
    captured: list[bool] = []
    original = ExtensionHostService._store

    def capture(self, connection, loaded, *, allow_write):
        captured.append(allow_write)
        return original(self, connection, loaded, allow_write=allow_write)

    monkeypatch.setattr(ExtensionHostService, "_store", capture)
    env.invoke("get_note", {"record_id": "missing"}, extension_id=DECLARATIVE_ID)
    env.invoke(
        "put_note",
        {"record_id": "note-1", "data": {"label": "Nota declarativa"}},
        extension_id=DECLARATIVE_ID,
    )
    assert captured == [False, True]
