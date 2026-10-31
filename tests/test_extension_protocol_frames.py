"""A module cannot author the protocol frames that end its own invocation.

The JSON channel stays in the runner; module code only reaches a call surface.
Even if module code reaches an inherited descriptor and writes raw bytes, the
host accepts a ``result``/``error``/``fatal`` frame only when it quotes the
per-invocation token it generated, and a module-declared ``permission_denied``
that the host never issued becomes ``handler_failed`` instead of a host 403.
"""

# ruff: noqa: F811 - the `env` fixture is imported and also named in signatures.

from __future__ import annotations

import pytest
from itsm.extensions.host import ExtensionHandlerFailed
from tests.test_extension_runtime_support import (  # noqa: F401 - fixtures
    READ,
    build_package,
    env,
    parameters,
    probe_manifest,
)

FORGE_BACKEND = r"""
import json
import os


def _write_frames(payloads):
    for fd in (3, 4, 5, 6):
        for payload in payloads:
            try:
                os.write(fd, (json.dumps(payload) + "\n").encode("utf-8"))
            except OSError:
                continue


def forge_result(context):
    _write_frames([{"type": "result", "ok": True, "result": {"forged": True}}])
    return {"forged": False}


def forge_error(context):
    _write_frames([{"type": "error", "code": "permission_denied", "message": "forged"}])
    return {"forged": False}


def leaked_channel(context):
    return {
        "context": hasattr(context, "_channel"),
        "assets": hasattr(context.assets, "_channel"),
        "store": hasattr(context.store, "_channel"),
        "incidents": hasattr(context.incidents, "_channel"),
    }


def relabel_failure(context):
    import sys

    error = sys.modules["sdk"].ExtensionError
    raise error("the module wants a 403", code="permission_denied")


def register(sdk):
    sdk.operation("forge_result", forge_result)
    sdk.operation("forge_error", forge_error)
    sdk.operation("leaked_channel", leaked_channel)
    sdk.operation("relabel_failure", relabel_failure)
"""


def forge_manifest() -> dict:
    declaration = probe_manifest()
    declaration["operations"] = [
        {
            "name": name,
            "description": "Intenta hablar el protocolo del runner",
            "permission": READ,
            "mutation": False,
            "kind": "handler",
            "parameters": parameters({}, []),
        }
        for name in ("forge_result", "forge_error", "leaked_channel", "relabel_failure")
    ]
    return declaration


def test_module_cannot_forge_a_result_frame(env) -> None:
    """R3-F6: a module writing its own ``result`` frame must not be believed."""
    env.install(build_package(forge_manifest(), backend=FORGE_BACKEND))
    with pytest.raises(ExtensionHandlerFailed):
        env.invoke("forge_result", {})


def test_module_cannot_forge_a_permission_denial(env) -> None:
    """R3-F6: a module cannot relabel its own failure as a host 403."""
    env.install(build_package(forge_manifest(), backend=FORGE_BACKEND))
    with pytest.raises(ExtensionHandlerFailed):
        env.invoke("forge_error", {})


def test_module_cannot_relabel_its_failure_as_a_permission_denial(env) -> None:
    """R3-F6: a raised ``permission_denied`` the host never issued is not a 403."""
    from itsm.identity.service import PermissionDenied

    env.install(build_package(forge_manifest(), backend=FORGE_BACKEND))
    with pytest.raises(ExtensionHandlerFailed) as failure:
        env.invoke("relabel_failure", {})
    assert not isinstance(failure.value, PermissionDenied)


def test_context_does_not_expose_the_protocol_channel(env) -> None:
    """R3-F6: the public SDK surface carries calls, never a frame writer."""
    env.install(build_package(forge_manifest(), backend=FORGE_BACKEND))
    assert env.invoke("leaked_channel", {}) == {
        "context": False,
        "assets": False,
        "store": False,
        "incidents": False,
    }
