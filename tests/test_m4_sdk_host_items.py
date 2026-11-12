"""The public extension host rejects bad array items before executing a handler."""

from __future__ import annotations

import pytest
from itsm.extensions.errors import ExtensionValidationFailed
from tests.test_extension_runtime_support import (
    build_package,
    env,  # noqa: F401 - pytest fixture
    probe_manifest,
)


def test_host_checks_items_before_handler_and_accepts_supported_values(env):  # noqa: F811
    manifest = probe_manifest()
    manifest["operations"][0]["parameters"]["properties"]["value"] = {
        "type": "array",
        "items": {"type": "string"},
    }
    env.install(build_package(manifest))
    before = env.invoke("list_records")
    with pytest.raises(ExtensionValidationFailed, match=r"value\[0\]"):
        env.invoke("echo", {"value": [{"unexpected": True}]})
    assert env.invoke("list_records") == before
    assert env.invoke("echo", {"value": ["supported"]})["value"] == ["supported"]
