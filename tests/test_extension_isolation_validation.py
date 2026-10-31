"""Offline harness evidence for SDK v2 packages.

The harness is the only validator that runs without Docker, so its report must
describe each check exactly once and must exercise both runtimes: sandboxed
packages through the bounded candidate subprocess, declarative packages through
host-side evidence only.
"""

from __future__ import annotations

import pytest
from itsm.extensions.sdk.generator import generate_package
from itsm.extensions.sdk.package import build_package
from itsm.extensions.sdk.validator import harness
from itsm.extensions.sdk.validator.harness import ValidationFailure, validate_payload
from itsm.extensions.sdk.validator.protocol import build_frame


def _report(runtime: str) -> dict:
    generated = generate_package(
        extension_id=f"demo-{runtime}",
        name="Demo",
        description="Demo module for the validation suite.",
        runtime=runtime,
    )
    built = build_package(generated.files, known_core_permissions=())
    report = validate_payload(
        build_frame(built.data, digest=built.digest, known_core_permissions=())
    )
    assert report["status"] == "passed", report["errors"]
    return report


@pytest.mark.parametrize("runtime", ["sandboxed", "declarative"])
def test_report_lists_each_check_once(runtime: str) -> None:
    report = _report(runtime)
    names = [check["name"] for check in report["checks"]]
    assert len(names) == len(set(names)), names
    assert report["sdkVersion"] == 2


def test_declarative_report_has_no_execution_check() -> None:
    report = _report("declarative")
    names = {check["name"] for check in report["checks"]}
    assert "execution" not in names
    assert "registration" in names and "operations" in names
    details = {check["name"]: check["detail"] for check in report["checks"]}
    assert details["backend"] == "declarative runtime ships no executable backend"
    assert "declarative view" in details["frontend"]


def test_missing_javascript_engine_reports_a_failed_frontend_check(monkeypatch) -> None:
    from tests.test_extension_runtime_support import (
        PROBE_BACKEND,
        build_package,
        probe_manifest,
    )

    manifest = probe_manifest()
    manifest["frontend"] = {
        "entry": "frontend.js",
        "pages": [
            {
                "id": "board",
                "label": "Board",
                "permission": "ext_probe.read",
                "view": {"isolated": {"component": "ProbeBoard"}},
            }
        ],
        "assetPanels": [],
        "contributions": [],
    }
    built = build_package(
        manifest,
        backend=PROBE_BACKEND,
        frontend="window.ITSMExtension.register({components: {ProbeBoard: {}}});",
    )
    monkeypatch.setattr(
        harness,
        "_js_engine",
        lambda: (_ for _ in ()).throw(ValidationFailure("no javascript engine available")),
    )
    report = validate_payload(
        build_frame(
            built, digest=__import__("hashlib").sha256(built).hexdigest(), known_core_permissions=()
        )
    )
    assert report["status"] == "failed"
    detail = {check["name"]: check["detail"] for check in report["checks"]}["frontend"]
    assert detail.startswith("ValidationFailure:")
    assert "no javascript engine available" in detail
