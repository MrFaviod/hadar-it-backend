"""Actual OpenCode 2.1.2 profile-evidence protocol checks.

These unit tests exercise the installer boundary with the documented
``Config.Entry`` union and the location/data ``/api/skill`` envelope. They do
not start an engine, read a home directory, or use a model.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from itsm.agent_integrations.installer import (
    DEFAULT_AGENT,
    IntegrationTarget,
    _runtime_evidence,
    _TargetState,
    sha256_text,
)

SELECTED = ("itsm-inventory",)


def profile_state(tmp_path: Path) -> tuple[_TargetState, str]:
    root = tmp_path / "workspace"
    skill_file = root / ".opencode" / "skills" / "itsm-inventory" / "SKILL.md"
    skill_file.parent.mkdir(parents=True)
    skill_file.write_text("---\nname: itsm-inventory\n---\nInventory.\n")
    config = root / "opencode.json"
    config.write_text('{"default_agent":"itsm"}\n')
    text = '{"default_agent":"itsm"}\n'
    state = _TargetState(
        target=IntegrationTarget("opencode", str(root), None, "2.1.2"),
        root=root,
        engine="opencode",
        format="v2",
        version="2.1.2",
        profile=None,
        config_path=config,
        config_relative="opencode.json",
        config_text=text,
        config_exists=True,
        config_data={},
        skills_relative=".opencode/skills",
    )
    return state, sha256_text(text)


def managed_permissions() -> list[dict[str, str]]:
    return [
        {"action": "*", "resource": "*", "effect": "deny"},
        {"action": "itsm_*", "resource": "*", "effect": "allow"},
        {"action": "skill", "resource": "*", "effect": "deny"},
        {"action": "skill", "resource": "itsm-inventory", "effect": "allow"},
    ]


def runtime_evidence(
    state: _TargetState,
    digest: str,
    *,
    config: list[dict[str, Any]] | None = None,
    skills: dict[str, Any] | None = None,
    permissions: list[dict[str, str]] | None = None,
    saved: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "source": "opencode:http://127.0.0.1:1",
        "verified": True,
        "configDigest": digest,
        "targetPath": str(state.root),
        "location": {"directory": str(state.root)},
        "agent": {
            "id": "itsm",
            "name": "itsm",
            "mode": "primary",
            "hidden": False,
            "permissions": permissions or managed_permissions(),
        },
        "config": config
        if config is not None
        else [
            {"type": "directory", "path": str(state.root / ".opencode")},
            {
                "type": "document",
                "path": str(state.config_path),
                "info": {"default_agent": DEFAULT_AGENT},
            },
        ],
        "skills": skills
        if skills is not None
        else {
            "location": {"directory": str(state.root)},
            "data": [
                {
                    "id": "itsm-inventory",
                    "name": "itsm-inventory",
                    "path": str(
                        state.root / ".opencode" / "skills" / "itsm-inventory" / "SKILL.md"
                    ),
                },
                # OpenCode always registers embedded skills; the restricted
                # agent's wildcard deny makes them unavailable to the agent.
                {"id": "opencode.skill", "name": "opencode", "path": "/builtin/opencode.md"},
            ],
        },
        "savedPermissions": saved or [],
        "checks": [
            {"name": "inspection.config", "status": "pass", "detail": "entries"},
            {"name": "inspection.agent", "status": "pass", "detail": "agent"},
            {"name": "inspection.skills", "status": "pass", "detail": "skills"},
        ],
    }


def validate(state: _TargetState, digest: str, evidence: dict[str, Any]) -> tuple[str, bool, str]:
    return _runtime_evidence(
        evidence,
        engine="opencode",
        config_digest=digest,
        state=state,
        skill_names=list(SELECTED),
    )


def test_actual_v212_entries_and_skill_envelope_are_accepted(tmp_path: Path) -> None:
    state, digest = profile_state(tmp_path)
    status, verified, detail = validate(state, digest, runtime_evidence(state, digest))
    assert (status, verified) == ("pass", True), detail


def test_extra_config_sources_are_rejected(tmp_path: Path) -> None:
    state, digest = profile_state(tmp_path)
    base = [
        {"type": "directory", "path": str(state.root / ".opencode")},
        {
            "type": "document",
            "path": str(state.config_path),
            "info": {"default_agent": DEFAULT_AGENT},
        },
    ]
    extra_entries = [
        {"type": "directory", "path": str(tmp_path / "global" / "opencode")},
        {
            "type": "document",
            "path": str(tmp_path / "global" / "opencode" / "opencode.json"),
            "info": {"default_agent": DEFAULT_AGENT},
        },
    ]
    for extra in extra_entries:
        status, verified, _ = validate(
            state,
            digest,
            runtime_evidence(state, digest, config=[*base, extra]),
        )
        assert (status, verified) == ("fail", False)


def test_document_without_a_bound_path_is_rejected(tmp_path: Path) -> None:
    state, digest = profile_state(tmp_path)
    config = [
        {"type": "directory", "path": str(state.root / ".opencode")},
        {"type": "document", "info": {"default_agent": DEFAULT_AGENT}},
    ]
    status, verified, _ = validate(state, digest, runtime_evidence(state, digest, config=config))
    assert (status, verified) == ("fail", False)


def test_skill_inventory_must_bind_the_selected_profile(tmp_path: Path) -> None:
    state, digest = profile_state(tmp_path)
    skill_path = state.root / ".opencode" / "skills" / "itsm-inventory" / "SKILL.md"

    wrong_location = {
        "location": {"directory": str(tmp_path / "other")},
        "data": [{"id": "itsm-inventory", "name": "itsm-inventory", "path": str(skill_path)}],
    }
    wrong_path = {
        "location": {"directory": str(state.root)},
        "data": [
            {
                "id": "itsm-inventory",
                "name": "itsm-inventory",
                "path": str(tmp_path / "other" / "SKILL.md"),
            }
        ],
    }
    missing_selected = {
        "location": {"directory": str(state.root)},
        "data": [{"id": "opencode.skill", "name": "opencode", "path": "/builtin/opencode.md"}],
    }
    for skills in (wrong_location, wrong_path, missing_selected):
        status, verified, _ = validate(
            state, digest, runtime_evidence(state, digest, skills=skills)
        )
        assert (status, verified) == ("fail", False)


def test_unselected_skill_allowance_is_rejected(tmp_path: Path) -> None:
    state, digest = profile_state(tmp_path)
    permissions = [
        *managed_permissions(),
        {"action": "skill", "resource": "other", "effect": "allow"},
    ]
    skills = {
        "location": {"directory": str(state.root)},
        "data": [
            {
                "id": "itsm-inventory",
                "name": "itsm-inventory",
                "path": str(state.root / ".opencode" / "skills" / "itsm-inventory" / "SKILL.md"),
            },
            {"id": "other", "name": "other", "path": str(tmp_path / "other.md")},
        ],
    }
    status, verified, _ = validate(
        state,
        digest,
        runtime_evidence(state, digest, permissions=permissions, skills=skills),
    )
    assert (status, verified) == ("fail", False)


def test_hermes_profile_evidence_without_trusted_launch_is_rejected(tmp_path: Path) -> None:
    state, digest = profile_state(tmp_path)
    state.profile = "itsm"
    state.target = IntegrationTarget("hermes", str(state.root), "itsm", "0.16.0")
    evidence = runtime_evidence(state, digest)
    evidence["source"] = "hermes:http://127.0.0.1:1"
    evidence["runtime"] = {
        "profile": "itsm",
        "home": str(state.root),
        "capabilities": {"chat": True},
    }
    status, verified, detail = _runtime_evidence(
        evidence,
        engine="hermes",
        config_digest=digest,
        state=state,
        skill_names=list(SELECTED),
    )
    assert (status, verified) == ("fail", False)
    assert "launch" in detail.lower()
