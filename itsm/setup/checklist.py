"""The verification checklist for assisted configuration.

The checklist is built from observations, never from intent: every item carries
the evidence that produced its state, and a status only counts as green when the
setup process actually read it back. Postponable items stay visible as
``postponed`` and never become green. Capabilities that this release does not
ship are reported as ``unavailable`` instead of being claimed as ready, and a
missing production backup can only be accepted as a recorded risk.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MODES: tuple[str, ...] = ("dev", "prod")
SECTIONS: tuple[str, ...] = (
    "agent",
    "appearance",
    "notifications",
    "monitoring",
    "operational",
)
POSTPONABLE_SECTIONS: tuple[str, ...] = ("notifications", "monitoring")

#: Statuses that satisfy a required item. ``risk`` only satisfies the one item
#: that the operator is allowed to accept explicitly, and ``declared`` is a
#: policy the operator stated (read back from the installation database), never
#: an observed backup status.
GREEN = "passed"
DECLARED = "declared"
_PASSING = frozenset({GREEN})


@dataclass(frozen=True)
class Requirement:
    """One contract requirement and where it is decided."""

    id: str
    section: str
    required: tuple[str, ...]
    postponable: tuple[str, ...]


REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement("setup_enabled", "operational", MODES, ()),
    Requirement("claim_completed", "operational", MODES, ()),
    Requirement("ai_explicit", "agent", MODES, ()),
    Requirement("database_ready", "operational", MODES, ()),
    Requirement("migrated", "operational", MODES, ()),
    Requirement("owner_present", "operational", MODES, ()),
    Requirement("origin_valid", "operational", MODES, ()),
    Requirement("session_valid", "operational", ("prod",), ()),
    Requirement("worker_ready", "operational", MODES, ()),
    Requirement("storage_ready", "operational", MODES, ()),
    Requirement("appearance_decided", "appearance", MODES, ()),
    Requirement("backup_policy_declared", "operational", ("prod",), ("dev",)),
    Requirement("smtp", "notifications", (), MODES),
    Requirement("monitoring", "monitoring", (), MODES),
    Requirement("external_search", "", (), MODES),
    Requirement("external_engines", "", (), MODES),
    Requirement("integrations", "", (), MODES),
)

_BY_ID = {item.id: item for item in REQUIREMENTS}


def requirement(identifier: str) -> Requirement:
    return _BY_ID[identifier]


def section_required(mode: str, section: str) -> bool:
    return any(mode in item.required for item in REQUIREMENTS if item.section == section)


def section_postponable(section: str) -> bool:
    return section in POSTPONABLE_SECTIONS


def _status(
    requirement_id: str,
    *,
    mode: str,
    observations: dict[str, dict[str, Any]],
    configuration: dict[str, Any],
) -> dict[str, Any]:
    """Resolve one item from operational observations and stored receipts."""

    requirement = _BY_ID[requirement_id]

    if requirement_id.startswith("external_"):
        return {
            "status": "unavailable",
            "evidence": "this capability is not offered by the current release",
        }
    if requirement_id == "session_valid" and mode == "dev":
        return {
            "status": "not_required",
            "evidence": "the contract does not require a secure session in dev",
        }

    sections = (configuration.get("sections") or {}) if isinstance(configuration, dict) else {}
    entry = sections.get(requirement.section) if requirement.section else None
    receipt = entry.get("receipt") if isinstance(entry, dict) else None
    section_status = entry.get("status") if isinstance(entry, dict) else None

    if requirement_id == "ai_explicit":
        ai = observations.get("ai") or {}
        if ai.get("pending"):
            return {"status": "pending", "evidence": "AI was explicitly deferred"}
        if section_status == GREEN and (receipt or {}).get("capability") == "verified":
            return {
                "status": GREEN,
                "evidence": (
                    "provider settings persisted; credential present; "
                    f"tool {(receipt or {}).get('tool') or 'probe'} answered"
                ),
            }
        if section_status == "pending" and receipt:
            return {
                "status": "pending",
                "evidence": str(receipt.get("reason") or "agent capability not verified"),
            }
        return {"status": "pending", "evidence": "no verified agent provider recorded"}

    if requirement_id == "appearance_decided":
        if section_status == GREEN:
            return {
                "status": GREEN,
                "evidence": (
                    f"active appearance {receipt.get('active_id') if receipt else 'preset'}"
                ),
            }
        return {"status": "pending", "evidence": "no appearance decision recorded"}

    if requirement_id == "smtp":
        if section_status == "postponed":
            return {"status": "postponed", "evidence": "postponed by the operator"}
        if section_status == GREEN:
            return {"status": GREEN, "evidence": "SMTP channel saved and read back"}
        return {"status": "pending", "evidence": "no notification channel configured"}

    if requirement_id == "monitoring":
        if section_status == "postponed":
            return {"status": "postponed", "evidence": "postponed by the operator"}
        if section_status == GREEN:
            return {"status": GREEN, "evidence": "monitoring profile updated and read back"}
        return {"status": "pending", "evidence": "no monitoring profile configured"}

    if requirement_id == "backup_policy_declared":
        if section_status == "risk":
            reason = str((receipt or {}).get("reason") or "accepted without a reason")
            return {
                "status": "risk",
                "evidence": f"accepted risk: {reason}",
                "acceptedRisk": True,
            }
        observation = observations.get(requirement_id) or {}
        return {
            "status": str(observation.get("status") or "pending"),
            "evidence": str(observation.get("evidence") or "backup policy not observed"),
        }

    observation = observations.get(requirement_id) or {}
    return {
        "status": str(observation.get("status") or "pending"),
        "evidence": str(observation.get("evidence") or "not observed"),
    }


def build_checklist(
    mode: str,
    *,
    configuration: dict[str, Any] | None = None,
    observations: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return every contract item with its state, evidence and blocking flag."""

    record = configuration or {}
    observed = observations or {}
    items: list[dict[str, Any]] = []
    for requirement in REQUIREMENTS:
        resolved = _status(
            requirement.id,
            mode=mode,
            observations=observed,
            configuration=record,
        )
        required = mode in requirement.required
        postponable = mode in requirement.postponable
        status = resolved["status"]
        accepted_risk = bool(resolved.get("acceptedRisk"))
        satisfied = status in _PASSING or (
            requirement.id == "backup_policy_declared" and (accepted_risk or status == DECLARED)
        )
        blocking = required and not satisfied
        items.append(
            {
                "id": requirement.id,
                "section": requirement.section,
                "required": required,
                "postponable": postponable,
                "status": status,
                "evidence": resolved["evidence"],
                "blocking": blocking,
                "acceptedRisk": accepted_risk,
            }
        )
    blocking_ids = [item["id"] for item in items if item["blocking"]]
    accepted = [item["id"] for item in items if item["acceptedRisk"]]
    return {
        "mode": mode,
        "ready": not blocking_ids,
        "checklist": items,
        "blocking": blocking_ids,
        "acceptedRisk": accepted,
    }


__all__ = [
    "MODES",
    "POSTPONABLE_SECTIONS",
    "REQUIREMENTS",
    "SECTIONS",
    "Requirement",
    "build_checklist",
    "requirement",
    "section_postponable",
    "section_required",
]
