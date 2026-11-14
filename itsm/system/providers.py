"""Allowlisted AI provider selection consumed by the integrated agent runtime.

The persisted row is application-owned state. Credential values are never read
into this module's public payloads: only the name of the external environment
variable and whether it is currently configured are exposed.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.system.models import SystemProviderSettings

CLASSIFICATIONS: Final[tuple[str, ...]] = ("development", "test", "production")
MAINTENANCE_WINDOWS: Final[tuple[str, ...]] = ("anytime", "outside_business_hours")
PROVIDER_CATALOG: Final[dict[str, dict[str, object]]] = {
    "openai": {
        "id": "openai",
        "label": "OpenAI",
        "credentialEnv": ("OPENAI_API_KEY",),
    },
    "anthropic": {
        "id": "anthropic",
        "label": "Anthropic",
        "credentialEnv": ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
    },
}
PROVIDER_IDS: Final[tuple[str, ...]] = tuple(PROVIDER_CATALOG)
MODEL_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$")


class ProviderSelectionError(ValueError):
    """Caller-supplied provider or model is outside the installation allowlist."""


@dataclass(frozen=True)
class ProviderSelection:
    provider: str
    model: str
    source: str
    updated_at: datetime | None = None
    updated_by: str | None = None
    provider_id: str | None = None


def validate_selection(provider: object, model: object) -> tuple[str, str]:
    """Return normalized values or raise for anything outside the allowlist."""
    if not isinstance(provider, str) or provider not in PROVIDER_CATALOG:
        raise ProviderSelectionError("provider is not allowlisted")
    if not isinstance(model, str) or not MODEL_PATTERN.fullmatch(model.strip()):
        raise ProviderSelectionError("model is not a bounded provider model id")
    return provider, model.strip()


def parse_agent_model(value: str) -> tuple[str, str] | None:
    """Parse the existing ``provider:model`` installation default."""
    provider, separator, model = value.partition(":")
    if not separator:
        return None
    try:
        return validate_selection(provider, model)
    except ProviderSelectionError:
        return None


def credential_configured(provider: str, environ: Mapping[str, str] | None = None) -> bool:
    values = os.environ if environ is None else environ
    entry = PROVIDER_CATALOG.get(provider)
    if entry is None:
        return False
    return any(bool(values.get(name)) for name in entry["credentialEnv"])  # type: ignore[union-attr]


def provider_descriptors(environ: Mapping[str, str] | None = None) -> list[dict[str, object]]:
    return [
        {
            "id": entry["id"],
            "label": entry["label"],
            "credentialConfigured": credential_configured(provider_id, environ),
            "credentialEnv": list(entry["credentialEnv"]),  # type: ignore[arg-type]
        }
        for provider_id, entry in PROVIDER_CATALOG.items()
    ]


def persisted_selection(session: Session) -> ProviderSelection | None:
    """Read only the persisted row; a missing table degrades to unset."""
    try:
        row = session.get(SystemProviderSettings, 1)
    except SQLAlchemyError:
        session.rollback()
        return None
    if row is None:
        return None
    try:
        provider, model = validate_selection(row.provider, row.model)
    except ProviderSelectionError:
        return None
    return ProviderSelection(
        provider=provider,
        model=model,
        source="installation",
        updated_at=row.updated_at,
        updated_by=row.updated_by,
        provider_id=getattr(row, "provider_id", None),
    )


def effective_selection(session: Session, settings: Settings) -> ProviderSelection | None:
    """Installation selection first, then the process-level installation default."""
    stored = persisted_selection(session)
    if stored is not None:
        return stored
    parsed = parse_agent_model(settings.agent_model)
    if parsed is None:
        return None
    return ProviderSelection(provider=parsed[0], model=parsed[1], source="environment")


def selection_payload(selection: ProviderSelection | None) -> dict[str, object] | None:
    if selection is None:
        return None
    return {
        "provider": selection.provider,
        "model": selection.model,
        "source": selection.source,
        "updatedAt": (None if selection.updated_at is None else selection.updated_at.isoformat()),
        "updatedBy": selection.updated_by,
    }
