"""Shared native SDK composition for HTTP, chat, MCP and worker contexts."""

from __future__ import annotations

from collections.abc import Callable
from functools import partial
from typing import Any

from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.identity.permissions import PERMISSION_CODES
from itsm.identity.service import IdentityService


def create_extension_services(
    settings: Settings, session_factory: Callable[[], Session]
) -> tuple[Any, Any]:
    """Bind canonical host authority once; never inspect a candidate on startup."""
    from itsm.extensions.development import DevelopmentService
    from itsm.extensions.host import ExtensionHostService
    from itsm.extensions.notifications import enqueue_extension_notice
    from itsm.extensions.validator import ContainerValidator, RemoteContainerValidator

    # The host owns pack install/uninstall, so it is also where the versioned
    # catalog overlay is bound to this application's session factory.
    from itsm.i18n import registry

    registry.configure(session_factory)
    host = ExtensionHostService(
        settings,
        session_factory,
        notify=partial(enqueue_extension_notice, settings=settings),
    )
    validator = (
        RemoteContainerValidator(
            settings.extension_validator_url,
            token=settings.extension_validator_token.get_secret_value(),
            timeout=settings.extension_validation_timeout_seconds + 15,
        )
        if settings.extension_validator_url and settings.extension_validator_token
        else ContainerValidator(
            core_permissions=PERMISSION_CODES,
            image=settings.extension_validator_image,
            timeout=settings.extension_validation_timeout_seconds,
        )
    )
    development = DevelopmentService(
        settings.extension_workspace_path,
        session_factory=session_factory,
        identity_factory=lambda session: IdentityService(session, settings),
        validator=validator,
        known_core_permissions=PERMISSION_CODES,
        host=host,
    )
    return host, development
