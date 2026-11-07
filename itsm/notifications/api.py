"""HTTP adapter for notification configuration, inbox and delivery tests."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from itsm.identity.api import authenticated_actor, mutation_guard
from itsm.identity.service import AuthContext, IdentityService
from itsm.notifications.service import DEFAULT_LIMIT, NotificationService


class ScheduleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timezone: str = Field(min_length=1, max_length=64)
    start: str = Field(pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
    end: str = Field(pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]$")


class ChannelInput(BaseModel):
    """No raw credential is accepted; only a deployment secret reference."""

    model_config = ConfigDict(extra="forbid")

    id: str | None = Field(default=None, min_length=1, max_length=36)
    kind: Literal["internal", "smtp", "telegram"] | None = None
    name: str | None = Field(default=None, min_length=1, max_length=120)
    enabled: bool | None = None
    secretRef: str | None = Field(default=None, max_length=64)
    config: dict[str, str] | None = None


class RuleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str | None = Field(default=None, min_length=1, max_length=36)
    name: str | None = Field(default=None, min_length=1, max_length=120)
    enabled: bool | None = None
    minimumSeverity: Literal["info", "warning", "critical"] | None = None
    recipientIds: list[str] | None = Field(default=None, max_length=100)
    channelIds: list[str] | None = Field(default=None, max_length=20)
    escalationRecipientIds: list[str] | None = Field(default=None, max_length=100)
    schedule: ScheduleInput | None = None
    acknowledgeAfterSeconds: int | None = Field(default=None, ge=0, le=604800)
    retryIntervalSeconds: int | None = Field(default=None, ge=0, le=86400)
    escalateAfterSeconds: int | None = Field(default=None, ge=0, le=604800)
    maxAttempts: int | None = Field(default=None, ge=1, le=10)


def get_notification_service(request: Request) -> Iterator[NotificationService]:
    session = request.app.state.session_factory()
    try:
        settings = request.app.state.settings
        yield NotificationService(
            session, settings, identity=IdentityService(session, settings)
        )
    finally:
        session.close()


NotificationDependency = Annotated[NotificationService, Depends(get_notification_service)]
AuthDependency = Annotated[AuthContext, Depends(authenticated_actor)]
MutationDependency = Annotated[AuthContext, Depends(mutation_guard)]


def create_notification_router() -> APIRouter:
    """Notification routes, mounted under the versioned API prefix."""
    router = APIRouter()

    @router.get("/notifications/inbox")
    def list_inbox(
        service: NotificationDependency,
        context: AuthDependency,
        limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        unread: bool | None = Query(default=None),
    ) -> dict[str, Any]:
        return service.list_inbox(context.principal, limit, offset, unread)

    @router.post("/notifications/inbox/{notification_id}/read")
    def mark_read(
        notification_id: str,
        service: NotificationDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.mark_read(context.principal, notification_id)

    @router.get("/notifications/config")
    def get_config(
        service: NotificationDependency, context: AuthDependency
    ) -> dict[str, Any]:
        return service.get_config(context.principal)

    @router.post("/notifications/channels")
    def save_channel(
        payload: ChannelInput,
        service: NotificationDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.save_channel(
            context.principal, payload.model_dump(exclude_unset=True)
        )

    @router.post("/notifications/rules")
    def save_rule(
        payload: RuleInput,
        service: NotificationDependency,
        context: MutationDependency,
    ) -> dict[str, Any]:
        return service.save_rule(context.principal, payload.model_dump(exclude_unset=True))

    @router.post("/notifications/channels/{channel_id}/test", status_code=202)
    def test_channel(
        channel_id: str,
        service: NotificationDependency,
        context: MutationDependency,
        payload: dict[str, Any] | None = Body(default=None),
    ) -> dict[str, Any]:
        # The body is intentionally unused: the deployment-owned channel is the
        # only possible destination, so a request cannot supply a URL or token.
        return service.test_channel(context.principal, channel_id)

    return router
