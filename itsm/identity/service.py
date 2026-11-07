"""Identity services: authentication, sessions, authorization and administration.

Every business operation authorizes through :meth:`IdentityService.authorize`
against Casbin policies stored in the database, so an endpoint check alone can
never grant access. Principals are resolved from persisted identities; a caller
subsystem (API, Pydantic AI, FastMCP) never asserts its own role or identity.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.identity.clock import as_utc, utcnow
from itsm.identity.hashing import (
    burn_password_check,
    hash_password,
    hash_token,
    verify_password,
)
from itsm.identity.models import (
    Identity,
    IdentityAuditEvent,
    IdentityCredential,
    IdentityLoginAttempt,
    IdentityRole,
    IdentityRolePolicy,
    IdentitySecuritySettings,
    IdentitySession,
)
from itsm.identity.permissions import (
    ACTOR_KINDS,
    HUMAN_ACTOR_KIND,
    MACHINE_ACTOR_KINDS,
    MACHINE_FORBIDDEN_PERMISSIONS,
    PERMISSION_CATALOG,
    ROLE_ADMIN,
    ROLE_SUPERADMIN,
    SYSTEM_PERMISSIONS,
    SENSITIVE_MACHINE_PERMISSIONS,
    is_known_permission,
)
from itsm.identity.policy import PolicyEngine

USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
ATTEMPT_RETENTION = timedelta(hours=24)
MACHINE_TOKEN_PREFIX = "itsm_mk_"
SESSION_MINUTES_MIN = 5
SESSION_MINUTES_MAX = 1440
AUDIT_PAGE_MAX = 200
AUDIT_RESOURCE_MAX = 200


class IdentityError(Exception):
    """Base class for domain errors translated by the API layer."""


class ValidationFailed(IdentityError):
    """Caller input violates a documented identity rule."""


class Conflict(IdentityError):
    """The operation conflicts with persisted state or an invariant."""


class NotFound(IdentityError):
    """The requested identity or role does not exist."""


class AuthenticationFailed(IdentityError):
    """Generic authentication failure; never reveals which check failed."""

    def __init__(self, message: str = "invalid credentials") -> None:
        super().__init__(message)


class AccountThrottled(IdentityError):
    """Too many failed logins in the configured window."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("too many login attempts; try again later")
        self.retry_after_seconds = retry_after_seconds


class PermissionDenied(IdentityError):
    """Authorization denial; audited before it is raised."""

    def __init__(self, message: str = "permission denied") -> None:
        super().__init__(message)


class BootstrapRefused(IdentityError):
    """Installation bootstrap is only allowed on an empty human roster."""


@dataclass(frozen=True)
class UserView:
    id: str
    username: str
    name: str
    email: str | None
    role_id: str | None
    active: bool
    last_access: datetime | None
    person_id: str | None
    actor_kind: str


@dataclass(frozen=True)
class RoleView:
    id: str
    name: str
    permissions: tuple[str, ...]
    built_in: bool


@dataclass(frozen=True)
class Principal:
    """Resolved actor context; constructed only by this service module."""

    actor_id: str
    kind: str
    username: str
    display_name: str
    role_id: str | None
    delegated_by: str | None = None
    scopes: frozenset[str] = frozenset()
    execution_id: str | None = None
    authorization_ref: str | None = None
    session_id: str | None = None


@dataclass(frozen=True)
class AuthContext:
    principal: Principal
    permissions: frozenset[str]
    csrf_token: str | None
    session_minutes: int
    session_id: str | None = None


@dataclass(frozen=True)
class SessionGrant:
    principal: Principal
    permissions: frozenset[str]
    csrf_token: str
    session_minutes: int
    expires_at: datetime
    session_id: str
    token: str = field(repr=False)


@dataclass(frozen=True)
class MachineCredential:
    credential_id: str
    token: str = field(repr=False)


@dataclass(frozen=True)
class CurrentView:
    user: UserView
    permissions: frozenset[str]
    csrf_token: str | None
    session_minutes: int


@dataclass(frozen=True)
class StateView:
    users: tuple[UserView, ...]
    roles: tuple[RoleView, ...]
    session_minutes: int


@dataclass(frozen=True)
class CatalogView:
    permissions: tuple[str, ...]
    actor_kinds: tuple[str, ...]


@dataclass(frozen=True)
class AuditView:
    actor_id: str | None
    actor_kind: str
    actor_username: str | None
    action: str
    resource: str
    outcome: str
    created_at: datetime
    execution_id: str | None
    delegated_by: str | None
    authorization_ref: str | None


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit]


class IdentityService:
    """Domain service for identity, sessions and authorization."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        now: Callable[[], datetime] = utcnow,
    ) -> None:
        self._session = session
        self._settings = settings
        self._now = now

    # ------------------------------------------------------------------ views
    def _user_view(self, identity: Identity) -> UserView:
        return UserView(
            id=identity.id,
            username=identity.username,
            name=identity.name,
            email=identity.email,
            role_id=identity.role_id,
            active=bool(identity.active),
            last_access=as_utc(identity.last_access_at) if identity.last_access_at else None,
            person_id=identity.person_id,
            actor_kind=identity.actor_kind,
        )

    def _role_view(self, role: IdentityRole) -> RoleView:
        codes = self._session.execute(
            select(IdentityRolePolicy.resource, IdentityRolePolicy.operation)
            .where(IdentityRolePolicy.role_id == role.id)
            .order_by(IdentityRolePolicy.resource, IdentityRolePolicy.operation)
        ).all()
        return RoleView(
            id=role.id,
            name=role.name,
            permissions=tuple(f"{resource}.{operation}" for resource, operation in codes),
            built_in=bool(role.built_in),
        )

    def _user_views(self) -> tuple[UserView, ...]:
        rows = self._session.execute(select(Identity).order_by(Identity.username)).scalars()
        return tuple(self._user_view(identity) for identity in rows)

    def _role_views(self) -> tuple[RoleView, ...]:
        rows = self._session.execute(select(IdentityRole).order_by(IdentityRole.id)).scalars()
        return tuple(self._role_view(role) for role in rows)

    def session_minutes(self) -> int:
        row = self._session.get(IdentitySecuritySettings, 1)
        if row is None:
            return self._settings.auth_session_minutes_default
        return int(row.session_minutes)

    # ------------------------------------------------------------------ audit
    def _audit(
        self,
        *,
        actor_kind: str,
        action: str,
        resource: str,
        outcome: str,
        actor_id: str | None = None,
        actor_username: str | None = None,
        execution_id: str | None = None,
        delegated_by: str | None = None,
        authorization_ref: str | None = None,
    ) -> None:
        self._session.add(
            IdentityAuditEvent(
                created_at=self._now(),
                actor_id=actor_id,
                actor_kind=_clip(actor_kind, 32),
                actor_username=None if actor_username is None else _clip(actor_username, 64),
                action=_clip(action, 64),
                resource=_clip(resource, AUDIT_RESOURCE_MAX),
                outcome=_clip(outcome, 16),
                execution_id=None if execution_id is None else _clip(execution_id, 64),
                delegated_by=delegated_by,
                authorization_ref=(
                    None if authorization_ref is None else _clip(authorization_ref, 120)
                ),
            )
        )

    def _audit_denied(
        self, principal: Principal, identity: Identity, permission: str, resource: str
    ) -> None:
        self._audit(
            actor_id=identity.id,
            actor_kind=identity.actor_kind,
            actor_username=identity.username,
            action=permission,
            resource=resource,
            outcome="denied",
            execution_id=principal.execution_id,
            delegated_by=identity.delegated_by_id,
            authorization_ref=principal.authorization_ref,
        )

    # ----------------------------------------------------- validation helpers
    def _normalize_username(self, username: str) -> str:
        if not isinstance(username, str):
            raise ValidationFailed("username is required")
        normalized = username.strip().lower()
        if not USERNAME_PATTERN.match(normalized):
            raise ValidationFailed(
                "username must be 3-64 characters using a-z, 0-9, dot, underscore or hyphen"
            )
        return normalized

    def _normalize_name(self, name: str) -> str:
        if not isinstance(name, str):
            raise ValidationFailed("name is required")
        normalized = name.strip()
        if not 1 <= len(normalized) <= 120:
            raise ValidationFailed("name must be 1-120 characters")
        return normalized

    def _normalize_email(self, email: str | None) -> str | None:
        if email is None:
            return None
        normalized = email.strip()
        if not normalized:
            return None
        if len(normalized) > 254 or "@" not in normalized or any(ch.isspace() for ch in normalized):
            raise ValidationFailed("email is not valid")
        return normalized

    def _normalize_person_id(self, person_id: str | None) -> str | None:
        if person_id is None:
            return None
        normalized = person_id.strip()
        if not normalized:
            return None
        if len(normalized) > 64:
            raise ValidationFailed("person_id must be at most 64 characters")
        return normalized

    def _validate_password(self, password: str) -> str:
        minimum = self._settings.auth_password_min_length
        maximum = self._settings.auth_password_max_length
        if not isinstance(password, str) or not minimum <= len(password) <= maximum:
            raise ValidationFailed(f"password must be {minimum}-{maximum} characters")
        return password

    def _validate_actor_kind(self, actor_kind: str) -> str:
        if actor_kind not in ACTOR_KINDS:
            raise ValidationFailed("actor_kind is not supported")
        return actor_kind

    def _validate_permissions(self, permissions: Iterable[str]) -> tuple[str, ...]:
        if isinstance(permissions, str):
            raise ValidationFailed("permissions must be a list of permission codes")
        cleaned: set[str] = set()
        for code in permissions:
            if not isinstance(code, str) or not is_known_permission(code):
                raise ValidationFailed("permissions contain an unknown code")
            cleaned.add(code)
        return tuple(sorted(cleaned))

    def _load_role(self, role_id: str | None) -> IdentityRole:
        role = None if not role_id else self._session.get(IdentityRole, role_id)
        if role is None:
            raise ValidationFailed("role_id is unknown")
        return role

    def _identity_by_username(self, username: str) -> Identity | None:
        return self._session.execute(
            select(Identity).where(Identity.username == username)
        ).scalar_one_or_none()

    def _require_identity(self, identity_id: str) -> Identity:
        identity = self._session.get(Identity, identity_id)
        if identity is None:
            raise NotFound("identity not found")
        return identity

    # ---------------------------------------------------------- authorization
    def _effective_permissions(self, identity: Identity, scopes: frozenset[str]) -> frozenset[str]:
        engine = PolicyEngine.load(self._session)
        if identity.actor_kind == HUMAN_ACTOR_KIND:
            effective = engine.permissions(identity.role_id)
            # Reserved installation authority belongs to the persisted owner
            # profile only; copied system.* grants never elevate another role.
            if identity.role_id != ROLE_SUPERADMIN:
                effective = effective - SYSTEM_PERMISSIONS
        elif identity.actor_kind in MACHINE_ACTOR_KINDS:
            if identity.role_id in (ROLE_ADMIN, ROLE_SUPERADMIN):
                # Machines never inherit an administrator profile, even if stored.
                effective = frozenset()
            else:
                effective = engine.permissions(identity.role_id) - MACHINE_FORBIDDEN_PERMISSIONS
            if not identity.delegated_by_id:
                effective = effective - SYSTEM_PERMISSIONS
            else:
                delegator = self._session.get(Identity, identity.delegated_by_id)
                if (
                    delegator is None
                    or not delegator.active
                    or delegator.actor_kind != HUMAN_ACTOR_KIND
                ):
                    return frozenset()
                effective = effective & engine.permissions(delegator.role_id)
                # Revocation is revalidated per operation: the persisted role
                # owner and the live delegator must both still be the owner.
                if (
                    delegator.role_id != ROLE_SUPERADMIN
                    or identity.role_owner != ROLE_SUPERADMIN
                ):
                    effective = effective - SYSTEM_PERMISSIONS
        else:
            effective = frozenset()
        if scopes:
            effective = effective & scopes
        return effective

    def _persisted_permissions(self, principal: Principal) -> frozenset[str]:
        """Effective permissions the caller really holds, read from the database."""
        identity = self._session.get(Identity, principal.actor_id)
        if identity is None:
            return frozenset()
        return self._effective_permissions(identity, principal.scopes)

    def _assert_permission_ceiling(
        self,
        principal: Principal,
        *,
        action: str,
        resource: str,
        role_ids: Iterable[str | None] = (),
        permissions: Iterable[str] | None = None,
    ) -> None:
        """Refuse administration that exceeds the caller's own persisted grants.

        A caller may only hand out (or administer) permissions it holds itself:
        the assigned role, the target's current role and any requested grants
        must all be covered. Full administrators pass because their role covers
        the whole catalog, never because of a bypass.
        """
        ceiling = self._persisted_permissions(principal)
        engine = PolicyEngine.load(self._session)
        needed: set[str] = set()
        for role_id in role_ids:
            if role_id:
                needed |= engine.permissions(role_id)
        if permissions is not None:
            needed |= set(permissions)
        missing = needed - ceiling
        if not missing:
            return
        self._audit(
            actor_id=principal.actor_id,
            actor_kind=principal.kind,
            actor_username=principal.username,
            action=action,
            resource=resource,
            outcome="denied",
            execution_id=principal.execution_id,
            delegated_by=principal.delegated_by,
            authorization_ref=principal.authorization_ref,
        )
        self._session.commit()
        raise PermissionDenied("your permissions do not cover: " + ", ".join(sorted(missing)))

    def authorize(
        self,
        principal: Principal,
        permission: str,
        *,
        resource: str | None = None,
    ) -> None:
        """Authorize one operation for a resolved principal; deny by default."""
        target = resource or permission
        identity = self._session.get(Identity, principal.actor_id)
        allowed = False
        if identity is not None and identity.active and is_known_permission(permission):
            allowed = permission in self._effective_permissions(identity, principal.scopes)
            if (
                allowed
                and identity.actor_kind in MACHINE_ACTOR_KINDS
                and permission in SENSITIVE_MACHINE_PERMISSIONS
                and not principal.authorization_ref
            ):
                allowed = False
        if not allowed:
            if identity is not None:
                self._audit_denied(principal, identity, permission, target)
            else:
                self._audit(
                    actor_kind="unknown",
                    action=permission,
                    resource=target,
                    outcome="denied",
                    actor_id=principal.actor_id,
                    actor_username=principal.username,
                    execution_id=principal.execution_id,
                    authorization_ref=principal.authorization_ref,
                )
            self._session.commit()
            raise PermissionDenied()

    def _principal(self, identity: Identity, *, session_id: str | None = None) -> Principal:
        return Principal(
            actor_id=identity.id,
            kind=identity.actor_kind,
            username=identity.username,
            display_name=identity.name,
            role_id=identity.role_id,
            delegated_by=identity.delegated_by_id,
            session_id=session_id,
        )

    # ---------------------------------------------------------------- sessions
    def _login_key(self, username: str) -> str:
        return _clip(username.strip().lower() if isinstance(username, str) else "", 64)

    def _prune_attempts(self) -> None:
        threshold = self._now() - ATTEMPT_RETENTION
        self._session.execute(
            delete(IdentityLoginAttempt).where(IdentityLoginAttempt.attempted_at < threshold)
        )

    def _assert_not_throttled(self, key: str) -> None:
        window = timedelta(minutes=self._settings.auth_login_window_minutes)
        threshold = self._now() - window
        failures = self._session.execute(
            select(func.count(IdentityLoginAttempt.id)).where(
                IdentityLoginAttempt.username_key == key,
                IdentityLoginAttempt.successful.is_(False),
                IdentityLoginAttempt.attempted_at >= threshold,
            )
        ).scalar_one()
        if int(failures) >= self._settings.auth_login_max_attempts:
            raise AccountThrottled(int(window.total_seconds()))

    def _record_login_failure(self, key: str, identity: Identity | None) -> None:
        self._session.add(
            IdentityLoginAttempt(
                username_key=key,
                attempted_at=self._now(),
                successful=False,
            )
        )
        self._audit(
            actor_id=None if identity is None else identity.id,
            actor_kind="anonymous" if identity is None else identity.actor_kind,
            actor_username=key,
            action="auth.login",
            resource="identity" if identity is None else f"identity:{identity.id}",
            outcome="denied",
        )
        self._session.commit()

    def login(self, username: str, password: str) -> SessionGrant:
        """Human login: generic rejection, durable throttling, opaque session."""
        key = self._login_key(username)
        self._prune_attempts()
        self._assert_not_throttled(key)

        identity = self._identity_by_username(key) if key else None
        if identity is None or not identity.password_hash:
            burn_password_check()
            verified = False
        else:
            verified = verify_password(identity.password_hash, password)

        invalid = (
            identity is None
            or not identity.active
            or identity.actor_kind != HUMAN_ACTOR_KIND
            or identity.role_id is None
            or not verified
        )
        if invalid:
            self._record_login_failure(key, identity)
            raise AuthenticationFailed()

        now = self._now()
        minutes = self.session_minutes()
        self._session.execute(
            delete(IdentityLoginAttempt).where(IdentityLoginAttempt.username_key == key)
        )
        raw_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        session_id = str(uuid4())
        self._session.add(
            IdentitySession(
                id=session_id,
                identity_id=identity.id,
                token_digest=hash_token(raw_token),
                csrf_token=csrf_token,
                created_at=now,
                last_access_at=now,
                expires_at=now + timedelta(minutes=minutes),
            )
        )
        identity.last_access_at = now
        permissions = self._effective_permissions(identity, frozenset())
        principal = self._principal(identity, session_id=session_id)
        expires_at = now + timedelta(minutes=minutes)
        self._audit(
            actor_id=identity.id,
            actor_kind=identity.actor_kind,
            actor_username=identity.username,
            action="auth.login",
            resource=f"identity:{identity.id}",
            outcome="success",
        )
        self._session.commit()
        return SessionGrant(
            principal=principal,
            permissions=permissions,
            csrf_token=csrf_token,
            session_minutes=minutes,
            expires_at=expires_at,
            session_id=session_id,
            token=raw_token,
        )

    def authenticate_session(self, token: str | None) -> AuthContext:
        """Resolve and revalidate a cookie session; called on every request."""
        if not token:
            raise AuthenticationFailed("authentication required")
        row = self._session.execute(
            select(IdentitySession).where(IdentitySession.token_digest == hash_token(token))
        ).scalar_one_or_none()
        if row is None:
            raise AuthenticationFailed("authentication required")
        now = self._now()
        if row.revoked_at is not None or as_utc(row.expires_at) <= now:
            raise AuthenticationFailed("authentication required")
        identity = self._session.get(Identity, row.identity_id)
        if identity is None or not identity.active or identity.role_id is None:
            raise AuthenticationFailed("authentication required")

        permissions = self._effective_permissions(identity, frozenset())
        row.last_access_at = now
        identity.last_access_at = now
        context = AuthContext(
            principal=self._principal(identity, session_id=row.id),
            permissions=permissions,
            csrf_token=row.csrf_token,
            session_minutes=self.session_minutes(),
            session_id=row.id,
        )
        self._session.commit()
        return context

    def logout(self, principal: Principal) -> None:
        now = self._now()
        revoked = 0
        if principal.session_id:
            row = self._session.get(IdentitySession, principal.session_id)
            if row is not None and row.revoked_at is None:
                row.revoked_at = now
                revoked = 1
        self._audit(
            actor_id=principal.actor_id,
            actor_kind=principal.kind,
            actor_username=principal.username,
            action="auth.logout",
            resource=f"session:{principal.session_id}" if principal.session_id else "session",
            outcome="success" if revoked else "denied",
        )
        self._session.commit()

    def me(self, context: AuthContext) -> CurrentView:
        identity = self._require_identity(context.principal.actor_id)
        return CurrentView(
            user=self._user_view(identity),
            permissions=context.permissions,
            csrf_token=context.csrf_token,
            session_minutes=context.session_minutes,
        )

    # ------------------------------------------------------- machine identity
    def authenticate_token(
        self,
        token: str | None,
        *,
        execution_id: str | None = None,
        authorization_ref: str | None = None,
    ) -> AuthContext:
        """Machine bearer authentication using a stored token digest."""
        if not token:
            raise AuthenticationFailed("authentication required")
        credential = self._session.execute(
            select(IdentityCredential).where(
                IdentityCredential.token_digest == hash_token(token),
                IdentityCredential.revoked_at.is_(None),
            )
        ).scalar_one_or_none()
        if credential is None:
            raise AuthenticationFailed("authentication required")
        identity = self._session.get(Identity, credential.identity_id)
        if (
            identity is None
            or not identity.active
            or identity.actor_kind not in MACHINE_ACTOR_KINDS
        ):
            raise AuthenticationFailed("authentication required")

        now = self._now()
        identity.last_access_at = now
        principal = Principal(
            actor_id=identity.id,
            kind=identity.actor_kind,
            username=identity.username,
            display_name=identity.name,
            role_id=identity.role_id,
            delegated_by=identity.delegated_by_id,
            execution_id=execution_id,
            authorization_ref=authorization_ref,
        )
        context = AuthContext(
            principal=principal,
            permissions=self._effective_permissions(identity, frozenset()),
            csrf_token=None,
            session_minutes=self.session_minutes(),
        )
        self._session.commit()
        return context

    def resolve_actor(
        self,
        identity_id: str,
        *,
        scopes: Iterable[str] = (),
        execution_id: str | None = None,
        authorization_ref: str | None = None,
    ) -> Principal:
        """Resolve a principal for tool callers (Pydantic AI, FastMCP, CLI)."""
        identity = self._session.get(Identity, identity_id)
        if identity is None or not identity.active:
            raise PermissionDenied("identity is not available")
        return Principal(
            actor_id=identity.id,
            kind=identity.actor_kind,
            username=identity.username,
            display_name=identity.name,
            role_id=identity.role_id,
            delegated_by=identity.delegated_by_id,
            scopes=frozenset(scopes),
            execution_id=execution_id,
            authorization_ref=authorization_ref,
        )

    def issue_machine_credential(
        self, username: str, label: str | None = None
    ) -> MachineCredential:
        """Issue a one-time visible static token; only its digest is stored."""
        normalized = self._normalize_username(username)
        identity = self._identity_by_username(normalized)
        if identity is None:
            raise NotFound(f"machine identity {normalized} not found")
        if identity.actor_kind not in MACHINE_ACTOR_KINDS:
            raise ValidationFailed("credentials are issued only to machine identities")
        if not identity.active:
            raise Conflict("identity is inactive")
        token = MACHINE_TOKEN_PREFIX + secrets.token_urlsafe(32)
        credential_id = str(uuid4())
        self._session.add(
            IdentityCredential(
                id=credential_id,
                identity_id=identity.id,
                token_digest=hash_token(token),
                label=None if label is None else _clip(label.strip(), 64) or None,
                created_at=self._now(),
            )
        )
        self._audit(
            actor_kind="system",
            action="identity.credential_issued",
            resource=f"identity:{identity.id}",
            outcome="success",
        )
        self._session.commit()
        return MachineCredential(credential_id=credential_id, token=token)

    def revoke_machine_credentials(self, username: str) -> int:
        normalized = self._normalize_username(username)
        identity = self._identity_by_username(normalized)
        if identity is None:
            raise NotFound(f"machine identity {normalized} not found")
        if identity.actor_kind not in MACHINE_ACTOR_KINDS:
            raise ValidationFailed("credentials belong only to machine identities")
        now = self._now()
        rows = self._session.execute(
            select(IdentityCredential).where(
                IdentityCredential.identity_id == identity.id,
                IdentityCredential.revoked_at.is_(None),
            )
        ).scalars()
        revoked = 0
        for credential in rows:
            credential.revoked_at = now
            revoked += 1
        self._audit(
            actor_id=identity.id,
            actor_kind=identity.actor_kind,
            actor_username=identity.username,
            action="identity.credential_revoked",
            resource=f"identity:{identity.id}",
            outcome="success" if revoked else "noop",
        )
        self._session.commit()
        return revoked

    # ------------------------------------------------------------- bootstrap
    def bootstrap_superadmin(self, username: str, name: str, password: str) -> UserView:
        """Installation-only creation of the first human installation owner.

        The built-in role row is locked first so concurrent bootstrap attempts
        serialize on databases that support row locks and the first-owner check
        cannot race with adoption.
        """
        role = self._session.get(IdentityRole, ROLE_SUPERADMIN, with_for_update=True)
        if role is None:
            raise Conflict("built-in roles are missing; run the database migrations first")
        humans = self._session.execute(
            select(func.count(Identity.id)).where(Identity.actor_kind == HUMAN_ACTOR_KIND)
        ).scalar_one()
        if int(humans):
            raise BootstrapRefused("the installation already has a human identity")
        normalized = self._normalize_username(username)
        display_name = self._normalize_name(name)
        self._validate_password(password)
        if self._identity_by_username(normalized) is not None:
            raise Conflict("username is already in use")
        now = self._now()
        identity = Identity(
            id=str(uuid4()),
            username=normalized,
            name=display_name,
            email=None,
            actor_kind=HUMAN_ACTOR_KIND,
            person_id=None,
            active=True,
            password_hash=hash_password(password),
            role_id=ROLE_SUPERADMIN,
            created_at=now,
            updated_at=now,
        )
        self._session.add(identity)
        self._session.flush()
        view = self._user_view(identity)
        self._audit(
            actor_kind="system",
            action="identity.bootstrap",
            resource=f"identity:{identity.id}",
            outcome="success",
            actor_username=normalized,
        )
        self._session.commit()
        return view

    def adopt_superadmin(self, username: str) -> UserView:
        """Installation-only claim of ownership on an existing installation.

        Allowed only while no active human superadmin exists, so an upgraded
        installation can explicitly designate its first owner without promoting
        every existing administrator. The owner's password is never read or
        replaced here.
        """
        role = self._session.get(IdentityRole, ROLE_SUPERADMIN, with_for_update=True)
        if role is None:
            raise Conflict("built-in roles are missing; run the database migrations first")
        normalized = self._normalize_username(username)
        target = self._identity_by_username(normalized)
        if target is None:
            raise NotFound("identity not found")
        if target.actor_kind != HUMAN_ACTOR_KIND:
            raise ValidationFailed("only human identities can own the installation")
        if not target.active:
            raise ValidationFailed("the identity is not active")
        active_owners = self._session.execute(
            select(func.count(Identity.id)).where(
                Identity.actor_kind == HUMAN_ACTOR_KIND,
                Identity.active.is_(True),
                Identity.role_id == ROLE_SUPERADMIN,
            )
        ).scalar_one()
        if int(active_owners):
            raise BootstrapRefused("the installation already has an active superadministrator")
        target.role_id = ROLE_SUPERADMIN
        target.updated_at = self._now()
        self._revoke_sessions(target.id)
        view = self._user_view(target)
        self._audit(
            actor_kind="system",
            action="identity.superadmin_adopted",
            resource=f"identity:{target.id}",
            outcome="success",
            actor_username=target.username,
        )
        self._session.commit()
        return view

    def bootstrap_machine(
        self,
        username: str,
        name: str,
        actor_kind: str,
        role_id: str,
        *,
        delegated_by: str | None = None,
    ) -> UserView:
        """Installation-only creation of a machine identity.

        A machine identity never receives the superadmin or admin role and can
        only be created once a human installation owner exists, so an empty
        database cannot be turned into a machine-owned installation. Reserved
        grants require an active human superadmin delegator, supplied by
        username because this path has no authenticated principal.
        """
        owners = self._session.execute(
            select(func.count(Identity.id)).where(
                Identity.actor_kind == HUMAN_ACTOR_KIND,
                Identity.active.is_(True),
                Identity.role_id == ROLE_SUPERADMIN,
            )
        ).scalar_one()
        if not int(owners):
            raise BootstrapRefused("bootstrap a human superadministrator first")
        if actor_kind not in MACHINE_ACTOR_KINDS:
            raise ValidationFailed("actor_kind must be a machine actor kind")
        role = self._load_role(role_id)
        self._check_machine_role(actor_kind, role.id)
        delegated_by_id = None
        if delegated_by is not None:
            delegator = self._identity_by_username(self._normalize_username(delegated_by))
            if delegator is None:
                raise ValidationFailed("delegated-by identity is unknown")
            delegated_by_id = delegator.id
        delegated_by_id, role_owner = self._role_assignment(
            actor_kind=actor_kind, role=role, delegated_by_id=delegated_by_id
        )
        normalized = self._normalize_username(username)
        display_name = self._normalize_name(name)
        if self._identity_by_username(normalized) is not None:
            raise Conflict("username is already in use")
        now = self._now()
        identity = Identity(
            id=str(uuid4()),
            username=normalized,
            name=display_name,
            email=None,
            actor_kind=actor_kind,
            person_id=None,
            active=True,
            password_hash=None,
            role_id=role.id,
            delegated_by_id=delegated_by_id,
            role_owner=role_owner,
            created_at=now,
            updated_at=now,
        )
        self._session.add(identity)
        self._session.flush()
        view = self._user_view(identity)
        self._audit(
            actor_kind="system",
            action="identity.bootstrap_machine",
            resource=f"identity:{identity.id}",
            outcome="success",
            actor_username=normalized,
        )
        self._session.commit()
        return view

    # ---------------------------------------------------------- administration
    def _revoke_sessions(self, identity_id: str) -> None:
        now = self._now()
        rows = self._session.execute(
            select(IdentitySession).where(
                IdentitySession.identity_id == identity_id,
                IdentitySession.revoked_at.is_(None),
            )
        ).scalars()
        for row in rows:
            row.revoked_at = now

    def _assert_not_last_superadmin(self, target: Identity) -> None:
        remaining = self._session.execute(
            select(func.count(Identity.id)).where(
                Identity.actor_kind == HUMAN_ACTOR_KIND,
                Identity.active.is_(True),
                Identity.role_id == ROLE_SUPERADMIN,
                Identity.id != target.id,
            )
        ).scalar_one()
        if int(remaining) == 0:
            raise Conflict("at least one active superadministrator is required")

    def _check_machine_role(self, actor_kind: str, role_id: str | None) -> None:
        if actor_kind in MACHINE_ACTOR_KINDS and role_id in (ROLE_ADMIN, ROLE_SUPERADMIN):
            raise ValidationFailed("machine identities cannot use an administrator role")

    def _delegator(self, delegated_by_id: str, *, require_superadmin: bool) -> Identity:
        delegator = self._session.get(Identity, delegated_by_id)
        if delegator is None or delegator.actor_kind != HUMAN_ACTOR_KIND or not delegator.active:
            raise ValidationFailed("delegation requires an active human identity")
        if require_superadmin and delegator.role_id != ROLE_SUPERADMIN:
            raise ValidationFailed(
                "reserved permissions require delegation by an active superadministrator"
            )
        return delegator

    def _role_assignment(
        self,
        *,
        actor_kind: str,
        role: IdentityRole,
        delegated_by_id: str | None,
    ) -> tuple[str | None, str | None]:
        """Validate a role/delegation pair and return (delegated_by_id, role_owner).

        Human reserved grants are refused unless the role itself is the owner
        profile. Machine reserved grants are refused unless an active human
        superadmin delegates them, and the delegator's role is persisted as the
        machine's role owner so a later change cannot silently broaden it.
        """
        permissions = PolicyEngine.load(self._session).permissions(role.id)
        if actor_kind == HUMAN_ACTOR_KIND:
            if role.id != ROLE_SUPERADMIN and permissions & SYSTEM_PERMISSIONS:
                raise ValidationFailed(
                    "system permissions are reserved to the installation owner"
                )
            if delegated_by_id is not None:
                self._delegator(delegated_by_id, require_superadmin=False)
            return delegated_by_id, None
        if role.id in (ROLE_ADMIN, ROLE_SUPERADMIN):
            raise ValidationFailed("machine identities cannot use an administrator role")
        reserved = bool(permissions & SYSTEM_PERMISSIONS)
        if not delegated_by_id:
            if reserved:
                raise ValidationFailed(
                    "reserved permissions require delegation by an active superadministrator"
                )
            return None, None
        delegator = self._delegator(delegated_by_id, require_superadmin=reserved)
        return delegator.id, delegator.role_id

    def create_user(
        self,
        principal: Principal,
        *,
        username: str,
        name: str,
        role_id: str,
        email: str | None = None,
        person_id: str | None = None,
        actor_kind: str = HUMAN_ACTOR_KIND,
        active: bool = True,
        password: str | None = None,
        delegated_by_id: str | None = None,
    ) -> UserView:
        self.authorize(principal, "users.create", resource="identity")
        normalized = self._normalize_username(username)
        display_name = self._normalize_name(name)
        email_value = self._normalize_email(email)
        person_value = self._normalize_person_id(person_id)
        kind = self._validate_actor_kind(actor_kind)
        role = self._load_role(role_id)
        self._check_machine_role(kind, role.id)
        self._assert_permission_ceiling(
            principal,
            action="identity.user_created",
            resource=f"identity-role:{role.id}",
            role_ids=[role.id],
        )
        delegated_by_id, role_owner = self._role_assignment(
            actor_kind=kind, role=role, delegated_by_id=delegated_by_id
        )
        if kind in MACHINE_ACTOR_KINDS and password:
            raise ValidationFailed("machine identities do not use passwords")
        password_hash = None
        if kind == HUMAN_ACTOR_KIND:
            if not password:
                raise ValidationFailed("a password is required for human identities")
            password_hash = hash_password(self._validate_password(password))
        if self._identity_by_username(normalized) is not None:
            raise Conflict("username is already in use")

        now = self._now()
        identity = Identity(
            id=str(uuid4()),
            username=normalized,
            name=display_name,
            email=email_value,
            actor_kind=kind,
            person_id=person_value,
            active=bool(active),
            password_hash=password_hash,
            role_id=role.id,
            delegated_by_id=delegated_by_id,
            role_owner=role_owner,
            created_at=now,
            updated_at=now,
        )
        self._session.add(identity)
        self._session.flush()
        view = self._user_view(identity)
        self._audit(
            actor_id=principal.actor_id,
            actor_kind=principal.kind,
            actor_username=principal.username,
            action="identity.user_created",
            resource=f"identity:{identity.id}",
            outcome="success",
            execution_id=principal.execution_id,
            authorization_ref=principal.authorization_ref,
        )
        self._session.commit()
        return view

    def update_user(
        self,
        principal: Principal,
        identity_id: str,
        *,
        username: str | None = None,
        name: str | None = None,
        email: str | None = None,
        role_id: str | None = None,
        person_id: str | None = None,
        actor_kind: str | None = None,
        active: bool | None = None,
        password: str | None = None,
        delegated_by_id: str | None = None,
    ) -> UserView:
        """Update mutable fields; ``None`` means "leave unchanged"."""
        self.authorize(principal, "users.edit", resource=f"identity:{identity_id}")
        target = self._require_identity(identity_id)
        self._assert_permission_ceiling(
            principal,
            action="identity.user_updated",
            resource=f"identity:{identity_id}",
            role_ids=[target.role_id, role_id],
        )
        if role_id is not None and role_id != target.role_id:
            if target.id == principal.actor_id:
                raise PermissionDenied("you cannot change your own role")
            new_role = self._load_role(role_id)
            self._check_machine_role(target.actor_kind, new_role.id)
            if (
                target.active
                and target.actor_kind == HUMAN_ACTOR_KIND
                and target.role_id == ROLE_SUPERADMIN
            ):
                self._assert_not_last_superadmin(target)
        if actor_kind is not None and actor_kind != target.actor_kind:
            raise ValidationFailed("actor_kind cannot be changed")
        if (
            active is False
            and target.active
            and target.actor_kind == HUMAN_ACTOR_KIND
            and target.role_id == ROLE_SUPERADMIN
        ):
            self._assert_not_last_superadmin(target)
        if role_id is not None or delegated_by_id is not None:
            role = self._load_role(role_id if role_id is not None else target.role_id)
            delegated_by_id, role_owner = self._role_assignment(
                actor_kind=target.actor_kind,
                role=role,
                delegated_by_id=(
                    delegated_by_id if delegated_by_id is not None else target.delegated_by_id
                ),
            )
            target.delegated_by_id = delegated_by_id
            target.role_owner = role_owner

        revoke = False
        if username is not None:
            normalized = self._normalize_username(username)
            if normalized != target.username:
                if self._identity_by_username(normalized) is not None:
                    raise Conflict("username is already in use")
                target.username = normalized
        if name is not None:
            target.name = self._normalize_name(name)
        if email is not None:
            target.email = self._normalize_email(email)
        if person_id is not None:
            target.person_id = self._normalize_person_id(person_id)
        if role_id is not None and role_id != target.role_id:
            target.role_id = role_id
            revoke = True
        if active is not None and bool(active) != bool(target.active):
            target.active = bool(active)
            revoke = revoke or not target.active
        if password is not None:
            if target.actor_kind != HUMAN_ACTOR_KIND:
                raise ValidationFailed("machine identities do not use passwords")
            target.password_hash = hash_password(self._validate_password(password))
            revoke = True
        target.updated_at = self._now()
        if revoke:
            self._revoke_sessions(target.id)

        self._session.flush()
        view = self._user_view(target)
        self._audit(
            actor_id=principal.actor_id,
            actor_kind=principal.kind,
            actor_username=principal.username,
            action="identity.user_updated",
            resource=f"identity:{target.id}",
            outcome="success",
            execution_id=principal.execution_id,
            authorization_ref=principal.authorization_ref,
        )
        self._session.commit()
        return view

    def set_active(self, principal: Principal, identity_id: str, *, active: bool) -> UserView:
        self.authorize(principal, "users.edit", resource=f"identity:{identity_id}")
        target = self._require_identity(identity_id)
        self._assert_permission_ceiling(
            principal,
            action="identity.user_activated" if active else "identity.user_deactivated",
            resource=f"identity:{identity_id}",
            role_ids=[target.role_id],
        )
        if not active and target.active:
            if target.actor_kind == HUMAN_ACTOR_KIND and target.role_id == ROLE_SUPERADMIN:
                self._assert_not_last_superadmin(target)
            self._revoke_sessions(target.id)
        target.active = bool(active)
        target.updated_at = self._now()
        self._session.flush()
        view = self._user_view(target)
        self._audit(
            actor_id=principal.actor_id,
            actor_kind=principal.kind,
            actor_username=principal.username,
            action="identity.user_activated" if active else "identity.user_deactivated",
            resource=f"identity:{target.id}",
            outcome="success",
            execution_id=principal.execution_id,
            authorization_ref=principal.authorization_ref,
        )
        self._session.commit()
        return view

    def create_role(
        self, principal: Principal, *, name: str, permissions: Iterable[str]
    ) -> RoleView:
        self.authorize(principal, "roles.manage", resource="identity:roles")
        display_name = self._normalize_name(name)
        codes = self._validate_permissions(permissions)
        self._assert_permission_ceiling(
            principal,
            action="identity.role_created",
            resource="identity:roles",
            permissions=codes,
        )
        if self._session.execute(
            select(func.count(IdentityRole.id)).where(IdentityRole.name == display_name)
        ).scalar_one():
            raise Conflict("a role with that name already exists")
        role = IdentityRole(
            id=f"role-{uuid4().hex[:12]}",
            name=display_name,
            built_in=False,
            created_at=self._now(),
        )
        self._session.add(role)
        for code in codes:
            resource, _, operation = code.partition(".")
            self._session.add(
                IdentityRolePolicy(role_id=role.id, resource=resource, operation=operation)
            )
        self._session.flush()
        view = self._role_view(role)
        self._audit(
            actor_id=principal.actor_id,
            actor_kind=principal.kind,
            actor_username=principal.username,
            action="identity.role_created",
            resource=f"identity-role:{role.id}",
            outcome="success",
            execution_id=principal.execution_id,
            authorization_ref=principal.authorization_ref,
        )
        self._session.commit()
        return view

    def update_role(
        self,
        principal: Principal,
        role_id: str,
        *,
        name: str | None = None,
        permissions: Iterable[str] | None = None,
    ) -> RoleView:
        self.authorize(principal, "roles.manage", resource=f"identity-role:{role_id}")
        role = self._session.get(IdentityRole, role_id)
        if role is None:
            raise NotFound("role not found")
        if role.built_in:
            raise Conflict("built-in roles cannot be modified")
        if permissions is not None and role.id == principal.role_id:
            raise PermissionDenied("you cannot change your own role")
        self._assert_permission_ceiling(
            principal,
            action="identity.role_updated",
            resource=f"identity-role:{role_id}",
            role_ids=[role.id],
            permissions=permissions,
        )
        if name is not None:
            display_name = self._normalize_name(name)
            if display_name != role.name:
                if self._session.execute(
                    select(func.count(IdentityRole.id)).where(IdentityRole.name == display_name)
                ).scalar_one():
                    raise Conflict("a role with that name already exists")
                role.name = display_name
        if permissions is not None:
            codes = self._validate_permissions(permissions)
            self._session.execute(
                delete(IdentityRolePolicy).where(IdentityRolePolicy.role_id == role.id)
            )
            for code in codes:
                resource, _, operation = code.partition(".")
                self._session.add(
                    IdentityRolePolicy(role_id=role.id, resource=resource, operation=operation)
                )
        self._session.flush()
        view = self._role_view(role)
        self._audit(
            actor_id=principal.actor_id,
            actor_kind=principal.kind,
            actor_username=principal.username,
            action="identity.role_updated",
            resource=f"identity-role:{role.id}",
            outcome="success",
            execution_id=principal.execution_id,
            authorization_ref=principal.authorization_ref,
        )
        self._session.commit()
        return view

    def update_settings(self, principal: Principal, *, session_minutes: int) -> int:
        self.authorize(principal, "sessions.manage", resource="identity:settings")
        if not isinstance(session_minutes, int) or not (
            SESSION_MINUTES_MIN <= session_minutes <= SESSION_MINUTES_MAX
        ):
            raise ValidationFailed(
                f"sessionMinutes must be {SESSION_MINUTES_MIN}-{SESSION_MINUTES_MAX}"
            )
        row = self._session.get(IdentitySecuritySettings, 1)
        if row is None:
            row = IdentitySecuritySettings(id=1, session_minutes=session_minutes)
            self._session.add(row)
        row.session_minutes = session_minutes
        row.updated_at = self._now()
        self._audit(
            actor_id=principal.actor_id,
            actor_kind=principal.kind,
            actor_username=principal.username,
            action="identity.settings_updated",
            resource="identity:settings",
            outcome="success",
            execution_id=principal.execution_id,
            authorization_ref=principal.authorization_ref,
        )
        self._session.commit()
        return session_minutes

    def record_operation(
        self,
        principal: Principal,
        *,
        action: str,
        resource: str,
        outcome: str = "success",
    ) -> None:
        """Audit an operation performed by another module through this service."""
        identity = self._session.get(Identity, principal.actor_id)
        self._audit(
            actor_id=principal.actor_id,
            actor_kind=identity.actor_kind if identity is not None else principal.kind,
            actor_username=identity.username if identity is not None else principal.username,
            action=action,
            resource=resource,
            outcome=outcome,
            execution_id=principal.execution_id,
            delegated_by=identity.delegated_by_id if identity is not None else None,
            authorization_ref=principal.authorization_ref,
        )
        self._session.commit()

    def state(self, context: AuthContext) -> StateView:
        """Authorized subsets for the startup screen; 200 for any authenticated actor."""
        permissions = context.permissions
        can_read_users = "users.view" in permissions
        can_read_roles = can_read_users or "roles.manage" in permissions
        return StateView(
            users=self._user_views() if can_read_users else (),
            roles=self._role_views() if can_read_roles else (),
            session_minutes=self.session_minutes(),
        )

    def catalog(self, principal: Principal) -> CatalogView:
        self.authorize(principal, "roles.manage", resource="identity:permissions")
        return CatalogView(permissions=PERMISSION_CATALOG, actor_kinds=tuple(ACTOR_KINDS))

    def list_audit(self, principal: Principal, *, limit: int = 50) -> tuple[AuditView, ...]:
        self.authorize(principal, "sessions.manage", resource="identity:audit")
        bounded = max(1, min(int(limit), AUDIT_PAGE_MAX))
        rows = self._session.execute(
            select(IdentityAuditEvent).order_by(IdentityAuditEvent.id.desc()).limit(bounded)
        ).scalars()
        return tuple(
            AuditView(
                actor_id=row.actor_id,
                actor_kind=row.actor_kind,
                actor_username=row.actor_username,
                action=row.action,
                resource=row.resource,
                outcome=row.outcome,
                created_at=as_utc(row.created_at),
                execution_id=row.execution_id,
                delegated_by=row.delegated_by,
                authorization_ref=row.authorization_ref,
            )
            for row in rows
        )


def audit_event_payload(event: AuditView) -> dict[str, Any]:
    """Serialize an audit event for the API; never includes secrets."""
    return {
        "actorId": event.actor_id,
        "actorKind": event.actor_kind,
        "actorUsername": event.actor_username,
        "action": event.action,
        "resource": event.resource,
        "outcome": event.outcome,
        "createdAt": event.created_at.isoformat(),
        "executionId": event.execution_id,
        "delegatedBy": event.delegated_by,
        "authorizationRef": event.authorization_ref,
    }
