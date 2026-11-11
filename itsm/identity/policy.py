"""Casbin evaluation over ITSM-owned policy rows.

Policies are stored in ``identity_role_policies`` and loaded into an in-memory
Casbin enforcer for evaluation. The database remains the only source of truth:
a policy change is visible to the next loaded engine, and there is no implicit
administrator bypass outside Casbin.
"""

from __future__ import annotations

from collections.abc import Iterable

from casbin import Enforcer
from casbin import Model as CasbinModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from itsm.identity.models import IdentityRolePolicy

CASBIN_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""

PolicyRule = tuple[str, str, str]


def _build_enforcer(rules: Iterable[PolicyRule]) -> Enforcer:
    model = CasbinModel()
    model.load_model_from_text(CASBIN_MODEL)
    enforcer = Enforcer(model)
    for role_id, resource, operation in rules:
        enforcer.add_policy(role_id, resource, operation)
    return enforcer


class PolicyEngine:
    """RBAC evaluator: a role is the Casbin subject, permission is obj/act."""

    def __init__(self, rules: Iterable[PolicyRule]) -> None:
        materialized = list(rules)
        self._enforcer = _build_enforcer(materialized)
        permissions: dict[str, set[str]] = {}
        for role_id, resource, operation in materialized:
            permissions.setdefault(role_id, set()).add(f"{resource}.{operation}")
        self._permissions = {role: frozenset(codes) for role, codes in permissions.items()}

    @classmethod
    def load(cls, session: Session) -> PolicyEngine:
        """Load every stored policy row into a fresh enforcer."""
        rows = session.execute(
            select(
                IdentityRolePolicy.role_id,
                IdentityRolePolicy.resource,
                IdentityRolePolicy.operation,
            )
        ).all()
        return cls(
            (str(role_id), str(resource), str(operation)) for role_id, resource, operation in rows
        )

    def allowed(self, role_id: str | None, resource: str, operation: str) -> bool:
        """Deny by default: unknown roles and unknown permissions are denied."""
        if not role_id:
            return False
        return bool(self._enforcer.enforce(role_id, resource, operation))

    def permissions(self, role_id: str | None) -> frozenset[str]:
        """Effective ``resource.operation`` codes for one role."""
        if not role_id:
            return frozenset()
        return self._permissions.get(role_id, frozenset())


_SESSION_ENGINE_KEY = "identity.policy_engine"


def session_policy_engine(session: Session) -> PolicyEngine:
    """Return the engine for this unit of work, loading it at most once.

    The cache lives on the request-scoped session, never in a process global,
    so each request sees the policy rows committed before it started. Writers
    in the same session must call ``invalidate_session_policy_engine``.
    """
    engine = session.info.get(_SESSION_ENGINE_KEY)
    if engine is None:
        engine = PolicyEngine.load(session)
        session.info[_SESSION_ENGINE_KEY] = engine
    return engine


def invalidate_session_policy_engine(session: Session) -> None:
    session.info.pop(_SESSION_ENGINE_KEY, None)
