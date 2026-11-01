"""Domain errors carry stable translation keys (T4a, D8, S8, S10).

The scanner walks the package with ``ast`` instead of grepping, so a raise split
over several lines is still checked and the message expression can be inspected.
Group A modules (T4a) must key every user-visible domain raise; the group B
modules still pending T4b live in an allowlist that may only shrink.

The HTTP cases prove the localized envelope end to end: ``key`` and ``params``
travel next to the localized ``message`` for both core locales.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.i18n import CATALOG_DIR, CORE_LOCALES, t
from itsm.main import create_app
from tests.conftest import run_migrations
from tests.identity_support import Harness

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = BACKEND_ROOT / "itsm"

#: Domain exceptions rendered by the shared error envelope.
DOMAIN_ERRORS = frozenset(
    {
        "ValidationFailed",
        "NotFound",
        "Conflict",
        "PermissionDenied",
        "AuthenticationFailed",
        "BootstrapRefused",
    }
)

#: T4a modules: every domain raise must carry ``key=``.
GROUP_A = frozenset(
    {
        "identity",
        "directory",
        "maintenance",
        "interventions",
        "workflows",
        "workspace",
        "redundancy",
        "ai_usage",
        "appearance",
        "attachments",
        "system",
        "search",
        "events",
        "dashboard",
        "inventory",
        "operations",
        "relationships",
        "reports",
        "monitoring",
        "notifications",
        "agent_integrations",
        "agents",
        "mcp",
    }
)

#: T4b modules: pending conversion. This set may only shrink.
PENDING = frozenset(
    {
        "extensions",
    }
)

#: Shared namespaces that a module may reuse instead of its own.
SHARED_PREFIXES = ("api.auth.", "api.error.", "api.i18n.", "api.validation.")

PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")

ORIGIN = "http://testserver"
API = "/api/v1"
ADMIN_PASSWORD = "installer-password-2026"


@dataclass(frozen=True)
class RaiseSite:
    """One ``raise <DomainError>(...)`` call found by the scanner."""

    module: str
    path: str
    line: int
    error: str
    keyed: bool
    key: str | None
    params: frozenset[str] | None


def module_of(path: Path) -> str:
    parts = path.relative_to(PACKAGE_ROOT).parts
    return parts[0] if len(parts) > 1 else path.stem


def _static_key(call: ast.Call) -> str | None:
    for keyword in call.keywords:
        if (
            keyword.arg == "key"
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ):
            return keyword.value.value
    return None


def _static_params(call: ast.Call) -> frozenset[str] | None:
    """Parameter names of a literal ``params=`` dict; ``None`` when dynamic."""
    for keyword in call.keywords:
        if keyword.arg != "params":
            continue
        if isinstance(keyword.value, ast.Dict):
            names = set()
            for key in keyword.value.keys:
                assert isinstance(key, ast.Constant), ast.dump(key)
                names.add(str(key.value))
            return frozenset(names)
        return None
    return frozenset()


def scan_raises() -> list[RaiseSite]:
    sites: list[RaiseSite] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
                continue
            func = node.exc.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name not in DOMAIN_ERRORS:
                continue
            keyed = any(keyword.arg == "key" for keyword in node.exc.keywords)
            sites.append(
                RaiseSite(
                    module=module_of(path),
                    path=str(path.relative_to(BACKEND_ROOT)),
                    line=node.lineno,
                    error=str(name),
                    keyed=keyed,
                    key=_static_key(node.exc) if keyed else None,
                    params=_static_params(node.exc) if keyed else None,
                )
            )
    return sites


def read_catalog(locale: str) -> dict[str, str]:
    path = Path(CATALOG_DIR) / f"{locale}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def placeholders(template: str) -> frozenset[str]:
    return frozenset(PLACEHOLDER.findall(template))


SITES = scan_raises()
KEYED = [site for site in SITES if site.key is not None]


def test_group_a_domain_raises_carry_a_translation_key() -> None:
    missing = [
        f"{site.path}:{site.line} raises {site.error} without key="
        for site in SITES
        if site.module in GROUP_A and not site.keyed
    ]

    assert missing == [], "\n".join(missing)


def test_pending_allowlist_only_shrinks() -> None:
    unkeyed = {site.module for site in SITES if not site.keyed}
    assert unkeyed <= PENDING, sorted(unkeyed - PENDING)
    assert GROUP_A.isdisjoint(PENDING)


def test_every_error_key_resolves_in_both_catalogs_and_context() -> None:
    catalogs = {locale: read_catalog(locale) for locale in CORE_LOCALES}
    context = json.loads((Path(CATALOG_DIR) / "context.json").read_text(encoding="utf-8"))

    missing = sorted({site.key for site in KEYED if site.key not in catalogs["es"]})
    assert missing == [], missing
    for key in {site.key for site in KEYED}:
        assert key in context, key
        assert placeholders(catalogs["es"][key]) == placeholders(catalogs["en"][key]), key


def test_raise_site_parameters_match_the_catalog_placeholders() -> None:
    spanish = read_catalog("es")

    mismatched = []
    for site in KEYED:
        if site.params is None:
            continue
        expected = placeholders(spanish[site.key or ""])
        if site.params != expected:
            mismatched.append(
                f"{site.path}:{site.line} {site.key}: raises {sorted(site.params)}, "
                f"catalog {sorted(expected)}"
            )

    assert mismatched == [], "\n".join(mismatched)


def test_error_keys_stay_in_their_module_or_a_shared_namespace() -> None:
    wrong = sorted(
        {
            f"{site.path}:{site.line} {site.key}"
            for site in KEYED
            if not str(site.key).startswith((f"api.{site.module}.", *SHARED_PREFIXES))
        }
    )

    assert wrong == [], "\n".join(wrong)


# --------------------------------------------------------------- HTTP evidence


@pytest.fixture
def env(settings_factory: Callable[..., Settings]) -> Iterator[tuple[TestClient, Harness]]:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    harness = Harness(settings=settings, engine=create_engine_from_settings(settings))
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", ADMIN_PASSWORD)
    with TestClient(create_app(settings)) as client:
        try:
            yield client, harness
        finally:
            harness.close()


def admin_headers(client: TestClient) -> dict[str, str]:
    response = client.post(
        f"{API}/auth/login",
        json={"username": "ana.admin", "password": ADMIN_PASSWORD},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 200, response.text
    return {"Origin": ORIGIN, "X-CSRF-Token": str(response.json()["csrfToken"])}


#: One reachable domain error per converted module group, in both locales.
CASES = [
    (
        "search",
        "GET",
        "/search?q=router&kind=bogus",
        422,
        "api.search.unsupported_search_kinds",
        {"kinds": "bogus"},
    ),
    (
        "directory",
        "GET",
        "/people/not-a-uuid",
        404,
        "api.directory.record_not_found",
        {"field": "person"},
    ),
    (
        "maintenance",
        "GET",
        "/maintenance/plans/00000000-0000-0000-0000-000000000000",
        404,
        "api.maintenance.maintenance_plan_not_found",
        {},
    ),
    (
        "redundancy",
        "GET",
        "/redundancy-groups/not-a-uuid",
        404,
        "api.redundancy.redundancy_group_not_found",
        {},
    ),
    (
        "appearance",
        "GET",
        "/appearance/resources/00000000-0000-0000-0000-000000000000",
        404,
        "api.appearance.appearance_resource_not_found",
        {},
    ),
    (
        "inventory",
        "GET",
        "/assets/not-a-uuid",
        404,
        "api.inventory.asset_not_found",
        {},
    ),
    (
        "relationships",
        "DELETE",
        "/relationships/00000000-0000-0000-0000-000000000000",
        404,
        "api.relationships.relationship_not_found",
        {},
    ),
    (
        "reports",
        "GET",
        "/reports/jobs/00000000-0000-0000-0000-000000000000",
        404,
        "api.reports.job_not_found",
        {},
    ),
    (
        "dashboard",
        "GET",
        "/dashboard?period=bogus",
        422,
        "api.dashboard.period_allowed",
        {"allowed": "24h, 7d, 30d"},
        "monitoring",
        "GET",
        "/monitoring/alerts/00000000-0000-0000-0000-000000000000",
        404,
        "api.monitoring.record_not_found",
        {"field": "alert"},
    ),
    (
        "notifications",
        "POST",
        "/notifications/inbox/00000000000000000000000000000000/read",
        404,
        "api.notifications.record_not_found",
        {"field": "notification"},
    ),
    (
        "agent_integrations",
        "GET",
        "/agent/sessions/00000000-0000-0000-0000-000000000000",
        404,
        "api.agent_integrations.record_not_found",
        {"field": "agent session"},
    ),
]


@pytest.mark.parametrize("locale", ["es", "en"])
@pytest.mark.parametrize("module,method,path,status,key,params", CASES)
def test_domain_errors_return_the_localized_key_and_params(
    env, module: str, method: str, path: str, status: int, key: str, params: dict, locale: str
) -> None:
    client, _ = env
    headers = admin_headers(client)
    headers["Accept-Language"] = locale

    response = client.request(method, f"{API}{path}", headers=headers)

    assert response.status_code == status, response.text
    error = response.json()["error"]
    assert error["key"] == key, module
    assert error["params"] == params
    assert error["message"] == t(key, locale, **params)
    other = "en" if locale == "es" else "es"
    assert error["message"] != t(key, other, **params)
