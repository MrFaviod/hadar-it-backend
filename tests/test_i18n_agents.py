"""Superadmin language-pack tools and locale-aware agents (S7, S8)."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from itsm.config import Settings
from itsm.extensions.development import DevelopmentService, InvalidArguments
from itsm.i18n import registry
from itsm.i18n.registry import LocaleName, ProviderPayload
from itsm.identity.service import PermissionDenied
from tests.inventory_support import READER, Catalog, prepare

EXTENSION_CATALOGS = {
    "es": {
        "ext.software-licenses.title": "Licencias",
        "ext.software-licenses.count": "{count} licencia | {count} licencias",
    },
    "en": {
        "ext.software-licenses.title": "Licenses",
        "ext.software-licenses.count": "{count} license | {count} licenses",
    },
}


@dataclass
class PassingValidator:
    """Validator double: the workspace archive is real, the container is not."""

    calls: int = 0

    def validate(self, package_bytes: bytes, *, digest: str) -> dict[str, Any]:
        self.calls += 1
        return {
            "status": "passed",
            "digest": digest,
            "sdkVersion": 2,
            "checks": [{"name": "archive", "status": "passed", "detail": "fixture"}],
            "errors": [],
            "container": {"image": "itsm-extension-validator:1", "runtime": "fixture"},
            "completedAt": datetime.now(UTC).isoformat(),
        }


@pytest.fixture
def catalog(settings_factory: Callable[..., Settings]) -> Iterator[Catalog]:
    database = prepare(settings_factory)
    registry.configure(database.factory())
    try:
        yield database
    finally:
        registry.reset()
        database.engine.dispose()


@pytest.fixture
def admin(catalog: Catalog) -> Any:
    return catalog.admin()


@pytest.fixture
def reader(catalog: Catalog) -> Any:
    return catalog.add_user(*READER)


def seed_extension(
    catalog: Catalog,
    *,
    provider_id: str = "software-licenses",
    version: str = "1.0.0",
    catalogs: dict[str, dict[str, str]] | None = None,
) -> None:
    """Register an installed module's own source catalogs, as an install does."""
    with catalog.session() as session:
        registry.write_provider(
            session,
            ProviderPayload(
                provider_id=provider_id,
                kind=registry.EXTENSION,
                version=version,
                locales=(
                    LocaleName("es", "Spanish", "Español"),
                    LocaleName("en", "English", "English"),
                ),
                catalogs=catalogs or EXTENSION_CATALOGS,
            ),
        )
        session.commit()


def seed_pack(
    catalog: Catalog,
    *,
    provider_id: str = "pt-br",
    catalog_locale: str = "pt-BR",
    catalogs: dict[str, dict[str, str]] | None = None,
) -> None:
    with catalog.session() as session:
        registry.write_provider(
            session,
            ProviderPayload(
                provider_id=provider_id,
                kind=registry.LANGUAGE_PACK,
                version="1.0.0",
                locales=(LocaleName(catalog_locale, "Portuguese (Brazil)", "Português (Brasil)"),),
                catalogs=catalogs or {"pt-BR": {"ext.software-licenses.title": "Licenças"}},
            ),
        )
        session.commit()


def service(catalog: Catalog, root: Path) -> DevelopmentService:
    return DevelopmentService(
        root,
        session_factory=catalog.factory(),
        identity_factory=lambda session: catalog.service(session),
        validator=PassingValidator(),
    )


def keys_for(payload: dict[str, Any]) -> list[str]:
    return [item["key"] for item in payload["keys"]]


def test_i18n_keys_lists_core_context_and_installed_extension_keys(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    seed_extension(catalog)
    development = service(catalog, tmp_path)

    core = development.dispatch(
        "i18n_keys", {"namespace": "api", "prefix": "api.i18n.locale", "limit": 200}, admin
    )
    assert "api.i18n.locale_count" in keys_for(core)
    assert all(key.startswith("api.i18n.locale") for key in keys_for(core))
    entry = next(item for item in core["keys"] if item["key"] == "api.i18n.locale_count")
    assert entry["namespace"] == "api"
    assert entry["source"] == "core"
    assert entry["context"]
    assert entry["message"] == "{count} idioma instalado | {count} idiomas instalados"

    extension = development.dispatch("i18n_keys", {"namespace": "ext"}, admin)
    assert keys_for(extension) == [
        "ext.software-licenses.count",
        "ext.software-licenses.title",
    ]
    assert {item["source"] for item in extension["keys"]} == {"software-licenses"}
    assert {item["namespace"] for item in extension["keys"]} == {"ext.software-licenses"}
    assert all(item["context"] is None for item in extension["keys"])


def test_i18n_keys_pages_deterministically(catalog: Catalog, admin: Any, tmp_path: Path) -> None:
    development = service(catalog, tmp_path)
    first = development.dispatch("i18n_keys", {"namespace": "api", "limit": 5}, admin)
    second = development.dispatch("i18n_keys", {"namespace": "api", "limit": 5, "offset": 5}, admin)

    assert first["total"] == second["total"] > 5
    assert len(first["keys"]) == 5 and len(second["keys"]) == 5
    assert keys_for(first) == sorted(keys_for(first))
    assert not set(keys_for(first)) & set(keys_for(second))


def test_i18n_keys_rejects_an_unknown_namespace(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    development = service(catalog, tmp_path)
    with pytest.raises(InvalidArguments):
        development.dispatch("i18n_keys", {"namespace": "nowhere"}, admin)


def test_i18n_missing_reports_only_untranslated_keys(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    seed_extension(catalog)
    seed_pack(catalog)
    development = service(catalog, tmp_path)

    partial = development.dispatch("i18n_missing", {"locale": "pt-BR", "namespace": "ext"}, admin)
    assert partial["locale"] == "pt-BR"
    assert partial["sourceLocale"] == "es"
    assert [item["key"] for item in partial["missing"]] == ["ext.software-licenses.count"]

    untouched = development.dispatch("i18n_missing", {"locale": "fr-FR", "namespace": "ext"}, admin)
    assert [item["key"] for item in untouched["missing"]] == [
        "ext.software-licenses.count",
        "ext.software-licenses.title",
    ]


def test_i18n_missing_uses_the_resolved_parent_locale(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    seed_extension(catalog)
    with catalog.session() as session:
        registry.write_provider(
            session,
            ProviderPayload(
                provider_id="pt",
                kind=registry.LANGUAGE_PACK,
                version="1.0.0",
                locales=(LocaleName("pt", "Portuguese", "Português"),),
                catalogs={
                    "pt": {
                        "ext.software-licenses.title": "Licenças",
                        "ext.software-licenses.count": "{count} licença | {count} licenças",
                    }
                },
            ),
        )
        session.commit()
    development = service(catalog, tmp_path)

    payload = development.dispatch("i18n_missing", {"locale": "pt-BR", "namespace": "ext"}, admin)
    assert payload["missing"] == []
    assert payload["locale"] == "pt-BR"


def test_i18n_validate_rejects_parameters_plurals_and_keys(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    seed_extension(catalog)
    development = service(catalog, tmp_path)

    report = development.dispatch(
        "i18n_validate",
        {
            "locale": "pt-BR",
            "catalog": {
                "api.i18n.locale_count": "{count} idioma",
                "api.agent_integrations.api_key_empty": "{wrong}",
                "bad.key": "x",
                "ext.software-licenses.title": "Licenças",
            },
        },
        admin,
    )
    assert report["valid"] is False
    assert report["locale"] == "pt-BR"
    errors = " | ".join(report["errors"])
    assert "plural forms differ" in errors
    assert "parameters differ" in errors
    assert "invalid translation key" in errors


def test_i18n_validate_follows_the_target_locale_plural_categories(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    development = service(catalog, tmp_path)
    report = development.dispatch(
        "i18n_validate",
        {
            "locale": "ru",
            "catalog": {
                "api.i18n.locale_count": "{count} язык | {count} языка",
            },
        },
        admin,
    )
    assert report["valid"] is False
    assert any("plural" in error for error in report["errors"])


def test_i18n_validate_rejects_duplicate_json_keys(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    development = service(catalog, tmp_path)
    report = development.dispatch(
        "i18n_validate",
        {
            "locale": "pt-BR",
            "catalog": ('{"api.i18n.locale_count": "x | y", "api.i18n.locale_count": "z | w"}'),
        },
        admin,
    )
    assert report["valid"] is False
    assert any("duplicate key" in error for error in report["errors"])


def test_i18n_validate_requires_overrides_to_replace_owner_text(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    seed_extension(catalog)
    development = service(catalog, tmp_path)
    catalog_document = {"ext.software-licenses.title": "Licenças"}

    silent = development.dispatch(
        "i18n_validate", {"locale": "es", "catalog": catalog_document}, admin
    )
    assert silent["valid"] is False
    assert any("overrides" in error for error in silent["errors"])

    declared = development.dispatch(
        "i18n_validate",
        {
            "locale": "es",
            "catalog": catalog_document,
            "overrides": ["ext.software-licenses.title"],
        },
        admin,
    )
    assert declared["valid"] is True
    assert declared["errors"] == []


def test_i18n_validate_accepts_a_complete_catalog(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    development = service(catalog, tmp_path)
    report = development.dispatch(
        "i18n_validate",
        {
            "locale": "pt-BR",
            "catalog": {
                "api.i18n.locale_count": "{count} idioma | {count} idiomas",
            },
        },
        admin,
    )
    assert report == {"locale": "pt-BR", "valid": True, "keys": 1, "errors": []}


def test_i18n_package_scaffolds_a_draft_pack_covering_core_and_extensions(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    seed_extension(catalog, version="1.2.0")
    development = service(catalog, tmp_path)

    payload = development.dispatch(
        "i18n_package", {"workspace_id": "pt-br", "locale": "pt-BR"}, admin
    )
    assert payload["kind"] == "language-pack"
    assert payload["review"] == "draft"
    assert payload["tag"] == "pt-BR"
    assert [item["path"] for item in payload["files"]] == [
        "extension.json",
        "i18n/pt-BR.json",
    ]

    manifest_text = development.dispatch(
        "extension_workspace_read",
        {"workspace_id": "pt-br", "path": "extension.json"},
        admin,
    )
    manifest = json.loads(manifest_text["content"])
    assert manifest["kind"] == "language-pack"
    assert manifest["sdkVersion"] == 2
    assert manifest["id"] == "pt-br"
    assert manifest["review"] == {"status": "draft"}
    assert manifest["catalogs"] == {"pt-BR": "i18n/pt-BR.json"}
    assert manifest["locales"] == [
        {
            "tag": "pt-BR",
            "name": "Portuguese (Brazil)",
            "nativeName": "português (Brasil)",
        }
    ]
    assert manifest["compatibility"] == {
        "core": "^0.1.0",
        "extensions": {"software-licenses": "^1.2.0"},
    }

    catalogs = json.loads(
        development.dispatch(
            "extension_workspace_read",
            {"workspace_id": "pt-br", "path": "i18n/pt-BR.json"},
            admin,
        )["content"]
    )
    assert catalogs["ext.software-licenses.title"] == "Licencias"
    assert catalogs["api.i18n.locale_count"].startswith("{count} idioma instalado")

    report = development.dispatch("extension_workspace_validate", {"workspace_id": "pt-br"}, admin)
    assert report["status"] == "passed"


def test_i18n_package_never_marks_a_pack_reviewed(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    development = service(catalog, tmp_path)
    development.dispatch("i18n_package", {"workspace_id": "pt-br", "locale": "pt-BR"}, admin)

    manifest = json.loads(
        development.dispatch(
            "extension_workspace_read",
            {"workspace_id": "pt-br", "path": "extension.json"},
            admin,
        )["content"]
    )
    assert manifest["review"]["status"] == "draft"
    with catalog.session() as session:
        assert registry.provider_count(session, registry.LANGUAGE_PACK) == 0


def test_i18n_tools_require_module_administration(
    catalog: Catalog, reader: Any, tmp_path: Path
) -> None:
    development = service(catalog, tmp_path)
    calls: list[tuple[str, dict[str, Any]]] = [
        ("i18n_keys", {}),
        ("i18n_missing", {"locale": "pt-BR"}),
        ("i18n_validate", {"locale": "pt-BR", "catalog": {}}),
        ("i18n_package", {"workspace_id": "pt-br", "locale": "pt-BR"}),
    ]
    for method, arguments in calls:
        with pytest.raises(PermissionDenied):
            development.dispatch(method, arguments, reader)


def test_i18n_package_rejects_an_invalid_locale(
    catalog: Catalog, admin: Any, tmp_path: Path
) -> None:
    development = service(catalog, tmp_path)
    with pytest.raises(InvalidArguments):
        development.dispatch("i18n_package", {"workspace_id": "pt-br", "locale": "??"}, admin)


def test_i18n_missing_requires_a_locale(catalog: Catalog, admin: Any, tmp_path: Path) -> None:
    development = service(catalog, tmp_path)
    with pytest.raises(InvalidArguments):
        development.dispatch("i18n_missing", {}, admin)


# ------------------------------------------------------------------ S8: agents


class RecordingRuntime:
    """Pydantic runtime double that records the locale each turn was given."""

    configured = True

    def __init__(self) -> None:
        self.locales: list[str | None] = []

    def chat_with_usage(
        self,
        principal: Any,
        request: Any,
        *,
        credential_digest: str | None = None,
        usage: Any = None,
        quota: Any = None,
        **options: Any,
    ) -> tuple[Any, Any]:
        self.locales.append(options.get("locale"))
        if quota is not None:
            identifier = quota.before_call(8)
            quota.after_call(
                identifier,
                {
                    "type": "usage",
                    "totalTokens": 5,
                    "precision": "measured",
                    "source": "provider",
                },
            )
        from itsm.agents.runtime import ChatReply

        return ChatReply(message="hola", actions=[], results=[], approvalPending=False), usage


def _capture_agent(catalog: Catalog, client: Any, seen: list[dict[str, Any]]) -> Any:
    import pydantic_ai.models
    from itsm.agents.runtime import AgentRuntime
    from pydantic_ai.messages import ModelResponse, TextPart
    from pydantic_ai.models.function import FunctionModel

    def run(messages: Any, info: Any) -> Any:
        seen.append(
            {
                "instructions": info.instructions,
                "tools": {
                    tool.name: (
                        tool.description,
                        json.dumps(tool.parameters_json_schema, sort_keys=True),
                    )
                    for tool in info.function_tools
                },
            }
        )
        return ModelResponse(parts=[TextPart(content="ok")])

    pydantic_ai.models.ALLOW_MODEL_REQUESTS = False
    test_client = client(catalog.settings)
    runtime = AgentRuntime(catalog.settings, catalog.factory(), model=FunctionModel(run))
    test_client.app.state.agent_runtime = runtime
    test_client.app.state.isolated_runtime = runtime
    return test_client


def test_agent_instructions_and_tool_descriptions_follow_the_user_locale(
    catalog: Catalog, client: Any
) -> None:
    from tests.conftest import sign_in

    seen: list[dict[str, Any]] = []
    test_client = _capture_agent(catalog, client, seen)
    headers = sign_in(test_client, catalog.settings)
    admin = catalog.admin()

    with catalog.session() as session:
        catalog.service(session).update_preferences(admin, locale="en")
    english = test_client.post("/api/v1/agent/chat", json={"message": "hola"}, headers=headers)
    assert english.status_code == 200, english.text

    with catalog.session() as session:
        catalog.service(session).update_preferences(admin, locale="es")
    spanish = test_client.post("/api/v1/agent/chat", json={"message": "hola"}, headers=headers)
    assert spanish.status_code == 200, spanish.text

    assert (seen[0]["instructions"] or "").startswith("You are the ITSM inventory assistant")
    assert (seen[1]["instructions"] or "").startswith("Sos el asistente de inventario del ITSM")

    assert seen[0]["tools"].keys() == seen[1]["tools"].keys()
    for name, (_, schema) in seen[0]["tools"].items():
        assert seen[1]["tools"][name][1] == schema, name
    assert seen[0]["tools"]["extension_sdk_index"][0] != seen[1]["tools"]["extension_sdk_index"][0]
    assert seen[0]["tools"]["extension_sdk_index"][0].startswith("Discover")
    assert seen[1]["tools"]["extension_sdk_index"][0].startswith("Descubrí")


def test_a_conversation_keeps_the_locale_it_was_started_with(
    settings_factory: Callable[..., Settings],
) -> None:
    import asyncio

    from itsm.agent_integrations.service import AgentIntegrationService

    catalog = prepare(settings_factory, agent_model="openai:gpt-4o-mini")
    try:
        runtime = RecordingRuntime()
        service = AgentIntegrationService(catalog.settings, catalog.factory(), runtime=runtime)
        admin = catalog.admin()
        with catalog.session() as session:
            catalog.service(session).update_preferences(admin, locale="en")
        created = asyncio.run(
            service.create_session(
                admin, {"instanceId": "pydantic", "model": catalog.settings.agent_model}
            )
        )
        assert created["locale"] == "en"

        with catalog.session() as session:
            catalog.service(session).update_preferences(admin, locale="es")
        assert service.get_session(admin, created["id"])["locale"] == "en"

        async def drain() -> None:
            turn = service.prepare_turn(admin, created["id"], "hola", None)
            async for _event in turn.stream():
                pass

        asyncio.run(drain())
        assert runtime.locales == ["en"]
    finally:
        catalog.engine.dispose()


def test_external_engine_context_carries_the_conversation_locale(
    settings_factory: Callable[..., Settings],
) -> None:
    from itsm.agent_integrations.service import AgentIntegrationService
    from itsm.agents.engines import _compose_prompt

    catalog = prepare(settings_factory)
    try:
        service = AgentIntegrationService(catalog.settings, catalog.factory())
        history = service._external_history([{"role": "user", "content": "turno anterior"}], "en")
        assert history[0]["role"] == "system"
        prompt = _compose_prompt("hola", history)
        assert "Preferred user language: en." in prompt
        assert "Sistema: Preferred user language: en." in prompt
        assert "Usuario: turno anterior" in prompt
    finally:
        catalog.engine.dispose()


def test_sdk_index_references_the_language_pack_guidance(catalog, admin, tmp_path: Path) -> None:
    development = service(catalog, tmp_path / "references")

    index = development.dispatch("extension_sdk_index", {}, admin)

    assert "i18n" in {item["name"] for item in index["references"]}
    reference = development.dispatch("extension_sdk_reference", {"name": "i18n"}, admin)
    for tool in ("i18n_keys", "i18n_missing", "i18n_validate", "i18n_package"):
        assert tool in reference["content"]


PACK_TOOLS = ("i18n_keys", "i18n_missing", "i18n_validate", "i18n_package")


def test_pack_tools_are_registered_on_both_transports_with_bounded_arguments() -> None:
    from itsm.extensions import tools as extension_tools

    assert set(PACK_TOOLS) <= set(extension_tools.DEVELOPMENT_TOOL_NAMES)
    assert set(PACK_TOOLS) <= set(extension_tools.EXTENSION_TOOL_NAMES)

    class Collector:
        def __init__(self) -> None:
            self.functions: dict[str, Any] = {}

        def tool(self, function: Any) -> Any:
            self.functions[function.__name__] = function
            return function

    calls: list[tuple[str, dict[str, Any]]] = []
    server = Collector()
    extension_tools.register_mcp_extension_tools(
        server, lambda name, arguments: calls.append((name, arguments)) or {}
    )
    toolset = Collector()
    extension_tools.register_agent_extension_tools(
        toolset, lambda deps, name, arguments: calls.append((name, arguments)) or {}
    )
    assert set(PACK_TOOLS) <= set(server.functions)
    assert set(PACK_TOOLS) <= set(toolset.functions)

    server.functions["i18n_keys"]()
    server.functions["i18n_missing"]("pt-BR", namespace="ui", limit=10)
    server.functions["i18n_validate"]("pt-BR", {"ui.common.save": "Salvar"})
    server.functions["i18n_package"]("pack-pt-br", "pt-BR", name="Português")
    context = type("Context", (), {"deps": None})()
    toolset.functions["i18n_missing"](context, "pt-BR", offset=5)
    assert calls == [
        ("i18n_keys", {}),
        ("i18n_missing", {"locale": "pt-BR", "namespace": "ui", "limit": 10}),
        ("i18n_validate", {"locale": "pt-BR", "catalog": {"ui.common.save": "Salvar"}}),
        ("i18n_package", {"workspace_id": "pack-pt-br", "locale": "pt-BR", "name": "Português"}),
        ("i18n_missing", {"locale": "pt-BR", "offset": 5}),
    ]

    forwarded: list[str] = []

    class Development:
        def dispatch(self, name: str, arguments: Any, principal: Any) -> dict[str, Any]:
            forwarded.append(name)
            return {}

    for name in PACK_TOOLS:
        extension_tools.dispatch_extension_tool(
            name, {}, principal=None, host=None, development=Development()
        )
    assert forwarded == list(PACK_TOOLS)
