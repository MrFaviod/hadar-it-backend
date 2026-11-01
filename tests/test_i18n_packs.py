"""Language packs and extension catalogs through the extension lifecycle.

Every assertion goes through a public surface: the extension HTTP contract for
install/review/update/uninstall and ``/api/v1/i18n/*`` for the resolved
catalogs, so a passing test never proves an internal shortcut.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.extensions.sdk import contract
from itsm.extensions.sdk.generator import generate_package
from itsm.extensions.sdk.package import build_package, parse_package
from itsm.i18n import packs
from itsm.main import create_app
from tests.conftest import run_migrations
from tests.identity_support import Harness

ORIGIN = "http://testserver"
API = "/api/v1"
ADMIN_USERNAME = "ana.admin"
ADMIN_PASSWORD = "installer-password-2026"
PACK_ID = "pack-pt-br"
NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)

PT_CATALOG = {
    "api.error.not_found": "Não encontrado.",
    "api.i18n.unknown_doc_topic": "Não há documentação para {topic} em {locale}.",
    "api.i18n.text_unavailable": "Texto indisponível.",
}


def archive(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as handle:
        for name in sorted(files):
            handle.writestr(name, files[name])
    return buffer.getvalue()


def pack_manifest(
    *,
    version: str = "1.0.0",
    status: str = "reviewed",
    core: str = "^0.1.0",
    priority: int = 0,
    locale: str = "pt-BR",
    overrides: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "sdkVersion": 2,
        "kind": "language-pack",
        "id": PACK_ID,
        "name": "Português (Brasil)",
        "version": version,
        "locales": [{"tag": locale, "name": "Portuguese (Brazil)", "nativeName": "Português"}],
        "compatibility": {"core": core, "extensions": {}},
        "catalogs": {locale: f"i18n/{locale}.json"},
        "docs": {locale: {"licenses": f"i18n/docs/{locale}/licenses.md"}},
        "overrides": list(overrides),
        "priority": priority,
        "review": {"status": status},
    }


def pack_package(
    *,
    manifest: dict[str, Any] | None = None,
    catalogs: dict[str, dict[str, str]] | None = None,
) -> bytes:
    manifest = manifest or pack_manifest()
    catalogs = catalogs or {"pt-BR": PT_CATALOG}
    files = {"extension.json": json.dumps(manifest, ensure_ascii=False)}
    for locale, catalog in catalogs.items():
        files[f"i18n/{locale}.json"] = json.dumps(catalog, ensure_ascii=False)
    for locale, topics in (manifest.get("docs") or {}).items():
        for topic, path in topics.items():
            files[str(path)] = f"# {topic} ({locale})\n\nDocumentação de {topic}.\n"
    return archive(files)


def extension_package(
    *,
    extension_id: str = "notes-lab",
    version: str = "1.0.0",
    catalog: dict[str, str] | None = None,
) -> bytes:
    """A declarative module that also owns its ``ext.<id>.*`` catalogs."""
    generated = generate_package(
        extension_id=extension_id,
        name="Notes lab",
        description="Sample declarative module.",
        version=version,
        runtime="declarative",
    )
    manifest = dict(generated.manifest)
    manifest["i18n"] = {
        "sourceLocale": "es",
        "catalogs": {"es": "i18n/es.json", "en": "i18n/en.json"},
    }
    files = dict(generated.files)
    files["i18n/es.json"] = json.dumps(catalog or {f"ext.{extension_id}.title": "Notas"})
    files["i18n/en.json"] = json.dumps({f"ext.{extension_id}.title": "Notes"})
    files["extension.json"] = json.dumps(manifest)
    return archive(files)


def trusted_report(digest: str) -> dict[str, Any]:
    return {
        "status": "passed",
        "digest": digest,
        "sdkVersion": 2,
        "checks": [{"name": "unit-fixture", "status": "passed", "detail": "no execution"}],
        "errors": [],
        "container": {"source": "trusted-internal-unit-fixture", "notExecutionEvidence": True},
        "completedAt": NOW.isoformat(),
    }


class Env:
    def __init__(self, client: TestClient, harness: Harness, owner: Any) -> None:
        self.client = client
        self.harness = harness
        self.owner = owner

    @property
    def host(self) -> Any:
        return self.client.app.state.extensions  # type: ignore[attr-defined]

    def login(
        self, username: str = ADMIN_USERNAME, password: str = ADMIN_PASSWORD
    ) -> dict[str, str]:
        response = self.client.post(
            f"{API}/auth/login",
            json={"username": username, "password": password},
            headers={"Origin": ORIGIN},
        )
        assert response.status_code == 200, response.text
        return {"Origin": ORIGIN, "X-CSRF-Token": str(response.json()["csrfToken"])}

    def upload(self, data: bytes, headers: dict[str, str]) -> Any:
        return self.client.post(
            f"{API}/extensions/candidates",
            content=data,
            headers={**headers, "Content-Type": "application/zip"},
        )

    def candidate(self, data: bytes, headers: dict[str, str]) -> dict[str, Any]:
        response = self.upload(data, headers)
        assert response.status_code == 201, response.text
        return dict(response.json())

    def approve(
        self, candidate: dict[str, Any], headers: dict[str, str], *, expected: int | None
    ) -> Any:
        return self.client.post(
            f"{API}/extensions/candidates/{candidate['id']}/approve",
            json={"digest": candidate["digest"], "expectedVersion": expected},
            headers=headers,
        )

    def install(self, data: bytes, headers: dict[str, str]) -> dict[str, Any]:
        candidate = self.candidate(data, headers)
        response = self.approve(candidate, headers, expected=candidate["currentRevision"])
        assert response.status_code == 200, response.text
        return dict(response.json())

    def install_extension(self, data: bytes, headers: dict[str, str]) -> dict[str, Any]:
        candidate = self.candidate(data, headers)
        candidate = dict(
            self.host.record_validation_report(
                candidate["id"],
                trusted_report(candidate["digest"]),
                expected_version=candidate["revision"],
            )
        )
        response = self.approve(candidate, headers, expected=candidate["currentRevision"])
        assert response.status_code == 200, response.text
        return dict(response.json())

    def review(self, extension_id: str, status: str, expected: int, headers: dict[str, str]) -> Any:
        return self.client.post(
            f"{API}/extensions/{extension_id}/review",
            json={"status": status, "expectedVersion": expected},
            headers=headers,
        )

    def uninstall(self, extension_id: str, expected: int, headers: dict[str, str]) -> Any:
        return self.client.post(
            f"{API}/extensions/{extension_id}/uninstall",
            json={"expectedVersion": expected},
            headers=headers,
        )

    def locales(self) -> dict[str, Any]:
        response = self.client.get(f"{API}/i18n/locales")
        assert response.status_code == 200, response.text
        return dict(response.json())

    def tags(self) -> set[str]:
        return {str(entry["tag"]) for entry in self.locales()["locales"]}

    def revision(self) -> int:
        return int(self.locales()["revision"])

    def bundle(self, locale: str) -> Any:
        return self.client.get(f"{API}/i18n/bundle", params={"locale": locale})

    def messages(self, locale: str) -> dict[str, str]:
        response = self.bundle(locale)
        assert response.status_code == 200, response.text
        return dict(response.json()["messages"])

    def module(self, extension_id: str) -> dict[str, Any]:
        response = self.client.get(f"{API}/extensions")
        assert response.status_code == 200, response.text
        items = {item["id"]: item for item in response.json()["items"]}
        return items[extension_id]


@pytest.fixture
def env(settings_factory: Callable[..., Settings], tmp_path: Path) -> Iterator[Env]:
    settings = settings_factory(extension_data_path=tmp_path / "extensions-data")
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    harness = Harness(settings=settings, engine=create_engine_from_settings(settings))
    with harness.service() as service:
        user = service.bootstrap_superadmin(ADMIN_USERNAME, "Ana Admin", ADMIN_PASSWORD)
        owner = service.resolve_actor(user.id)
    with TestClient(create_app(settings)) as client:
        try:
            yield Env(client, harness, owner)
        finally:
            harness.close()


def test_language_pack_install_lists_pt_br_and_serves_catalogs(env: Env) -> None:
    headers = env.login()
    before = env.revision()

    installed = env.install(pack_package(), headers)

    assert installed["extensionId"] == PACK_ID
    assert installed["state"] == "installed"
    assert env.revision() > before
    descriptors = {entry["tag"]: entry for entry in env.locales()["locales"]}
    assert descriptors["pt-BR"] == {
        "tag": "pt-BR",
        "name": "Portuguese (Brazil)",
        "nativeName": "Português",
        "provider": PACK_ID,
    }
    messages = env.messages("pt-BR")
    assert messages["api.error.not_found"] == "Não encontrado."
    # Keys the pack does not define fall back through the documented chain; the
    # bundle reports the chain instead of duplicating the default catalog.
    assert env.bundle("pt-BR").json()["fallback"] == ["pt-BR", "es"]

    docs = env.client.get(
        f"{API}/i18n/docs", params={"locale": "pt-BR", "topic": "licenses"}, headers=headers
    )
    assert docs.status_code == 200, docs.text
    assert docs.json()["provider"] == PACK_ID
    assert "licenses" in docs.json()["content"]


def test_draft_pack_stays_inactive_until_an_authorized_review(env: Env) -> None:
    headers = env.login()
    env.install(pack_package(manifest=pack_manifest(status="draft")), headers)

    assert "pt-BR" not in env.tags()
    assert env.bundle("pt-BR").status_code == 404

    with env.harness.service() as service:
        role = service.create_role(env.owner, name="i18n reader", permissions=["assets.view"])
        service.create_user(
            env.owner,
            username="reviewer.one",
            name="Reviewer One",
            role_id=role.id,
            password="reviewer-password-2026",
        )
    module = env.module(PACK_ID)
    reviewer = env.login("reviewer.one", "reviewer-password-2026")
    denied = env.review(PACK_ID, "reviewed", module["revision"], reviewer)
    assert denied.status_code == 403, denied.text
    assert "pt-BR" not in env.tags()

    approved = env.review(PACK_ID, "reviewed", module["revision"], env.login())
    assert approved.status_code == 200, approved.text
    assert approved.json()["reviewStatus"] == "reviewed"
    assert "pt-BR" in env.tags()
    assert env.messages("pt-BR")["api.error.not_found"] == "Não encontrado."


def test_pack_override_precedence_and_silent_replacement_rejection(env: Env) -> None:
    headers = env.login()

    candidate = env.candidate(
        pack_package(
            manifest=pack_manifest(locale="es"),
            catalogs={"es": {"api.error.not_found": "No encontrado (pack)."}},
        ),
        headers,
    )
    # Owners live in the database, so the silent-replacement rule is enforced
    # when the pack is installed, not when bytes are first admitted.
    silent = env.approve(candidate, headers, expected=candidate["currentRevision"])
    assert silent.status_code == 422, silent.text
    assert "overrides" in silent.text
    assert env.messages("es")["api.error.not_found"] == "No encontrado."

    explicit = env.install(
        pack_package(
            manifest=pack_manifest(locale="es", overrides=("api.error.not_found",)),
            catalogs={"es": {"api.error.not_found": "Archivo no encontrado."}},
        ),
        headers,
    )
    assert explicit["state"] == "installed"
    bundle = env.bundle("es")
    assert bundle.status_code == 200, bundle.text
    assert bundle.json()["messages"]["api.error.not_found"] == "Archivo no encontrado."
    assert bundle.json()["overrides"] == {"api.error.not_found": "Archivo no encontrado."}


def test_pack_with_incompatible_core_range_is_rejected(env: Env) -> None:
    headers = env.login()
    before = env.revision()

    candidate = env.candidate(pack_package(manifest=pack_manifest(core=">=99.0.0")), headers)
    response = env.approve(candidate, headers, expected=candidate["currentRevision"])

    assert response.status_code == 422, response.text
    assert "core" in response.text
    assert env.revision() == before
    assert "pt-BR" not in env.tags()


def test_pack_locale_serves_backend_errors_for_a_user_preference(env: Env) -> None:
    headers = env.login()
    env.install(pack_package(manifest=pack_manifest(status="reviewed")), headers)

    preferred = env.client.patch(
        f"{API}/auth/me/preferences", json={"locale": "pt-BR"}, headers=headers
    )
    assert preferred.status_code == 200, preferred.text
    assert str(preferred.json()["locale"]).lower() == "pt-br"

    response = env.client.get(f"{API}/i18n/docs", params={"locale": "pt-BR", "topic": "missing"})

    assert response.status_code == 404, response.text
    error = response.json()["error"]
    assert error["message"] == "Não há documentação para missing em pt-BR."
    assert error["key"] == "api.i18n.unknown_doc_topic"


def test_pack_update_replaces_translations_and_uninstall_restores(env: Env) -> None:
    headers = env.login()
    env.install(pack_package(manifest=pack_manifest(status="reviewed")), headers)
    first = env.revision()

    updated_catalog = {**PT_CATALOG, "api.error.not_found": "Registro não encontrado."}
    candidate = env.candidate(
        pack_package(
            manifest=pack_manifest(version="1.1.0", status="reviewed"),
            catalogs={"pt-BR": updated_catalog},
        ),
        headers,
    )
    updated = env.approve(candidate, headers, expected=candidate["currentRevision"])
    assert updated.status_code == 200, updated.text
    assert env.revision() > first
    assert env.messages("pt-BR")["api.error.not_found"] == "Registro não encontrado."
    assert env.module(PACK_ID)["version"] == "1.1.0"

    removed = env.uninstall(PACK_ID, env.module(PACK_ID)["revision"], headers)

    assert removed.status_code == 200, removed.text
    assert "pt-BR" not in env.tags()
    assert env.bundle("pt-BR").status_code == 404
    assert env.messages("es")["api.error.not_found"] == "No encontrado."


def test_extension_i18n_catalogs_follow_the_module_lifecycle(env: Env) -> None:
    headers = env.login()
    env.install_extension(extension_package(), headers)

    messages = env.messages("es")
    assert messages["ext.notes-lab.title"] == "Notas"
    assert env.messages("en")["ext.notes-lab.title"] == "Notes"

    module = env.module("notes-lab")
    removed = env.uninstall("notes-lab", module["revision"], headers)

    assert removed.status_code == 200, removed.text
    assert "ext.notes-lab.title" not in env.messages("es")


def test_extension_i18n_namespace_violation_is_rejected_without_storage_change(env: Env) -> None:
    headers = env.login()
    before = env.revision()

    response = env.upload(
        extension_package(catalog={"api.error.not_found": "Secuestrado."}), headers
    )

    assert response.status_code == 422, response.text
    assert "namespace" in response.text
    assert env.revision() == before
    assert env.messages("es")["api.error.not_found"] == "No encontrado."


def test_v2_manifests_without_an_i18n_block_stay_valid() -> None:
    generated = generate_package(
        extension_id="plain-module",
        name="Plain module",
        description="A module that ships no translations.",
        runtime="declarative",
    )
    files = {name: text for name, text in generated.files.items() if not name.startswith("i18n/")}
    manifest = json.loads(files["extension.json"])
    manifest.pop("i18n")
    files["extension.json"] = json.dumps(manifest)
    assert "i18n" not in manifest
    assert contract.validate_manifest(manifest, known_core_permissions=())["id"] == "plain-module"
    built = build_package(files, known_core_permissions=())
    parsed = parse_package(built.data, known_core_permissions=())
    assert "i18n" not in parsed.manifest


def test_reference_packages_ship_bilingual_catalogs() -> None:
    for runtime in ("sandboxed", "declarative"):
        generated = generate_package(
            extension_id="sample-module",
            name="Sample module",
            description="Reference package for catalog checks.",
            runtime=runtime,
        )
        block = generated.manifest["i18n"]
        assert set(block["catalogs"]) == {"es", "en"}
        assert packs.validate_i18n_files(generated.manifest, generated.files) == []
        assert "ext.sample-module.title" in json.loads(generated.files["i18n/es.json"])

    root = Path("itsm/extensions/sdk/examples/software-licenses")
    for version_dir in sorted(root.iterdir()):
        files = {
            path.relative_to(version_dir).as_posix(): path.read_text(encoding="utf-8")
            for path in version_dir.rglob("*")
            if path.is_file()
        }
        manifest = json.loads(files["extension.json"])
        assert set(manifest["i18n"]["catalogs"]) == {"es", "en"}
        assert packs.validate_i18n_files(manifest, files) == []


def test_example_language_pack_validates_against_the_core_and_extension_sources() -> None:
    root = Path("itsm/extensions/sdk/examples/language-pack-pt-br")
    files = {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in root.rglob("*")
        if path.is_file()
    }
    manifest = json.loads(files["extension.json"])
    extension_files = {
        path.relative_to(
            Path("itsm/extensions/sdk/examples/software-licenses/1.1.0")
        ).as_posix(): path.read_text(encoding="utf-8")
        for path in Path("itsm/extensions/sdk/examples/software-licenses/1.1.0").rglob("*")
        if path.is_file()
    }
    extension_manifest = json.loads(extension_files["extension.json"])
    catalogs, _docs = packs.read_i18n_content(manifest, files)
    from itsm.extensions.sdk import package as sdk_package
    from itsm.extensions.sdk.validator.harness import validate_payload
    from itsm.extensions.sdk.validator.protocol import build_frame

    built = sdk_package.build_package(files, known_core_permissions=())
    reused = sdk_package.parse_package(built.data, known_core_permissions=())
    assert reused.manifest["kind"] == "language-pack"
    report = validate_payload(
        build_frame(built.data, digest=built.digest, known_core_permissions=())
    )
    assert report["status"] == "passed", report
    assert {check["name"] for check in report["checks"]} == {
        "protocol",
        "archive",
        "manifest",
        "layout",
    }
    problems = packs.validate_i18n_files(
        manifest,
        files,
        sources={
            "core": json.loads(Path("itsm/i18n/catalogs/es.json").read_text(encoding="utf-8")),
            "software-licenses": json.loads(
                extension_files[extension_manifest["i18n"]["catalogs"]["es"]]
            ),
        },
        owner_catalogs={},
    )
    assert problems == [], problems
    assert catalogs  # the pack is complete for its declared locale


def test_sdk_contract_checks_the_i18n_block_without_the_host_package():
    """The validator image ships only ``sdk/``, so its rules live in the contract."""
    from itsm.extensions.sdk.contract import ManifestError, validate_manifest
    from itsm.extensions.sdk.generator import generate_package

    generated = generate_package(
        extension_id="notes-board",
        name="Tablero de notas",
        description="Notas declarativas con catálogos bilingües.",
        runtime="declarative",
    )
    manifest = dict(generated.manifest)

    overriding = dict(manifest)
    overriding["i18n"] = {**manifest["i18n"], "overrides": ["api.error.not_found"]}
    with pytest.raises(ManifestError) as excinfo:
        validate_manifest(overriding, known_core_permissions=())
    assert "overrides" in str(excinfo.value)

    outside = dict(manifest)
    outside["i18n"] = {"sourceLocale": "es", "catalogs": {"es": "catalogs/es.json"}}
    with pytest.raises(ManifestError) as excinfo:
        validate_manifest(outside, known_core_permissions=())
    assert "i18n/*.json" in str(excinfo.value) or "i18n.catalogs" in str(excinfo.value)

    validate_manifest(manifest, known_core_permissions=())
