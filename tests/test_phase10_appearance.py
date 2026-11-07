"""Phase 10 appearance: durable presets, safe graphics, ZIP trust boundary."""

from __future__ import annotations

import base64
import io
import json
import struct
import warnings
import zipfile
from pathlib import Path
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from itsm.appearance import service as appearance_service
from itsm.appearance.api import create_appearance_router
from itsm.appearance.integration import appearance_report_branding, appearance_report_logo
from itsm.appearance.models import AppearancePreset, AppearanceResource, AppearanceState
from itsm.appearance.service import AppearanceService, build_appearance_service
from itsm.identity.api import create_identity_router, install_error_handlers
from itsm.identity.service import IdentityService
from itsm.inventory.models import InventoryBase
from itsm.reports.service import build_report_service
from PIL import Image
from sqlalchemy import select
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import MACHINE_PASSWORD, Catalog, prepare, sign_in_as

SAFE_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">'
    b'<defs><linearGradient id="g"><stop offset="0" stop-color="#0d766e"/></linearGradient></defs>'
    b'<path d="M4 4h40v40H4z" fill="url(#g)"/></svg>'
)
UNSAFE_SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


def png_bytes(
    size: tuple[int, int] = (48, 48),
    color: tuple[int, int, int, int] = (13, 118, 110, 255),
) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGBA", size, color).save(buffer, format="PNG")
    return buffer.getvalue()


def ico_bytes() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGBA", (32, 32), (12, 35, 51, 255)).save(buffer, format="ICO")
    return buffer.getvalue()


def image_url(content_type: str, data: bytes) -> str:
    return f"data:{content_type};base64," + base64.b64encode(data).decode("ascii")


def preset_payload(
    name: str = "Marca de instalación",
    *,
    logo: str = "",
    logo_dark: str = "",
    logo_compact: str = "",
    favicon: str = "",
    organization: str = "Operaciones TI",
    primary: str = "#0b2331",
    accent: str = "#a65c13",
) -> dict[str, Any]:
    return {
        "name": name,
        "version": 1,
        "description": "Identidad de la instalación",
        "branding": {
            "appName": "Asset Manager",
            "organizationName": organization,
            "logo": logo,
            "logoDark": logo_dark,
            "logoCompact": logo_compact,
            "favicon": favicon,
        },
        "colors": {
            "light": {"primary": primary, "secondary": "#0d766e", "accent": accent},
            "dark": {"primary": "#071923", "secondary": "#62d4c7", "accent": "#f6bf67"},
        },
        "preferences": {"defaultMode": "system", "compact": False},
    }


def zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        # Duplicate names are an intentional hostile fixture.
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                archive.writestr(name, data)
    return buffer.getvalue()


def manifest_bytes(preset: dict[str, Any], resources: list[dict[str, str]]) -> bytes:
    return json.dumps(
        {
            "format": "asset-manager-appearance",
            "version": 1,
            "preset": preset,
            "resources": resources,
        }
    ).encode()


def package_entries(
    preset: dict[str, Any] | None = None,
    files: dict[str, bytes] | None = None,
    resources: list[dict[str, str]] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    document = preset or preset_payload()
    stored = files or {}
    index = resources or []
    entries = [("preset.json", manifest_bytes(document, index))]
    entries.extend(stored.items())
    return zip_bytes(entries), document


def patch_central(zip_data: bytes, name: str, offset: int, fmt: str, value: int) -> bytes:
    payload = bytearray(zip_data)
    needle = b"PK\x01\x02"
    cursor = 0
    while True:
        index = payload.find(needle, cursor)
        assert index >= 0, "central directory entry not found"
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", payload, index + 28)
        entry_name = bytes(payload[index + 46 : index + 46 + name_length]).decode()
        if entry_name == name:
            struct.pack_into(fmt, payload, index + offset, value)
            return bytes(payload)
        cursor = index + 46 + name_length + extra_length + comment_length


@pytest.fixture
def catalog(settings_factory: Any, tmp_path: Path) -> Catalog:
    prepared = prepare(
        settings_factory,
        attachment_storage_path=tmp_path / "blobs",
        auth_origin="http://testserver",
    )
    InventoryBase.metadata.create_all(
        prepared.engine,
        tables=[
            AppearancePreset.__table__,
            AppearanceResource.__table__,
            AppearanceState.__table__,
        ],
    )
    return prepared


def open_client(catalog: Catalog) -> TestClient:
    app = FastAPI()
    app.state.settings = catalog.settings
    app.state.session_factory = catalog.factory()
    app.state.appearance_service = build_appearance_service(catalog.settings, catalog.factory())
    install_error_handlers(app)
    api = APIRouter(prefix=catalog.settings.api_prefix)
    api.include_router(create_identity_router())
    api.include_router(create_appearance_router())
    app.include_router(api)
    client = TestClient(app)
    client.__enter__()
    return client


@pytest.fixture
def api(catalog: Catalog):
    client = open_client(catalog)
    headers = sign_in_as(client, catalog.settings, ADMIN_USERNAME, ADMIN_PASSWORD)
    try:
        yield client, headers
    finally:
        client.__exit__(None, None, None)


def active(client: TestClient) -> dict[str, Any]:
    response = client.get(f"{client.app.state.settings.api_prefix}/appearance/active")
    assert response.status_code == 200, response.text
    return response.json()


def row_counts(catalog: Catalog) -> tuple[int, int]:
    with catalog.session() as session:
        presets = len(session.execute(select(AppearancePreset)).scalars().all())
        resources = len(session.execute(select(AppearanceResource)).scalars().all())
    return presets, resources


def create(client: TestClient, headers: dict[str, str], payload: dict[str, Any]) -> dict[str, Any]:
    response = client.post(
        f"{client.app.state.settings.api_prefix}/appearance/presets",
        json=payload,
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["preset"]


def apply(client: TestClient, headers: dict[str, str], preset_id: str) -> dict[str, Any]:
    response = client.post(
        f"{client.app.state.settings.api_prefix}/appearance/apply/{preset_id}", headers=headers
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_service_accepts_canonical_session_identity_and_settings(catalog: Catalog) -> None:
    with catalog.session() as session:
        service = AppearanceService(
            session,
            IdentityService(session, catalog.settings),
            catalog.settings,
            source="api",
        )
        assert service.active()["activeId"] == "generic"
        assert service.builtin_asset("logo")[0] == "image/svg+xml"


def test_mixed_invalid_graphics_store_no_blob(
    catalog: Catalog, api: tuple[TestClient, dict[str, str]]
) -> None:
    client, headers = api
    before = row_counts(catalog)
    blobs = len(list(Path(catalog.settings.attachment_storage_path).glob("*")))
    response = client.post(
        f"{catalog.settings.api_prefix}/appearance/presets",
        json=preset_payload(
            "Gráficos mixtos",
            logo=image_url("image/png", png_bytes()),
            logo_dark="https://evil.example/logo.svg",
        ),
        headers=headers,
    )
    assert response.status_code == 422
    assert row_counts(catalog) == before
    assert len(list(Path(catalog.settings.attachment_storage_path).glob("*"))) == blobs


def test_storage_failure_is_503_without_persisted_rows(
    catalog: Catalog,
    api: tuple[TestClient, dict[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("storage offline")

    monkeypatch.setattr(appearance_service.LocalBlobStorage, "put", fail)
    client, headers = api
    before = row_counts(catalog)
    response = client.post(
        f"{catalog.settings.api_prefix}/appearance/presets",
        json=preset_payload("Offline", logo=image_url("image/png", png_bytes())),
        headers=headers,
    )
    assert response.status_code == 503
    assert row_counts(catalog) == before


def test_public_identity_and_graphic_routes_work_before_login(catalog: Catalog) -> None:
    client = open_client(catalog)
    try:
        identity = active(client)
        assert identity["active"]["id"] == "generic"
        assert identity["activeId"] == "generic"
        assert identity["previousId"] is None
        assert identity["builtinIds"] == ["generic", "blue", "forest"]
        assert identity["active"]["branding"]["appName"] == "Asset Manager"
        prefix = catalog.settings.api_prefix
        logo = client.get(f"{prefix}/appearance/assets/logo")
        assert logo.status_code == 200
        assert logo.headers["content-type"].startswith("image/svg+xml")
        assert "sandbox" in logo.headers["content-security-policy"]
        assert logo.content.startswith(b"<svg")
        assert client.get(f"{prefix}/appearance/presets").status_code == 401
        headers = sign_in_as(client, catalog.settings, ADMIN_USERNAME, ADMIN_PASSWORD)
        catalog_response = client.get(f"{prefix}/appearance/presets", headers=headers)
        assert catalog_response.status_code == 200
        body = catalog_response.json()
        assert [preset["id"] for preset in body["presets"]] == ["generic", "blue", "forest"]
    finally:
        client.__exit__(None, None, None)


def test_create_apply_restore_revert_and_persist_across_restart(
    catalog: Catalog, api: tuple[TestClient, dict[str, str]]
) -> None:
    client, headers = api
    prefix = catalog.settings.api_prefix
    first = create(
        client,
        headers,
        preset_payload(
            "Identidad uno",
            logo=image_url("image/svg+xml", SAFE_SVG),
            logo_dark=image_url("image/png", png_bytes()),
            favicon=image_url("image/x-icon", ico_bytes()),
        ),
    )
    assert first["id"].startswith("custom-")
    assert first["version"] == 1
    assert first["branding"]["logo"].startswith(f"{prefix}/appearance/resources/")
    logo_response = client.get(first["branding"]["logo"])
    assert logo_response.status_code == 200
    assert logo_response.content == SAFE_SVG
    assert logo_response.headers["cache-control"].startswith("public")
    favicon_response = client.get(first["branding"]["favicon"])
    assert favicon_response.status_code == 200
    assert favicon_response.headers["content-type"] == "image/x-icon"
    assert favicon_response.content == ico_bytes()

    applied = apply(client, headers, first["id"])
    assert applied["activeId"] == first["id"]
    assert applied["previousId"] == "generic"
    assert applied["active"]["colors"]["light"]["primary"] == "#0b2331"

    second = create(client, headers, preset_payload("Identidad dos", primary="#123456"))
    applied = apply(client, headers, second["id"])
    assert applied["previousId"] == first["id"]

    reverted = client.post(f"{prefix}/appearance/revert", headers=headers)
    assert reverted.status_code == 200, reverted.text
    assert reverted.json()["activeId"] == first["id"]
    assert reverted.json()["previousId"] == second["id"]

    restored = client.post(f"{prefix}/appearance/restore", headers=headers)
    assert restored.status_code == 200, restored.text
    assert restored.json()["activeId"] == "generic"
    assert restored.json()["previousId"] == first["id"]

    # A fresh service/client reads the durable state, not process memory.
    restarted = open_client(catalog)
    try:
        persisted = active(restarted)
        assert persisted["activeId"] == "generic"
        assert persisted["previousId"] == first["id"]
        with catalog.session() as session:
            state = session.get(AppearanceState, 1)
            assert state is not None and state.active_id == "generic"
            assert state.previous_id == first["id"]
    finally:
        restarted.__exit__(None, None, None)


def test_builtin_immutability_and_active_delete_conflict(
    catalog: Catalog, api: tuple[TestClient, dict[str, str]]
) -> None:
    client, headers = api
    prefix = catalog.settings.api_prefix
    assert (
        client.put(
            f"{prefix}/appearance/presets/generic",
            json=preset_payload("No permitido"),
            headers=headers,
        ).status_code
        == 409
    )
    assert client.delete(f"{prefix}/appearance/presets/generic", headers=headers).status_code == 409
    assert (
        client.post(f"{prefix}/appearance/restore", headers=headers).json()["activeId"] == "generic"
    )
    first = create(client, headers, preset_payload("Activa"))
    apply(client, headers, first["id"])
    assert (
        client.delete(f"{prefix}/appearance/presets/{first['id']}", headers=headers).status_code
        == 409
    )
    second = create(client, headers, preset_payload("Secundaria"))
    deleted = client.delete(f"{prefix}/appearance/presets/{second['id']}", headers=headers)
    assert deleted.status_code == 204
    assert deleted.content == b""


def test_permissions_and_csrf_are_reused(
    catalog: Catalog, api: tuple[TestClient, dict[str, str]]
) -> None:
    client, headers = api
    prefix = catalog.settings.api_prefix
    assert (
        client.post(
            f"{prefix}/appearance/presets",
            json=preset_payload("Sin csrf"),
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"{prefix}/appearance/restore",
            json={},
            headers={"Origin": catalog.settings.auth_origin, "X-CSRF-Token": "wrong"},
        ).status_code
        == 403
    )
    create(client, headers, preset_payload("Sin permiso"))
    catalog.add_user("reader-appearance", "Reader Appearance", "user")
    reader_headers = sign_in_as(client, catalog.settings, "reader-appearance", MACHINE_PASSWORD)
    assert (
        client.post(
            f"{prefix}/appearance/presets",
            json=preset_payload("Lector"),
            headers=reader_headers,
        ).status_code
        == 403
    )
    assert client.get(f"{prefix}/appearance/presets", headers=reader_headers).status_code == 200


def test_export_preview_import_roundtrip_and_staging(
    catalog: Catalog, api: tuple[TestClient, dict[str, str]]
) -> None:
    client, headers = api
    prefix = catalog.settings.api_prefix
    logo = png_bytes((64, 64), (30, 90, 140, 255))
    favicon = ico_bytes()
    created = create(
        client,
        headers,
        preset_payload(
            "Portable",
            logo=image_url("image/png", logo),
            favicon=image_url("image/x-icon", favicon),
        ),
    )
    exported = client.get(f"{prefix}/appearance/presets/{created['id']}/export", headers=headers)
    assert exported.status_code == 200, exported.text
    assert exported.headers["content-type"] == "application/zip"
    assert "attachment;" in exported.headers["content-disposition"]
    with zipfile.ZipFile(io.BytesIO(exported.content)) as archive:
        manifest = json.loads(archive.read("preset.json"))
        assert manifest["format"] == "asset-manager-appearance"
        assert manifest["version"] == 1
        assert manifest["preset"]["branding"]["logo"].startswith("resources/logo.")
        assert archive.read(manifest["preset"]["branding"]["logo"]) == logo
        assert archive.read(manifest["preset"]["branding"]["favicon"]) == favicon

    before = row_counts(catalog)
    blob_count = len(list(Path(catalog.settings.attachment_storage_path).glob("*")))
    preview = client.post(
        f"{prefix}/appearance/import/preview",
        content=exported.content,
        headers={**headers, "Content-Type": "application/zip"},
    )
    assert preview.status_code == 200, preview.text
    detected = preview.json()
    assert detected["preset"]["branding"]["logo"].startswith("data:image/png;base64,")
    assert {resource["key"] for resource in detected["resources"]} == {"logo", "favicon"}
    assert detected["comparison"]["sameAsActive"] is False
    assert row_counts(catalog) == before
    assert len(list(Path(catalog.settings.attachment_storage_path).glob("*"))) == blob_count

    imported = client.post(
        f"{prefix}/appearance/import",
        json={"preset": detected["preset"], "policy": "both"},
        headers=headers,
    )
    assert imported.status_code == 201, imported.text
    staged = imported.json()
    assert staged["staged"] is True
    assert staged["preset"]["id"].startswith("custom-")
    assert active(client)["activeId"] == "generic"
    assert any(
        preset["id"] == staged["preset"]["id"] and preset["name"].endswith("(2)")
        for preset in client.get(f"{prefix}/appearance/presets", headers=headers).json()["presets"]
    )
    applied = apply(client, headers, staged["preset"]["id"])
    assert applied["activeId"] == staged["preset"]["id"]
    assert applied["active"]["branding"]["logo"] == staged["preset"]["branding"]["logo"]


def test_export_import_into_a_second_installation_preserves_graphics(
    catalog: Catalog,
    api: tuple[TestClient, dict[str, str]],
    settings_factory: Any,
    tmp_path: Path,
) -> None:
    client, headers = api
    prefix = catalog.settings.api_prefix
    logo = png_bytes((64, 64), (30, 90, 140, 255))
    favicon = ico_bytes()
    created = create(
        client,
        headers,
        preset_payload(
            "Portable",
            logo=image_url("image/png", logo),
            favicon=image_url("image/x-icon", favicon),
        ),
    )
    exported = client.get(f"{prefix}/appearance/presets/{created['id']}/export", headers=headers)
    assert exported.status_code == 200, exported.text

    other = prepare(
        settings_factory,
        database_url=f"sqlite:///{tmp_path / 'other-install.db'}",
        attachment_storage_path=tmp_path / "other-blobs",
    )
    InventoryBase.metadata.create_all(
        other.engine,
        tables=[
            AppearancePreset.__table__,
            AppearanceResource.__table__,
            AppearanceState.__table__,
        ],
    )
    other_client = open_client(other)
    try:
        other_headers = sign_in_as(other_client, other.settings, ADMIN_USERNAME, ADMIN_PASSWORD)
        other_prefix = other.settings.api_prefix
        assert active(other_client)["activeId"] == "generic"
        preview = other_client.post(
            f"{other_prefix}/appearance/import/preview",
            content=exported.content,
            headers=other_headers,
        )
        assert preview.status_code == 200, preview.text
        imported = other_client.post(
            f"{other_prefix}/appearance/import",
            json={"preset": preview.json()["preset"], "policy": "both"},
            headers=other_headers,
        )
        assert imported.status_code == 201, imported.text
        staged = imported.json()["preset"]
        applied = apply(other_client, other_headers, staged["id"])
        assert applied["activeId"] == staged["id"]
        assert applied["active"]["branding"]["logo"] != created["branding"]["logo"]
        assert other_client.get(applied["active"]["branding"]["logo"]).content == logo
        assert other_client.get(applied["active"]["branding"]["favicon"]).content == favicon
        assert (
            active(other_client)["active"]["branding"]["logo"]
            == (applied["active"]["branding"]["logo"])
        )
    finally:
        other_client.__exit__(None, None, None)


def test_generic_export_is_real_and_self_contained(
    catalog: Catalog, api: tuple[TestClient, dict[str, str]]
) -> None:
    client, headers = api
    prefix = catalog.settings.api_prefix
    exported = client.get(f"{prefix}/appearance/presets/generic/export", headers=headers)
    assert exported.status_code == 200, exported.text
    with zipfile.ZipFile(io.BytesIO(exported.content)) as archive:
        assert archive.testzip() is None
        manifest = json.loads(archive.read("preset.json"))
        references = [
            manifest["preset"]["branding"][key]
            for key in ("logo", "logoDark", "logoCompact", "favicon")
            if manifest["preset"]["branding"][key]
        ]
        assert references
        assert all(reference.startswith("resources/") for reference in references)
        assert all(archive.read(reference) for reference in references)
    preview = client.post(
        f"{prefix}/appearance/import/preview",
        content=exported.content,
        headers={**headers, "Content-Type": "application/zip"},
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["comparison"]["sameAsActive"] is True


def _valid_malicious_base() -> tuple[dict[str, Any], bytes]:
    preset = preset_payload("Malicioso", logo="resources/logo.svg")
    payload = SAFE_SVG
    return preset, payload


def _package(preset: dict[str, Any], name: str, content_type: str, data: bytes) -> bytes:
    entries = [
        (
            "preset.json",
            manifest_bytes(preset, [{"key": "logo", "name": name, "type": content_type}]),
        ),
        (name, data),
    ]
    return zip_bytes(entries)


MALICIOUS_PACKAGES: list[tuple[str, Any]] = []


def _register(label: str, builder: Any) -> None:
    MALICIOUS_PACKAGES.append((label, builder))


_register(
    "traversal",
    lambda: zip_bytes(
        [
            ("preset.json", manifest_bytes(preset_payload(), [])),
            ("../evil.svg", SAFE_SVG),
        ]
    ),
)
_register(
    "duplicate",
    lambda: zip_bytes(
        [
            ("preset.json", manifest_bytes(preset_payload(), [])),
            ("preset.json", manifest_bytes(preset_payload(), [])),
        ]
    ),
)
_register(
    "manifest-case-mismatch",
    lambda: zip_bytes([("Preset.JSON", manifest_bytes(preset_payload(), []))]),
)
_register(
    "unknown-entry",
    lambda: zip_bytes(
        [
            ("preset.json", manifest_bytes(preset_payload(), [])),
            ("extra.txt", b"extra"),
        ]
    ),
)
_register(
    "incompatible-version",
    lambda: zip_bytes(
        [
            (
                "preset.json",
                json.dumps(
                    {
                        "format": "asset-manager-appearance",
                        "version": 2,
                        "preset": preset_payload(),
                        "resources": [],
                    }
                ).encode(),
            )
        ]
    ),
)
_register(
    "unsafe-svg",
    lambda: _package(
        preset_payload("Malicioso", logo="resources/logo.svg"),
        "resources/logo.svg",
        "image/svg+xml",
        UNSAFE_SVG,
    ),
)
_register(
    "favicon-type-mismatch",
    lambda: _package(
        preset_payload("Malicioso", favicon="resources/favicon.png"),
        "resources/favicon.png",
        "image/png",
        ico_bytes(),
    ),
)
_register(
    "external-reference",
    lambda: zip_bytes(
        [
            (
                "preset.json",
                manifest_bytes(
                    preset_payload("Malicioso", logo="https://evil.example/logo.png"), []
                ),
            )
        ]
    ),
)
_register(
    "encrypted-entry",
    lambda: patch_central(
        zip_bytes([("preset.json", manifest_bytes(preset_payload(), []))]),
        "preset.json",
        8,
        "<H",
        1,
    ),
)
_register(
    "bad-crc",
    lambda: patch_central(
        zip_bytes([("preset.json", manifest_bytes(preset_payload(), []))]),
        "preset.json",
        16,
        "<I",
        1,
    ),
)
_register(
    "too-many-entries",
    lambda: zip_bytes(
        [("preset.json", manifest_bytes(preset_payload(), []))]
        + [(f"resources/extra-{index}.txt", b"x") for index in range(40)]
    ),
)
_register(
    "expanded-bomb",
    lambda: zip_bytes(
        [
            ("preset.json", manifest_bytes(preset_payload(), [])),
            ("resources/bomb.svg", b" " * (9 * 1024 * 1024)),
        ]
    ),
)


@pytest.mark.parametrize(
    "label,builder", MALICIOUS_PACKAGES, ids=[item[0] for item in MALICIOUS_PACKAGES]
)
def test_malicious_or_corrupt_packages_are_rejected_without_state_change(
    catalog: Catalog,
    api: tuple[TestClient, dict[str, str]],
    label: str,
    builder: Any,
) -> None:
    client, headers = api
    prefix = catalog.settings.api_prefix
    before = row_counts(catalog)
    blobs = len(list(Path(catalog.settings.attachment_storage_path).glob("*")))
    response = client.post(
        f"{prefix}/appearance/import/preview",
        content=builder(),
        headers={**headers, "Content-Type": "application/zip"},
    )
    assert response.status_code == 422, f"{label}: {response.status_code} {response.text}"
    assert row_counts(catalog) == before
    assert len(list(Path(catalog.settings.attachment_storage_path).glob("*"))) == blobs
    assert active(client)["activeId"] == "generic"

    # The same bytes through import must not create a staged preset either.
    response = client.post(
        f"{prefix}/appearance/import",
        json={
            "preset": preset_payload("Malicioso", logo="https://evil.example/x"),
            "policy": "both",
        },
        headers=headers,
    )
    assert response.status_code == 422
    assert row_counts(catalog) == before


def test_oversized_preview_body_is_rejected(
    catalog: Catalog, api: tuple[TestClient, dict[str, str]]
) -> None:
    client, headers = api
    before = row_counts(catalog)
    response = client.post(
        f"{catalog.settings.api_prefix}/appearance/import/preview",
        content=b"0" * (24 * 1024 * 1024 + 1),
        headers={**headers, "Content-Type": "application/zip"},
    )
    assert response.status_code == 422
    assert row_counts(catalog) == before


def test_save_rejects_external_references_and_unsafe_svg(
    catalog: Catalog, api: tuple[TestClient, dict[str, str]]
) -> None:
    client, headers = api
    prefix = catalog.settings.api_prefix
    before = row_counts(catalog)
    for reference in (
        "https://evil.example/logo.svg",
        "//evil.example/logo.svg",
        "assets/img/not-known.png",
        "javascript:alert(1)",
    ):
        response = client.post(
            f"{prefix}/appearance/presets",
            json=preset_payload("Externo", logo=reference),
            headers=headers,
        )
        assert response.status_code == 422, response.text
    response = client.post(
        f"{prefix}/appearance/presets",
        json=preset_payload("Svg inseguro", logo=image_url("image/svg+xml", UNSAFE_SVG)),
        headers=headers,
    )
    assert response.status_code == 422
    assert row_counts(catalog) == before
    safe = create(
        client,
        headers,
        preset_payload("Svg seguro", logo=image_url("image/svg+xml", SAFE_SVG)),
    )
    assert safe["branding"]["logo"].startswith(f"{prefix}/appearance/resources/")


def test_stored_resource_must_match_the_graphic_slot_type(
    catalog: Catalog, api: tuple[TestClient, dict[str, str]]
) -> None:
    client, headers = api
    prefix = catalog.settings.api_prefix
    favicon = create(
        client,
        headers,
        preset_payload("Icono", favicon=image_url("image/x-icon", ico_bytes())),
    )
    resource_url = favicon["branding"]["favicon"]
    assert resource_url.startswith(f"{prefix}/appearance/resources/")
    before = row_counts(catalog)
    response = client.post(
        f"{prefix}/appearance/presets",
        json=preset_payload("Icono como logo", logo=resource_url),
        headers=headers,
    )
    assert response.status_code == 422
    assert row_counts(catalog) == before


def test_report_branding_seam_uses_active_installation_identity(catalog: Catalog) -> None:
    client = open_client(catalog)
    try:
        headers = sign_in_as(client, catalog.settings, ADMIN_USERNAME, ADMIN_PASSWORD)
        prefix = catalog.settings.api_prefix
        created = create(
            client,
            headers,
            preset_payload(
                "Informes",
                organization="Organización Central",
                primary="#225577",
                accent="#aa5500",
                logo=image_url("image/png", png_bytes()),
            ),
        )
        apply(client, headers, created["id"])
        with catalog.session() as session:
            branding = appearance_report_branding(session)
            assert branding == {
                "name": "Organización Central",
                "primary": "#225577",
                "accent": "#aa5500",
            }
            logo = appearance_report_logo(session, catalog.settings)
            assert logo == png_bytes()

        reports = build_report_service(catalog.settings, catalog.factory())
        wire = reports.get_settings(catalog.admin())
        assert wire["branding"]["name"] == "Organización Central"
        assert wire["branding"]["primary"] == "#225577"
        assert wire["branding"]["accent"] == "#aa5500"

        saved = reports.save_settings(
            catalog.admin(),
            {
                "baseUrl": catalog.settings.report_base_url,
                "branding": {
                    "name": "Informes explícitos",
                    "primary": "#101010",
                    "accent": "#202020",
                    "header": "",
                    "footer": "",
                },
                "labelDefaults": {"formatId": "a4-24"},
            },
        )
        assert saved["branding"]["name"] == "Informes explícitos"

        client.post(f"{prefix}/appearance/restore", headers=headers)
        with catalog.session() as session:
            assert appearance_report_branding(session) == {}
            assert appearance_report_logo(session, catalog.settings) is None
    finally:
        client.__exit__(None, None, None)
