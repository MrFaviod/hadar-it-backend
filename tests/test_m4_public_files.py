"""Public CLI/SMTP coverage of M4 restore, dev and notification contracts."""

from __future__ import annotations

import json
from email.parser import BytesParser
from pathlib import Path

import pytest
from itsm.devtools import cli
from itsm.notifications.delivery import deliver_external
from tests.test_devtools_cli import (
    INVENTORY_ASSETS,
    PASSWORD,
    dev_settings,
    file_bytes,
    initialise,
    login_and_count,
    refused,
    run,
)
from tests.test_ops_extensions import (
    EXTENSION_ID,
    backup_artifact,
    create_module,
    restore,
    write_licenses,
)
from tests.test_ops_sqlite import migrated
from tests.test_phase8_notifications import _smtp_server, _smtp_url


def test_smtp_real_library_neutralizes_subject_headers_and_preserves_multiline_body(
    settings_factory,
):
    server = _smtp_server()
    try:
        settings = settings_factory(
            monitoring_secrets={"smtp": _smtp_url(server.server_address[1])}
        )
        outcome = deliver_external(
            "fixture",
            "smtp",
            "smtp",
            {},
            title="Asset\r\nBcc: nobody@example.test",
            body="first line\nsecond line",
            url=None,
            timeout_seconds=5,
            settings=settings,
        )
        assert outcome.state == "delivered"
        assert len(server.messages) == 1
        message = BytesParser().parsebytes(server.messages[0])
        assert message.get_all("Bcc") is None
        assert len(message.get_all("Subject")) == 1
        assert "Bcc: nobody@example.test" in message["Subject"]
        bodies = [
            part.get_payload(decode=True) for part in message.walk() if not part.is_multipart()
        ]
        assert any(b"first line\nsecond line" in body.replace(b"\r\n", b"\n") for body in bodies)
    finally:
        server.shutdown()
        server.server_close()


def test_reset_public_refuses_dev_substring_without_effect(tmp_path):
    initialise(tmp_path)
    outside = tmp_path / "outside-dev" / "attachments"
    outside.mkdir(parents=True)
    (outside / "keep").write_bytes(b"keep")
    before = file_bytes(tmp_path / "dev.db")
    result = run(
        tmp_path,
        "reset",
        "--yes-reset-dev-database",
        "--confirm",
        "dev.db",
        ITSM_ATTACHMENT_STORAGE_PATH=str(outside),
    )
    assert result.returncode == 1
    message = refused(result)
    assert message == (
        f"error: attachments path {outside} is outside the development data directory; "
        "next: set ITSM_DEV_DATA_DIR to the explicit parent root and keep state "
        "strictly inside it (nothing was changed)\n"
    )
    assert file_bytes(tmp_path / "dev.db") == before
    assert (outside / "keep").read_bytes() == b"keep"


def test_dev_interactive_password_hidden_and_usable(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ITSM_DEV_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: PASSWORD)
    monkeypatch.setattr(cli, "get_settings", lambda: dev_settings(tmp_path))
    assert cli.main(["init"]) == 0
    output = capsys.readouterr()
    assert PASSWORD not in output.out + output.err
    assert "password" not in json.loads(output.out)["admin"]
    assert json.loads(output.out)["admin"]["passwordSource"] == "interactive"
    assert login_and_count(dev_settings(tmp_path), "dev.admin", PASSWORD)[0] == INVENTORY_ASSETS


@pytest.mark.parametrize("mode", ["layout", "source-link", "target-link"])
def test_restore_cli_refuses_before_core_or_extension_write(settings_factory, tmp_path: Path, mode):
    settings = migrated(settings_factory)
    backup_root = tmp_path / "backups"
    data_root = tmp_path / "modules"
    module = create_module(data_root)
    write_licenses(module / "data.sqlite3", ["LIC-1"])
    (module / "files" / "first.txt").write_text("first")
    (module / "files" / "nested").mkdir()
    (module / "files" / "nested" / "last.txt").write_text("last")
    _, artifact, manifest = backup_artifact(settings, backup_root, data_root)
    destination = tmp_path / "restored"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "last.txt").write_text("last")
    extra = ["--target-file", str(tmp_path / "core-copy.db")]
    if mode == "layout":
        archived = artifact / "extensions" / EXTENSION_ID / "files/first.txt"
        archived.rename(archived.parent.parent / "config.json")
        for item in manifest["extensions"][0]["files"]:
            if item["path"] == "files/first.txt":
                item["path"] = "config.json"
        (artifact / "manifest.json").write_text(json.dumps(manifest))
    elif mode == "source-link":
        nested = artifact / "extensions" / EXTENSION_ID / "files/nested"
        (nested / "last.txt").unlink()
        nested.rmdir()
        nested.symlink_to(outside, target_is_directory=True)
    else:
        nested = destination / EXTENSION_ID / "files/nested"
        nested.parent.mkdir(parents=True)
        nested.symlink_to(outside, target_is_directory=True)
        extra += ["--replace-live", "--confirm", manifest["id"]]
        # No existing core target: the extension preflight must run before core restore.
    before = (outside / "last.txt").stat()
    result = restore(
        manifest["id"],
        settings,
        backup_root=backup_root,
        data_root=data_root,
        target=destination,
        extra=extra,
    )
    assert result.returncode == 1, (result.stdout, result.stderr)
    assert result.stdout == ""
    error = json.loads(result.stderr)
    assert error["status"] == "failed"
    expected = {
        "layout": f"extension {EXTENSION_ID}: unsupported restore layout: config.json",
        "source-link": (
            f"backup {manifest['id']} failed verification: extension {EXTENSION_ID}: "
            f"files/nested: symlink; extension {EXTENSION_ID}: "
            "files/nested/last.txt is missing from the artifact"
        ),
        "target-link": "extension restore path traverses a symlink",
    }
    assert error["error"] == expected[mode]
    assert not (tmp_path / "core-copy.db").exists()
    assert not (destination / EXTENSION_ID / "files/first.txt").exists()
    assert (outside / "last.txt").read_text() == "last"
    assert (outside / "last.txt").stat().st_mtime_ns == before.st_mtime_ns
