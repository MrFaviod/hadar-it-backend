"""M4 file boundaries, exercised with disposable paths and public operations."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest
from itsm.agent_integrations import installer as install
from itsm.devtools.guard import DevToolsRefused, require_dev_data_paths
from itsm.ops import engines, extensions, store
from tests.test_agent_installer import CatalogDouble, hermes_target, yaml_config
from tests.test_devtools_cli import dev_settings


@pytest.mark.parametrize("name", ["name] ; DROP DATABASE [other", "Sales ] 2026", "注文 DB"])
def test_mssql_identifier_is_one_delimited_identifier(name: str, tmp_path: Path) -> None:
    target = engines.database_target("mssql+pyodbc://sa@localhost/source")
    commands = [
        engines.mssql_backup_command(replace(target, database=name), tmp_path / "db.bak"),
        engines.mssql_restore_command(target, tmp_path / "db.bak", name),
    ]
    for command, verb in zip(commands, ["BACKUP", "RESTORE"], strict=True):
        statement = command.argv[command.argv.index("-Q") + 1]
        assert statement.startswith(f"{verb} DATABASE [{name.replace(']', ']]')}] ")
        assert not (tmp_path / "db.bak").exists()


def test_reset_dev_substring_cannot_override_explicit_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside-dev" / "attachments"
    outside.mkdir(parents=True)
    sentinel = outside / "keep"
    sentinel.write_bytes(b"unchanged")
    settings = dev_settings(tmp_path, attachment_storage_path=outside)
    with pytest.raises(DevToolsRefused, match="outside the development data directory"):
        require_dev_data_paths(settings, tmp_path / "dev-data")
    assert sentinel.read_bytes() == b"unchanged"
    inside = tmp_path / "dev-data" / "attachments"
    inside.mkdir(parents=True)
    assert require_dev_data_paths(dev_settings(tmp_path), tmp_path / "dev-data") == (inside,)


def restore_fixture(tmp_path: Path, paths: list[str]):
    artifact = tmp_path / "artifact"
    module = artifact / "extensions" / "sample"
    entries = []
    for relative in paths:
        source = module / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(b"fixture")
        digest, size = store.digest_file(source)
        entries.append(store.ExtensionFileEntry(relative, digest, size))
    return artifact, (store.ExtensionBackupEntry("sample", tuple(entries)),)


@pytest.mark.parametrize(
    "relative", ["config.json", "snapshots/extra/file.sqlite3", "snapshots/no.txt", "files"]
)
def test_restore_refuses_undeclared_layout_before_any_write(tmp_path: Path, relative: str) -> None:
    artifact, entries = restore_fixture(tmp_path, ["files/first.txt"])
    if relative == "files":
        bad = store.ExtensionFileEntry("files", "0" * 64, 0)
        entries = (store.ExtensionBackupEntry("sample", (*entries[0].files, bad)),)
    else:
        artifact, entries = restore_fixture(tmp_path, ["files/first.txt", relative])
    target = tmp_path / "destination"
    with pytest.raises(engines.OpsError, match="layout"):
        extensions.restore(artifact, entries, destination=target, replace=False)
    assert not target.exists()
    assert (artifact / "extensions/sample/files/first.txt").read_bytes() == b"fixture"


@pytest.mark.parametrize("side", ["source", "destination"])
def test_restore_refuses_symlink_ancestor_without_partial_effect(tmp_path: Path, side: str) -> None:
    artifact, entries = restore_fixture(tmp_path, ["files/first.txt", "files/nested/last.txt"])
    target = tmp_path / "destination"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "last.txt").write_bytes(b"fixture")
    if side == "source":
        nested = artifact / "extensions/sample/files/nested"
        (nested / "last.txt").unlink()
        nested.rmdir()
        nested.symlink_to(outside, target_is_directory=True)
    else:
        nested = target / "sample/files/nested"
        nested.parent.mkdir(parents=True)
        nested.symlink_to(outside, target_is_directory=True)
    before = (outside / "last.txt").stat()
    with pytest.raises(engines.OpsError, match="symlink"):
        extensions.restore(artifact, entries, destination=target, replace=side == "destination")
    assert (outside / "last.txt").read_bytes() == b"fixture"
    assert (outside / "last.txt").stat().st_mtime_ns == before.st_mtime_ns
    assert not (target / "sample/files/first.txt").exists()


def test_hermes_file_symlink_never_reads_external_frontmatter(tmp_path: Path) -> None:
    target, home = hermes_target(tmp_path / "profile")
    external = tmp_path / "private.md"
    external.write_text("---\nname: PRIVATE-EXTERNAL-NAME\n---\n")
    linked = home / "skills" / "linked-skill"
    linked.mkdir(parents=True)
    (linked / "SKILL.md").symlink_to(external)
    receipt = asyncio.run(
        install.IntegrationInstaller(catalog=CatalogDouble()).apply(
            target,
            mcp={
                "url": "http://127.0.0.1:1/mcp",
                "secretRef": "M4_MISSING_TOKEN",
                "identityId": "fixture",
            },
            skills=[],
        )
    )
    assert receipt["status"] == "configured", receipt
    disabled = yaml_config(home / "config.yaml")["skills"]["disabled"]
    assert "linked-skill" in disabled
    assert "PRIVATE-EXTERNAL-NAME" not in disabled
    assert external.read_text() == "---\nname: PRIVATE-EXTERNAL-NAME\n---\n"


@pytest.mark.parametrize("redirect", [False, True])
def test_installer_midwrite_rollback_respects_parent_boundary(
    tmp_path: Path, monkeypatch, redirect: bool
) -> None:
    target, home = hermes_target(tmp_path / "profile")
    config_before = (home / "config.yaml").read_bytes()
    external = tmp_path / "outside"
    (external / "itsm-inventory").mkdir(parents=True)
    sentinel = external / "itsm-inventory" / "SKILL.md"
    sentinel.write_bytes(b"outside sentinel")
    original = install._atomic_write

    def fail(path, data, *, mode=None):
        if path.name == "queries.md":
            if redirect:
                (home / "skills").rename(home / "saved-skills")
                (home / "skills").symlink_to(external, target_is_directory=True)
            raise OSError("injected disposable midwrite failure")
        return original(path, data, mode=mode)

    monkeypatch.setattr(install, "_atomic_write", fail)
    receipt = asyncio.run(
        install.IntegrationInstaller(catalog=CatalogDouble()).apply(
            target,
            mcp={
                "url": "http://127.0.0.1:1/mcp",
                "secretRef": "M4_MISSING_TOKEN",
                "identityId": "fixture",
            },
            skills=["itsm-inventory"],
        )
    )
    assert receipt["status"] == "failed", receipt
    assert sentinel.read_bytes() == b"outside sentinel"
    if not redirect:
        assert (home / "config.yaml").read_bytes() == config_before
        assert not (home / "skills").exists()
        assert not (home / ".itsm-agent").exists()
