"""Landlock covers file content, not inode metadata: seccomp must refuse it.

A module runs as the service user, so ``chmod``/``utime``/xattr on a path it
cannot read or write would still succeed through plain DAC ownership.  The
runtime therefore denies the whole metadata family, and these probes assert the
kernel refusal, the unchanged mode/mtime and the still-openable core database.
"""

# ruff: noqa: F811 - the `env` fixture is imported and also named in signatures.

from __future__ import annotations

import errno
import sqlite3
import stat
from pathlib import Path

from tests.inventory_support import asset_values  # noqa: F401 - parity with the suite
from tests.test_extension_runtime_support import (  # noqa: F401 - fixtures
    MODULE_ID,
    READ,
    build_package,
    core_fingerprint,
    env,
    parameters,
    probe_manifest,
)

METADATA_BACKEND = r"""
import os


def _result(fn):
    try:
        return {"allowed": True, "value": fn()}
    except BaseException as exc:  # noqa: BLE001 - the probe reports every refusal
        return {
            "allowed": False,
            "errno": getattr(exc, "errno", None),
            "error": type(exc).__name__,
        }


def chmod_path(context, path, mode):
    return _result(lambda: os.chmod(path, mode))


def utime_path(context, path):
    return _result(lambda: os.utime(path, (1, 1)))


def xattr_path(context, path):
    return _result(lambda: os.setxattr(path, "user.itsm-probe", b"1"))


def register(sdk):
    sdk.operation("chmod_path", chmod_path)
    sdk.operation("utime_path", utime_path)
    sdk.operation("xattr_path", xattr_path)
"""


def metadata_manifest() -> dict:
    declaration = probe_manifest()
    declaration["operations"] = [
        {
            "name": "chmod_path",
            "description": "Intenta cambiar el modo de un archivo",
            "permission": READ,
            "mutation": False,
            "kind": "handler",
            "parameters": parameters({"path": "string", "mode": "integer"}, ["path", "mode"]),
        },
        {
            "name": "utime_path",
            "description": "Intenta cambiar las fechas de un archivo",
            "permission": READ,
            "mutation": False,
            "kind": "handler",
            "parameters": parameters({"path": "string"}, ["path"]),
        },
        {
            "name": "xattr_path",
            "description": "Intenta escribir un atributo extendido",
            "permission": READ,
            "mutation": False,
            "kind": "handler",
            "parameters": parameters({"path": "string"}, ["path"]),
        },
    ]
    return declaration


def core_database_path(env) -> Path:
    return Path(env.settings.database_url.split("sqlite:///", 1)[-1])


def install_probe(env) -> None:
    env.install(build_package(metadata_manifest(), backend=METADATA_BACKEND))


def test_metadata_syscalls_cannot_disable_the_core_database(env) -> None:
    fingerprint = core_fingerprint(env.settings)
    install_probe(env)
    core = core_database_path(env)
    mode_before = stat.S_IMODE(core.stat().st_mode)

    chmod_core = env.invoke("chmod_path", {"path": str(core), "mode": 0})
    utime_core = env.invoke("utime_path", {"path": str(core)})
    xattr_core = env.invoke("xattr_path", {"path": str(core)})

    assert chmod_core["allowed"] is False
    assert chmod_core["errno"] == errno.EPERM
    assert utime_core["allowed"] is False
    assert utime_core["errno"] == errno.EPERM
    assert xattr_core["allowed"] is False
    assert xattr_core["errno"] == errno.EPERM
    # The core file is untouched: same mode, and the epoch-1 timestamp the
    # module asked for was never applied (the host's own audit write moves the
    # mtime, so only the requested value is the observable).
    assert stat.S_IMODE(core.stat().st_mode) == mode_before
    assert core.stat().st_mtime > 1_000_000_000
    connection = sqlite3.connect(core)
    try:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        connection.close()
    assert core_fingerprint(env.settings) == fingerprint


def test_metadata_syscalls_cannot_touch_foreign_or_own_paths(env) -> None:
    install_probe(env)
    foreign = env.storage("probe-beta")
    foreign.mkdir(parents=True)
    own_dir = env.storage(MODULE_ID)
    own_file = env.database(MODULE_ID)
    env.invoke("chmod_path", {"path": str(own_file), "mode": 0o600})
    modes = {path: stat.S_IMODE(path.stat().st_mode) for path in (foreign, own_dir, own_file)}

    chmod_foreign = env.invoke("chmod_path", {"path": str(foreign), "mode": 0})
    chmod_own_dir = env.invoke("chmod_path", {"path": str(own_dir), "mode": 0})
    chmod_own_file = env.invoke("chmod_path", {"path": str(own_file), "mode": 0})
    utime_foreign = env.invoke("utime_path", {"path": str(foreign)})

    for result in (chmod_foreign, chmod_own_dir, chmod_own_file, utime_foreign):
        assert result["allowed"] is False, result
        assert result["errno"] == errno.EPERM, result
    # No mode changed: the runner refuses the metadata family everywhere, so the
    # module cannot even relabel its own storage (it never needs to).
    for path, mode in modes.items():
        assert stat.S_IMODE(path.stat().st_mode) == mode


def test_both_architecture_tables_deny_the_metadata_family() -> None:
    """The deny list is static per architecture, so assert both tables.

    Only one architecture is exercisable on a given host; the other table is
    still part of the contract and a missing entry would silently reopen the
    denial path when the runtime is deployed on that kernel.
    """

    from itsm.extensions.runtime import sandbox as primitives

    expected = {
        "x86_64": {
            "chmod",
            "fchmod",
            "fchmodat",
            "fchmodat2",
            "utime",
            "utimes",
            "futimesat",
            "utimensat",
            "setxattr",
            "lsetxattr",
            "fsetxattr",
            "getxattr",
            "lgetxattr",
            "fgetxattr",
            "listxattr",
            "llistxattr",
            "flistxattr",
            "removexattr",
            "lremovexattr",
            "fremovexattr",
            "setxattrat",
            "getxattrat",
            "listxattrat",
            "removexattrat",
            "file_getattr",
            "file_setattr",
        },
        "aarch64": {
            "fchmod",
            "fchmodat",
            "fchmodat2",
            "utimensat",
            "setxattr",
            "lsetxattr",
            "fsetxattr",
            "getxattr",
            "lgetxattr",
            "fgetxattr",
            "listxattr",
            "llistxattr",
            "flistxattr",
            "removexattr",
            "lremovexattr",
            "fremovexattr",
            "setxattrat",
            "getxattrat",
            "listxattrat",
            "removexattrat",
            "file_getattr",
            "file_setattr",
        },
    }
    for arch, names in expected.items():
        denied = set(primitives.DENY_SYSCALLS[arch])
        assert names <= denied, (arch, sorted(names - denied))
