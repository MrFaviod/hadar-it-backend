"""Sandboxed entry point: ``python -E -s -S -B runner.py``.

The host writes one JSON ``run`` frame on stdin, this process applies every
isolation primitive *before* importing the module backend, and then serves the
single requested handler over a JSON-lines capability protocol.  Module code
never gets the protocol descriptors: they are duplicated first and stdin/stdout
are pointed at ``/dev/null`` so a stray ``print`` cannot forge a result.
"""

from __future__ import annotations

import contextlib
import os
import sys
import traceback
from pathlib import Path

import sandbox
import sdk
from protocol import ModuleError


def _fail(channel: sdk._Channel, code: str, message: str) -> int:
    with contextlib.suppress(OSError):
        channel.send({"type": "error", "code": code, "message": message[:400]})
    return 1


def _load_module(package_dir: str, backend: str) -> sdk.ModuleSDK:
    path = Path(package_dir) / backend
    source = path.read_text(encoding="utf-8")
    namespace: dict[str, object] = {"__name__": "itsm_extension_backend", "__file__": str(path)}
    exec(compile(source, str(path), "exec"), namespace)
    register = namespace.get("register")
    if not callable(register):
        raise ModuleError("backend.py does not expose register(sdk)")
    module_sdk = sdk.ModuleSDK()
    register(module_sdk)
    return module_sdk


def _resolve(module_sdk: sdk.ModuleSDK, kind: str, name: str) -> sdk.Handler:
    if kind == "operation":
        handler = module_sdk.operations.get(name)
    elif kind == "migration":
        handler = module_sdk.migrations.get(name)
    elif kind == "schedule":
        handler = module_sdk.schedules.get(name)
    elif kind == "subscription":
        handler = module_sdk.subscriptions.get(name)
    elif kind == "reconcile":
        handler = (
            module_sdk.reconcile_handler[1] if module_sdk.reconcile_handler else None
        )
    else:
        handler = None
    if handler is None:
        raise ModuleError(f"{kind} {name} is not registered")
    return handler


def _check_declared(module_sdk: sdk.ModuleSDK, declared: dict[str, list[str]]) -> None:
    missing = [
        f"operation {name}"
        for name in declared.get("operations", [])
        if name not in module_sdk.operations
    ]
    missing += [
        f"migration {name}"
        for name in declared.get("migrations", [])
        if name not in module_sdk.migrations
    ]
    missing += [
        f"schedule {name}"
        for name in declared.get("schedules", [])
        if name not in module_sdk.schedules
    ]
    missing += [
        f"subscription {name}"
        for name in declared.get("subscriptions", [])
        if name not in module_sdk.subscriptions
    ]
    reconcile = declared.get("reconcile") or []
    if reconcile and (
        not module_sdk.reconcile_handler
        or module_sdk.reconcile_handler[0] != reconcile[0]
    ):
        missing.append(f"reconcile {reconcile[0]}")
    if missing:
        raise ModuleError("unbound handlers: " + ", ".join(missing[:8]))


def main() -> int:
    reader_fd = os.dup(0)
    writer_fd = os.dup(1)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    channel = sdk._Channel(reader_fd, writer_fd)
    try:
        init = channel.receive()
    except OSError, ModuleError:
        return 1
    if init.get("type") != "run":
        return _fail(channel, "protocol_error", "first frame must be a run request")
    try:
        sandbox.enforce(
            read_paths=[str(path) for path in init.get("readOnlyPaths", [])],
            data_dir=str(init.get("dataDir")),
            cpu_seconds=int(init.get("limits", {}).get("cpuSeconds", 20)),
            memory_mb=int(init.get("limits", {}).get("memoryMb", 256)),
            file_size_bytes=int(init.get("limits", {}).get("fileSizeBytes", 16 * 1024 * 1024)),
            open_files=int(init.get("limits", {}).get("openFiles", 64)),
        )
    except sandbox.SandboxUnavailable as exc:
        return _fail(channel, "sandbox_unavailable", str(exc))
    try:
        module_sdk = _load_module(
            str(init.get("packageDir")), str(init.get("backend", "backend.py"))
        )
        _check_declared(module_sdk, init.get("declared", {}))
        request = init.get("request", {})
        kind = str(request.get("kind"))
        name = str(request.get("name"))
        handler = _resolve(module_sdk, kind, name)
        meta = request.get("context", {})
        context = sdk.Context(
            channel,
            principal=meta.get("principal", {}),
            extension_id=str(meta.get("extensionId", "")),
            version=str(meta.get("version", "")),
            operation=meta.get("operation"),
            event=meta.get("event"),
            schedule=meta.get("schedule"),
            data_path=str(init.get("dataPath")),
        )
        arguments = request.get("arguments") or {}
        result = handler(context, **arguments)
        channel.send({"type": "result", "ok": True, "result": result})
        return 0
    except ModuleError as exc:
        return _fail(channel, exc.code, str(exc) or "module refused the request")
    except MemoryError:
        return _fail(channel, "resource_limit", "module exceeded its memory limit")
    except BaseException:
        detail = traceback.format_exc(limit=2)
        sys.stderr.write(detail[-2000:])
        return _fail(channel, "handler_failed", "extension handler failed")


if __name__ == "__main__":
    raise SystemExit(main())
