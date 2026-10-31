# Backend reference (SDK v2, sandboxed runtime)

`backend.py` is executed by a restricted runner process, never by the API or
worker. The host extracts the package into a read-only cache directory and, for
every invocation, starts:

```text
python -E -s -S -B itsm/extensions/runtime/runner.py
```

with an empty environment, `cwd` set to the module data directory, rlimits,
`PR_SET_NO_NEW_PRIVS`, Landlock filesystem rules and a seccomp deny-list applied
**before** the module source is imported. The runner is stdlib-only and speaks
JSON lines over stdin/stdout; module `print` output is redirected to
`/dev/null` so it cannot forge results.

`-I` is intentionally replaced by `-E -s -S -B`: `-I` also implies `-P`, which
removes the runner directory from `sys.path` and makes the sibling `sdk` and
`sandbox` modules unimportable. `-E` still ignores `PYTHON*` environment
variables, `-s` drops the user site directory, `-S` skips `site`, and `-B`
avoids writing bytecode into the read-only package directory.

## Registration

```python
def register(sdk):
    sdk.operation("list_records", list_records)
    sdk.operation("create_record", create_record)
    sdk.migration("normalize_status", normalize_status)
    sdk.schedule("expire_records", expire_records)
    sdk.subscribe("asset.archived", flag_archived_records)
    sdk.reconcile("repair_references", repair_references)
```

Bind every declared name exactly once. Operations, schedules, subscriptions and
reconcile receive `handler(context, **arguments)`; migrations receive
`handler(context)`. Return JSON or `None`.

## Context

- `principal` is a **dict**, not an object: `actor_id`, `kind`, `username`,
  `display_name`, `role_id`, `delegated_by`, `scopes`, `execution_id`,
  `authorization_ref`, `session_id`. Read `context.principal["actor_id"]`.
  Never take an actor, authority or role from operation arguments.
- `store.list(collection, limit=20, offset=0, filters=None)` returns
  `{"items": [{"id": "...", "version": 1, "data": {...}}], "total": 1}`.
  `get(collection, id)` returns that envelope or `None`.
  `put(collection, id, data, expected_version=None)` returns the new envelope.
  `delete(collection, id, expected_version=None)` returns a boolean. See
  [collections](collections.md).
- `db` is a `sqlite3` connection to **this module's own** `data.sqlite3`. It
  cannot open another path: Landlock allows read/write only inside the module
  data directory. Use it for module-owned tables beyond the managed store.
- `assets.get(asset_id)`, `assets.search(...)`, `assets.resolve(...)`,
  `assets.create(values, idempotencyKey=...)`, `assets.update(...)`,
  `assets.archive(...)` call the canonical inventory service with the invoking
  principal. They require the `assets.read` / `assets.write` capability.
- `incidents.get(id)`, `incidents.list(...)`, `incidents.create(values,
  idempotencyKey=...)` call the canonical interventions service and require the
  `incidents.read` / `incidents.write` capability.
- `notify(...)` delivers a native notice through the canonical notification
  path and requires the `notify` capability.
- `authorize(permission)` checks the invoking principal's persisted authority
  through `IdentityService`. It is a live check, not a cached UI hint.
- `operation`, `schedule`, `event` describe the current dispatch; `event` is a
  dict for subscription handlers and `None` otherwise.

## Idempotency

Every mutating capability call requires an `idempotencyKey` of 1–128 characters
that is stable for the business intent, for example
`"asset-create:" + record_id`. The host stores
`(extension_id, key, capability, request_hash, response)` in the core-owned
`extension_core_calls` table: the same key with the same request replays the
stored response, and the same key with a different request raises
`idempotency_conflict` (HTTP 409). Keys are never accepted from operation
arguments.

## Native notices

```python
context.notify(
    recipient_ids=[context.principal["actor_id"]],
    key="record-created", title="Registro creado", body="Tu registro está listo.",
    permission=WRITE_PERMISSION, asset_id=None,
    url="#/extensiones/record-registry/records",
    idempotency_key="notice:record-created",
)
```

The keyword-only method returns `None`. Recipients are a list/tuple of 1–100
actor IDs, each 1–64 characters; duplicates collapse. The key matches
`[A-Za-z0-9._:-]{1,64}`, title has 1–200 characters, body 1–4000. Permission
must be declared by this extension and live-authorized for the sender. Optional
asset IDs resolve through canonical asset reads. The optional URL must start
with `#/extensiones/<this-id>/` and be at most 500 characters.

The host filters recipients to authorized active humans; an empty authorized set
sends nothing. The native queue deduplicates module/key/recipient inside the
host transaction.

## Errors

Never fabricate success for denied authority or unavailable services. Raise a
normal exception: the runner maps it to a closed host error code
(`handler_failed`, `resource_limit`, `store_conflict`, `store_validation`,
`capability_denied`, `idempotency_conflict`, `not_found`). Do not depend on
exception text being returned to clients.

## Static rules

The validator rejects `import itsm`, `sqlalchemy`, `socket`, `subprocess`,
`ctypes`, `multiprocessing`, relative imports, `os.system`/`os.popen`/
`os.exec*`/`os.spawn*`/`os.fork` and `ctypes.CDLL` with a
`contract_gap_required:` message naming the missing public capability. If a
module needs behaviour the SDK does not expose, record a contract gap instead of
bypassing isolation.
