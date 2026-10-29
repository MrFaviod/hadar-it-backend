# Backend reference

`backend.py` is native trusted Python. It runs in the host process after human
installation, with ordinary Python capabilities. Human review, not a Python
sandbox, is the installation boundary. Use the standard library only: no pip,
`sdk_runtime`, package-sibling imports or new database engines.

## Registration and handlers

```python
def register(sdk):
    sdk.operation("list_records", list_records)
    sdk.operation("create_record", create_record)
    sdk.migration("normalize_status", normalize_status)
```

The binder exposes `operation(name, callable)`, `migration(name, callable)` and
`schedule(name, callable)`. Bind every declared name exactly once. Operations
and schedules receive `handler(context, **arguments)`; migrations receive
`handler(context)`. Return JSON or `None`. The host bounds results and checks
the declared operation permission before execution; handlers may explicitly
recheck with `context.authorize(permission)`.

## Context

- `principal` is an immutable object, not a dictionary. Its fields are
  `actor_id`, `kind`, `username`, `display_name`, `role_id`, `delegated_by`,
  `scopes`, `execution_id`, `authorization_ref`, `session_id`. Never take an
  actor, authority or role from operation arguments.
- `store.list(collection, limit=20, offset=0, filters=None)` returns
  `{"items": [{"id": "...", "version": 1, "data": {...}}], "total": 1}`.
  `get(collection, id)` returns that record envelope or `None`.
  `put(collection, id, data, expected_version=None)` returns the new envelope.
  `delete(collection, id, expected_version=None)` returns a boolean. See
  [collections](collections.md) for optimistic versions and pagination.
- `assets.get(asset_id)` returns the canonical read-only asset dictionary;
  missing assets raise native `NotFound`, never `None`. It requires
  `assets.view`. `assets.search` is keyword-only with `query`, `category`,
  `site`, `status`, `quick_code`, `asset_id`, `site_id`, `location_id`,
  `responsible_person_id`, `archived`, `limit=50`, `offset=0`, and returns
  `{"items": [...], "total": 0, "limit": 50, "offset": 0}`. Declare
  `assets.view` in `corePermissions` when using these reads.
  A missing, purged or malformed string `asset_id` returns an empty search page
  with the requested limit/offset; non-string ids are invalid. `get` still
  raises `NotFound` for missing assets. These reads use
  global `assets.view`: a missing permission raises `PermissionDenied`, not a
  per-asset omission. Do not catch or suppress authorization failures.
- `transaction()` is a context manager yielding the context. It creates a
  nested savepoint inside the host-owned transaction. Exceptions roll it
  back; store mutation and notice methods enforce read-only operations. No
  database session is exposed and extensions must not commit identity state.

## Native notices

```python
context.notify(
    recipient_ids=[context.principal.actor_id],
    key="record-created", title="Registro creado", body="Tu registro está listo.",
    permission=WRITE_PERMISSION, asset_id=None,
    url="#/extensiones/record-registry/records",
)
```

The keyword-only method returns `None`. Recipients are a list/tuple of 1–100
actor IDs, each 1–64 characters; duplicates collapse. The key matches
`[A-Za-z0-9._:-]{1,64}`, title has 1–200 characters, body 1–4000. Permission
must be declared by this extension and live-authorized for the sender.
Optional asset IDs resolve through canonical asset reads. The optional URL
must start with `#/extensiones/<this-id>/` and be at most 500 characters.

The host filters recipients to authorized active humans; an empty authorized
set sends nothing. The native queue deduplicates module/key/recipient inside
the host transaction. The validator only exercises the call shape with its
fixture actor: it does not prove production recipient policy or delivery.

## Errors

Never fabricate success for denied authority or unavailable services. Normal
handler exceptions become safe host errors; do not depend on exception text
being returned to clients. The host imports the source in memory without
adding the installed package directory to `sys.path`.
