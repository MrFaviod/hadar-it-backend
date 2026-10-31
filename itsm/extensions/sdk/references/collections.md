# Collections and durable data (per-module SQLite)

Every installed module owns exactly one SQLite database:

```text
<ITSM_EXTENSION_DATA_PATH>/<extension-id>/data.sqlite3
<ITSM_EXTENSION_DATA_PATH>/<extension-id>/snapshots/<revision>.sqlite3
```

Directories are `0700` and files `0600`. The database runs in WAL mode with
`synchronous=FULL`. The engine is independent of the core database: the core may
be PostgreSQL, MariaDB, SQL Server or SQLite and nothing changes here. The core
database stores no extension business data — only host metadata and the
idempotency ledger `extension_core_calls`.

## Declare

```json
"collections": [{
  "name": "records",
  "description": "Module records.",
  "schema": {
    "type": "object",
    "properties": {
      "title": {"type": "string", "maxLength": 200},
      "status": {"type": "string", "enum": ["open", "closed"]}
    },
    "required": ["title"]
  }
}]
```

Only declared collections can be used. `store` records live in the managed
`_itsm_records` table (`collection`, `record_id`, `version`, `data`,
`created_at`, `updated_at`).

## Store contract

```python
page = context.store.list("records", limit=20, offset=0, filters={"status": "open"})
# {"items": [{"id": "...", "version": 1, "data": {...}}], "total": 3}

record = context.store.get("records", record_id)  # record or None
created = context.store.put("records", new_id, {"title": "..."}, expected_version=0)
updated = context.store.put("records", record_id, data, expected_version=record["version"])
deleted = context.store.delete("records", record_id, expected_version=record["version"])
```

- `data` must be a JSON object, at most 256 KiB.
- Record ids are 1–64 characters drawn from letters, digits, `.`, `_`, `:`, `-`.
- `expected_version=0` is create-only. A different positive integer is an
  optimistic update; a mismatch raises a conflict.
- Deletion accepts the same optional nonnegative `expected_version`. A missing
  positive version, or any mismatch on an existing record (including `0`),
  raises a conflict.
- `filters` are equality filters over declared schema fields, at most 20 keys;
  the host compiles them to SQL `json_extract(data, '$.' || ?) = ?` with
  validated keys, so filters are never string-concatenated SQL.
- `list` returns `{items, total}`; the page is ordered by `record_id`.
- Data persists across disable, uninstall, upgrades and rollback.

Do not store credentials, tokens or personal secrets. Use the canonical
identity and authorization services for human authority.

## Data version

`PRAGMA user_version` is the module data schema revision, mirrored into
`extension_modules.data_schema_version`. Install prepares the file and sets the
version to the manifest `schemaVersion`. A migration advances it inside the
approved lifecycle action.

## Declarative modules

A `declarative` module has no code. Its `list`/`get`/`put`/`delete` operations
run in the host process against the same SQLite file, validating `data` against
the collection schema first. Invalid data (missing required field, unknown
field, wrong type, bad enum, out-of-range number, bad date/uuid format) is
rejected before any write. `put` generates a UUID when `record_id` is absent and
honours `expected_version` as compare-and-swap.

## Isolation

Sandboxed modules can read and write only their own data directory. Landlock
allows read/execute on the standard library, shared libraries, the runner and
the read-only package cache, and read/write only inside
`<data-path>/<id>/`. Reading another module's file, the core database or the
application source is denied with `EACCES`.
