# Explicit data migrations (snapshots and restore)

Migrations are declared in the manifest and bound by `register(sdk)`:

```json
"schemaVersion": 2,
"compatibleSchemaVersions": [1, 2],
"migrations": [
  { "from": 1, "to": 2, "handler": "normalize_status" }
]
```

```python
def normalize_status(context):
    offset = 0
    migrated = 0
    while True:
        page = context.store.list("records", limit=200, offset=offset)
        for row in page["items"]:
            data = row["data"]
            if not data.get("status"):
                updated = dict(data)
                updated["status"] = "open"
                context.store.put(
                    "records", row["id"], updated, expected_version=row["version"]
                )
                migrated += 1
        offset += len(page["items"])
        if offset >= page["total"]:
            break
    return {"migrated": migrated}
```

## Rules

- Migrations run only as part of an explicit approved install or upgrade.
  Nothing runs them at application startup.
- Each step executes in the sandboxed runner (`kind: "migration"`) inside the
  module's own SQLite transaction.
- Before the first step of an upgrade, the host copies the live database with
  the SQLite backup API to
  `<data-path>/<id>/snapshots/<current-revision>.sqlite3` (`0600`).
- If a step fails, the host restores that snapshot, keeps the previous active
  version and its data, and records the failure. A candidate never becomes
  partially installed.
- After the last step, `PRAGMA user_version` and
  `extension_modules.data_schema_version` advance to the target revision.
- The first migration starts at the lowest compatible revision and the final
  migration ends at `schemaVersion`.
- Rollback is allowed only when the target version's
  `compatibleSchemaVersions` includes the current data revision. Otherwise the
  request must ask for an explicit data restore:

```json
{"version": "1.0.0", "digest": "<sha256>", "expectedVersion": 7,
 "restoreData": true, "confirm": "<extension-id>"}
```

  Without `restoreData` the host rejects the rollback as incompatible. With
  `restoreData` but a missing or wrong `confirm`, it rejects the request as a
  validation error. With both, it restores the snapshot recorded for the target
  schema and sets the mirrored data revision back. There is no silent downgrade
  and no reverse migration.

## Legacy SDK v1 data

Installed SDK v1 modules are never executed again: discovery reports
`status: "requires_upgrade"` and invocation returns
`409 extension_requires_upgrade`. Their business rows still sit in the legacy
core table `extension_collection_records`. Copy them into the module file with:

```bash
python -m itsm.extensions relocate-legacy          # dry run, no writes
python -m itsm.extensions relocate-legacy --apply  # idempotent copy
```

The command compares `(collection, record_id)`: missing rows are inserted with
their original version, identical rows are reported `unchanged`, and rows that
already differ are reported `conflicts` and left untouched. It never deletes or
rewrites legacy rows, and re-running it is safe.

## Validation

The fixed validator binds every migration handler, calls it once with the
fixture context, and requires a JSON-serializable result. The generated package
also ships `tests/test_backend.py`, which seeds a legacy record and asserts the
real normalization migration. A passing import or compilation is not proof that
business migration behavior works.
