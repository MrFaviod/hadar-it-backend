# Explicit data migrations

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

- Migrations run only as part of an explicit approved install or upgrade
  lifecycle. Nothing runs them at application startup.
- They execute in manifest order inside the host transaction.
- If a migration fails, the host rolls back and keeps the previous active
  version and its data. The candidate does not become partially installed.
- The first migration starts at the lowest compatible revision and the final
  migration ends at `schemaVersion`.
- Rollback is allowed only when the target version's
  `compatibleSchemaVersions` includes the current data revision. There is no
  silent downgrade, data deletion or reverse migration.
- A rollback proves additive data preservation: records created by the newer
  version remain readable or are explicitly compatible with the older shape.

## Validation

The fixed validator binds every migration handler, calls it once with the
fixture context, and requires a JSON-serializable result. The generated
package also ships `tests/test_backend.py`, which seeds a legacy record and
asserts the real normalization migration. A passing import or compilation is
not proof that business migration behavior works.
