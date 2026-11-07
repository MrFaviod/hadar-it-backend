# Collections and durable data

Collections are namespaced durable records owned by the ext module. The host
supplies the SQLAlchemy session and transaction; the extension never creates a
database engine, connection or migration table.

## Declare

```json
"collections": [{ "name": "records", "description": "Module records." }]
```

Only declared collections can be used by the active package. Migrations may
also access collections that the version being migrated from declared.

## Store contract

```python
page = context.store.list(
    "records", limit=20, offset=0, filters={"status": "open"}
)
# {"items": [{"id": "...", "version": 1, "data": {...}}], "total": 3}

record = context.store.get("records", record_id)  # record or None
created = context.store.put("records", new_id, {"title": "..."}, expected_version=0)
updated = context.store.put("records", record_id, data, expected_version=record["version"])
deleted = context.store.delete("records", record_id, expected_version=record["version"])
```

- `data` must be a JSON object.
- `expected_version=0` is create-only. A different positive integer is an
  optimistic update; a mismatch raises a conflict.
- Deletion accepts the same optional nonnegative `expected_version`. Missing
  records return `False` with `None`/`0`; a missing positive version or any
  existing-record version mismatch (including `0`) raises a conflict.
- `list` returns the host-enforced page shape; do not assume more than the
  requested limit.
- Data persists across enable/disable, upgrades and compatible rollbacks.
- Collection data belongs to the module namespace. Another extension cannot
  list, read, write or delete it.

Do not store credentials, tokens or personal secrets in a collection. Use the
canonical identity and authorization services for human authority.

## Schema revisions

The active manifest records `schemaVersion`. The host tracks the installed
data revision separately from the semantic package version. A package upgrade
that changes collection shapes must declare an explicit ordered migration;
startup never runs migrations implicitly.
