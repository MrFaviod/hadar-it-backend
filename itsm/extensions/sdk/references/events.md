# Events and reconcile reference (SDK v2)

A module keeps its references consistent with core assets and incidents through
events, declarative policies and reconcile. It never reads the core database or
imports ITSM code.

## Subscriptions

Declare handlers in `extension.json`:

```json
"subscriptions": [
  {"event": "asset.archived", "handler": "flag_assignments"},
  {"event": "asset.deleted", "handler": "orphan_assignments"}
]
```

Accepted events are `asset.created`, `asset.updated`, `asset.archived`,
`asset.restored`, `asset.deleted`, `incident.created` and `incident.updated`.
Bind them once in `register(sdk)`:

```python
def register(sdk):
    sdk.subscribe("asset.archived", flag_assignments)
    sdk.subscribe("asset.deleted", orphan_assignments)
    sdk.reconcile("repair_references", repair_references)
```

Each handler receives `context.event`:

```json
{
  "id": "<event uuid>",
  "sequence": 42,
  "type": "asset.archived",
  "entityType": "asset",
  "entityId": "<permanent asset id>",
  "occurredAt": "2026-10-30T12:00:00+00:00",
  "changed": ["status"]
}
```

`changed` contains field names only. Delivery is ordered per consumer and
at-least-once, so keep handlers idempotent and deduplicate with `event["id"]`.
A failing handler is retried with backoff and eventually stalls visibly; the
host never silently drops the cursor. A Superadmin can reset the consumer.

## Declarative references

Instead of code, a collection field can declare a policy:

```json
{
  "name": "assignments",
  "schema": {"type": "object", "required": ["licenseId", "assetId"], "properties": {"licenseId": {"type": "string"}, "assetId": {"type": "string", "format": "uuid"}}},
  "references": [
    {"field": "assetId", "entity": "asset", "onArchive": "flag", "onDelete": "flag"}
  ]
}
```

`onArchive: "flag"` adds `_references: {"assetId": "archived"}` to the record;
`onDelete: "flag"` uses `"missing"`, while `onDelete: "delete"` removes the
record. The host applies the policy idempotently to the module SQLite file.

## Reconcile

```json
"reconcile": {"handler": "repair_references", "intervalSeconds": 300}
```

The handler runs periodically (minimum 300 seconds) and on explicit request. It
receives no event. Re-check every stored reference and repair it:

```python
def repair_references(context):
    rows = context.store.list("assignments", limit=200, offset=0, filters={})
    ids = sorted({row["data"]["assetId"] for row in rows["items"]})
    states = context.assets.resolve("asset", ids[:200])["states"] if ids else {}
    for row in rows["items"]:
        state = states.get(row["data"]["assetId"], "missing")
        data = dict(row["data"], referenceState=state, orphaned=state == "missing")
        if data != row["data"]:
            context.store.put("assignments", row["id"], data, row["version"])
    return {"checked": len(rows["items"])}
```

`assets.resolve` accepts at most 200 permanent ids and returns
`{"<id>": "active" | "archived" | "missing"}`. Reconcile must be safe to run any
number of times.

## Partial failures

Write the core effect first with a stable `idempotencyKey`, then the local
record:

```python
asset = context.assets.create(values, idempotencyKey=f"license:{record_id}")
context.store.put("licenses", record_id, {"assetId": asset["id"], ...})
```

If the process dies between both writes, retrying with the same key replays the
stored core response instead of creating a duplicate, and reconcile repairs a
local record that never landed. Reusing a key with different content is refused
with `409 idempotency_conflict`. Never write local state first and hope the core
call succeeds.

## Missing contracts

If the contract you need does not exist, do not import core modules, open the
core database, or reflect over another file's schema. Call the development tool
`extension_contract_gap` with `capability`, `reason` and `example`; a Superadmin
reviews the recorded gap. Static validation also reports `contract_gap_required`
for such attempts before a package can be installed.
