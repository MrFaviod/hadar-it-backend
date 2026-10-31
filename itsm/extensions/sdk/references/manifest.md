# Manifest reference (SDK v2)

`extension.json` is validated against `schema/extension.schema.json`
(JSON Schema Draft 2020-12, `additionalProperties: false`). Unknown fields are
rejected. Package limits applied by both the host and the fixed validator:
4 MiB compressed, 8 MiB expanded, 200 entries, 1 MiB per file.

## Top-level fields

| Field | Rule |
| --- | --- |
| `sdkVersion` | Exactly `2`. SDK v1 packages are rejected with an actionable upgrade message. |
| `id` | 2–48 lowercase words joined by single hyphens; `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`. |
| `name` | Non-empty display name, at most 120 characters. |
| `description` | Non-empty text, at most 1024 characters. |
| `version` | Strict semantic `X.Y.Z`. |
| `runtime` | `"sandboxed"` or `"declarative"`. |
| `storage` | Optional `{"engine": "sqlite"}`; SQLite is the only engine. |
| `capabilities` | Host capability allowlist: `assets.read`, `assets.write`, `incidents.read`, `incidents.write`, `notify`. |
| `permissions` | Declared extension permissions: `code`, `label`, `description`. |
| `corePermissions` | Requested existing core permission codes, for example `assets.view`; `ext_*` codes are rejected. |
| `operations` | Declared operations; `kind` is `handler` (default), `list`, `get`, `put` or `delete`. |
| `collections` | Module collections: `name`, `description`, optional `schema`, optional `references`. |
| `schemaVersion` | Positive integer data schema revision. |
| `compatibleSchemaVersions` | Unique positive integers including `schemaVersion`. |
| `migrations` | Ordered `{from,to,handler}`; positive, `from < to`, unique `from`. Sandboxed only. |
| `subscriptions` | `{event,handler}` pairs; sandboxed only. Events: `asset.created`, `asset.updated`, `asset.archived`, `asset.restored`, `asset.deleted`, `incident.created`, `incident.updated`. |
| `reconcile` | `{handler, intervalSeconds}` with `intervalSeconds >= 300`; sandboxed only. |
| `frontend` | `pages`, `assetPanels`, optional `widgets`, `actions`, `contributions` and `entry`. |
| `schedules` | `{name,handler,intervalSeconds,permission}`; interval 60–2592000 seconds; sandboxed only. |
| `skills` | `{name,description,path}` where `path` is exactly `skills/<name>/SKILL.md`. |

## Runtimes

- `sandboxed` requires a non-empty `backend.py`. Every invocation runs in a
  fresh restricted runner process (see [security](security.md)); the host never
  imports module code. Handlers must be bound with `register(sdk)`.
- `declarative` ships **no** `backend.py`, no migrations, no schedules, no
  subscriptions and no reconcile handler. Its `list`/`get`/`put`/`delete`
  operations are executed by the host directly against the module SQLite file.

A sandboxed package may not declare `kind: "list"|"get"|"put"|"delete"`, and a
declarative package may not declare `kind: "handler"` or a `collection` on a
handler operation.

## Permission naming

Every declared operation, schedule, subscription-driven mutation and notice
permission must be `ext_<id_with_underscores>.<suffix>`. A package with id
`record-registry` owns `ext_record_registry.*`. The prefix cannot shadow a core
permission. `corePermissions` must name known core codes; the host recomputes
the delta and never trusts a client-supplied list.

## Capabilities

Capabilities are an explicit allowlist, not documentation. A module that calls
`context.assets`, `context.incidents` or `context.notify` must declare the
matching capability or the host refuses the call before it reaches a canonical
service. Capability calls always run with the invoking principal, so Casbin
authorization applies exactly as it does for REST, chat and MCP.

Mutating capabilities (`assets.write`, `incidents.write`, `notify`) are allowed
only from operations declared `"mutation": true`, from schedules, or from
subscription/reconcile handlers, and they require an `idempotencyKey`. Replaying
the same key with the same request returns the stored response; the same key
with a different request raises an idempotency conflict.

## Collections and schema subset

```json
"collections": [{
  "name": "records",
  "description": "Module records.",
  "schema": {
    "type": "object",
    "properties": {
      "title": {"type": "string", "maxLength": 200},
      "status": {"type": "string", "enum": ["open", "closed"]},
      "dueAt": {"type": "string", "format": "date"}
    },
    "required": ["title"],
    "additionalProperties": false
  },
  "references": [
    {"field": "assetId", "entity": "asset", "onArchive": "keep", "onDelete": "flag"}
  ]
})]
```

The schema subset is deliberately small: an object with `properties` whose
fields are `string`, `number`, `integer`, `boolean` or `null`, plus `enum`,
`format` (`date`, `date-time`, `uuid`), `maxLength`, `minimum`, `maximum`,
`required` and `additionalProperties`. Unsupported keywords (`minItems`,
`pattern`, nested objects, arrays) are rejected so the host can validate
records identically for declarative and sandboxed modules.

`references` relate records to permanent core ids without foreign keys: the
field stores the id, `entity` is `asset` or `incident`, `onArchive` is `keep` or
`flag`, `onDelete` is `flag` or `delete`. Core rows are never touched.

## Operations

`parameters` is a bounded JSON Schema object with `type: "object"`,
`properties`, optional `required`, and optional `additionalProperties`. Each
property declares `type` as one of `array`, `boolean`, `integer`, `number`,
`object`, `string`. Property annotations `default` and `examples` are not
supported. Handler defaults provide optional argument behavior; package tests
supply explicit domain fixtures.

Declarative operations accept only their fixed arguments:

| Kind | Arguments |
| --- | --- |
| `list` | `limit` 1–200, `offset`, `filters` (equality on declared schema fields) |
| `get` | `record_id` (required) |
| `put` | `data` (required), optional `record_id`, optional `expected_version` |
| `delete` | `record_id` (required), optional `expected_version` |

`put` generates a UUID when `record_id` is absent and validates `data` against
the collection schema. `expected_version` implements the same compare-and-swap
as the store contract.

## Migration plan

For a package at schema revision 2 with compatible revisions `[1, 2]`, the valid
migration is `{from: 1, to: 2, handler: "normalize_status"}`. The first
migration must start at the lowest compatible revision; the final migration must
end at `schemaVersion`. A package with no migrations must declare
`compatibleSchemaVersions: [schemaVersion]`.
