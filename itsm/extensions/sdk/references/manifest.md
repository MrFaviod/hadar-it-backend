# Manifest reference

`extension.json` is validated against `schema/extension.schema.json`
(JSON Schema Draft 2020-12, `additionalProperties: false`). Unknown fields are
rejected. The exact package limits are applied by both the host and the fixed
validator: 4 MiB compressed, 8 MiB expanded, 200 entries, 1 MiB per file.

## Top-level fields

| Field | Rule |
| --- | --- |
| `sdkVersion` | Exactly `1`. |
| `id` | 2–48 lowercase words joined by single hyphens; `^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`. |
| `name` | Non-empty display name, at most 120 characters. |
| `description` | Non-empty text, at most 1024 characters. |
| `version` | Strict semantic `X.Y.Z`. |
| `permissions` | Declared extension permissions: `code`, `label`, `description`. |
| `corePermissions` | Requested existing core permission codes, for example `assets.view`; `ext_*` codes are rejected. |
| `operations` | Backend operations; each has `name`, `description`, `permission`, `mutation`, `parameters`. |
| `collections` | Durable module collections: `name`, `description`. |
| `schemaVersion` | Positive integer data schema revision. |
| `compatibleSchemaVersions` | Unique positive integers including `schemaVersion`. |
| `migrations` | Ordered `{from,to,handler}`; positive, `from < to`, unique `from`. |
| `frontend` | Exactly `entry: "frontend.js"` plus `pages` and `assetPanels`. |
| `schedules` | `{name,handler,intervalSeconds,permission}`; interval 60–2592000 seconds. |
| `skills` | `{name,description,path}` where `path` is exactly `skills/<name>/SKILL.md`. |

## Permission naming

Every declared operation permission must be
`ext_<id_with_underscores>.<operation_name>`. A package with id
`record-registry` owns `ext_record_registry.*`. The prefix cannot shadow a
core permission. `corePermissions` must name known core codes; the host
recomputes the delta and never trusts a client-supplied list.

## Operations

`parameters` is a bounded JSON Schema object with `type: "object"`,
`properties`, optional `required`, and optional `additionalProperties`. Each
property declares `type` as one of `array`, `boolean`, `integer`, `number`,
`object`, `string`. Property annotations `default` and `examples` are not supported
by this bounded schema. Handler defaults provide optional argument behavior;
package tests supply explicit domain fixtures. The fixed validator checks handler
signatures without inventing operation inputs. A mutation operation is still
dispatched through the same declared permission and host context.

## Migration plan

For a package at schema revision 2 with compatible revisions `[1, 2]`, the
valid migration is `{from: 1, to: 2, handler: "normalize_status"}`. The first
migration must start at the lowest compatible revision; the final migration
must end at `schemaVersion`. A package with no migrations must declare
`compatibleSchemaVersions: [schemaVersion]`.
