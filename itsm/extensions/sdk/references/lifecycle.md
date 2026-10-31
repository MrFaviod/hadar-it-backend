# Candidate and installation lifecycle

Extensions move through host-owned states. Workspace files are not installed
code and a workspace has no runtime authority.

| State | Meaning | Who moves it |
| --- | --- | --- |
| workspace | Actor-owned draft files under the development root | Authenticated developer |
| candidate | Immutable package bytes with a SHA-256 digest, pending review | `submit_candidate` |
| validated | A trusted validation report bound to that candidate digest | Host-internal recorder |
| approved | Human Superadmin approved this exact digest and delta | Human Superadmin only |
| installed | Active package bytes, data file and schema revision recorded | Approval/upgrade action |
| disabled | Installed bytes and data retained, operations and UI unavailable | Human Superadmin |
| requires_upgrade | Installed by SDK v1; never executed again until rebuilt for v2 | Legacy detection |
| rolled back | A compatible previous version is active, optionally with restored data | Human Superadmin only |
| uninstalled | Host rows and grants removed; data directory kept | Human Superadmin |

## Rules

- A candidate is immutable. Editing workspace source creates a new candidate
  digest and invalidates the prior validation and approval.
- Validation is bound to package bytes, not to a user-supplied boolean.
- Approval binds the digest, permission additions, migration plan and the
  expected installed revision. A stale revision fails safely.
- The expected revision is the installed monotonic integer revision, or null
  for the first install. It is not the semantic version.
- Approval prepares storage (`<data-path>/<id>/data.sqlite3`) and extracts the
  package into the read-only per-digest cache before any module code runs.
- Agents and models can create, read, write, validate and submit. They cannot
  approve, enable, disable, upgrade, roll back or uninstall.
- Disabling removes operations, tools, skills and native UI immediately while
  preserving module data and installed versions.
- Uninstall is `POST /api/v1/extensions/{id}/uninstall {expectedVersion}`. It
  removes installed versions, candidates, schedule state, migration rows,
  registered extension permissions and the Superadmin role policies for those
  codes, and records an audit event. It **keeps** the data directory and
  returns `{uninstalled: true, dataRetained: true, dataPath: "..."}`. No
  lifecycle action deletes module data.

## Status

`GET /api/v1/extensions/{id}/status` reports the operational state without
touching module code: id, status (`ready`, `disabled`, `requires_upgrade`),
enabled, version, digest, schema version, runtime, revision, storage path, data
size, available snapshots, event cursor, stalled flag and sandbox availability
(`available`, `landlockAbi`, `arch`, `detail`).

## SDK v1 modules

Installed SDK v1 modules stay visible with `status: "requires_upgrade"` and are
never executed: invocation returns `409 extension_requires_upgrade` with a
message pointing at `python -m itsm.extensions relocate-legacy`. Schedules are
not dispatched for them. New v1 candidates are rejected at inspection with an
actionable message naming `sdkVersion: 2` and the relocation command. Their
legacy rows remain in `extension_collection_records` until an operator copies
them into the module file with `relocate-legacy`; the command never deletes
them.

## Rollback

Rollback requires a previously installed version whose
`compatibleSchemaVersions` includes the current schema revision. Otherwise the
request must carry `restoreData: true` and `confirm: "<extension id>"`; the host
then restores `<data-path>/<id>/snapshots/<target-schema>.sqlite3` and moves the
mirrored data revision back. Incompatible rollback without that confirmation is
rejected without changing the active version or data. A rollback never rewrites
migrations backwards.
