# Candidate and installation lifecycle

Extensions move through host-owned states. Workspace files are not installed
code and a workspace has no runtime authority.

| State | Meaning | Who moves it |
| --- | --- | --- |
| workspace | Actor-owned draft files under the development root | Authenticated developer |
| candidate | Immutable package bytes with a SHA-256 digest, pending review | `submit_candidate` |
| validated | A trusted validation report bound to that candidate digest | Host-internal recorder |
| approved | Human Superadmin approved this exact digest and delta | Human Superadmin only |
| installed | Active package bytes and schema revision recorded by the host | Approval/upgrade action |
| disabled | Installed bytes retained, operations and UI unavailable | Human Superadmin |
| rolled back | A compatible previously installed version is active | Human Superadmin only |

## Rules

- A candidate is immutable. Editing workspace source creates a new candidate
  digest and invalidates the prior validation and approval.
- Validation is bound to package bytes, not to a user-supplied boolean.
- Approval binds the digest, permission additions, migration plan and the
  expected installed revision. A stale revision fails safely.
- The expected revision is the installed monotonic integer revision, or null
  for the first install. It is not the semantic version.
- Agents and models can create, read, write, validate and submit. They cannot
  approve, enable, disable, upgrade or roll back.
- Disabling removes operations, tools, skills and native UI immediately while
  preserving module data and installed versions.
- Uninstall removes installed frontend contributions and stops operations; it
  does not silently delete durable collection data.

## Rollback

Rollback requires a previously installed version whose
`compatibleSchemaVersions` includes the current schema revision. Incompatible
rollback is rejected without changing the active version or data. A rollback
never deletes records and never rewrites migrations backwards.
