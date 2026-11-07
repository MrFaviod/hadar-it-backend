# Trust boundary and permissions

This SDK implements **trusted native extensions**. A human Superadmin reviews
the exact package and approves installation. Approved code runs inside the
host process with ordinary Python and browser capabilities. It is not a
hostile-code sandbox, not an allowlist-isolated runtime, and no page or API may
claim otherwise.

## Two different boundaries

| Phase | Boundary |
| --- | --- |
| Development and validation | Candidate bytes run only in the fixed offline validator container. |
| Installed runtime | Human-approved native code runs in the trusted host process. |

The development workspace is actor-owned and path-bounded, but it is not an
OS sandbox. The validator container is fixed and offline but not a promise
that approved code is isolated.

## Permissions

- Declared extension permissions use `ext_<id_with_underscores>.<operation>`.
- Every operation checks its declared permission; the host also checks module
  enabled state and canonical core permissions.
- `corePermissions` are existing core codes. They are requested at install and
  become an explicit installation policy effect; there are no implicit admin,
  user, machine or wildcard grants.
- The namespace cannot shadow a core permission or another module.
- HTTP mutations require the authenticated session, Origin/CSRF validation
  and the trusted principal. Bearer identities are resolved by the host.
- Chat, MCP and HTTP invoke the same operation handler and authorization path.
- Machine actors cannot approve, enable, roll back or install. Sensitive core
  permissions keep their canonical machine rules.

## Package safety

Reject before importing candidate Python:

- absolute paths, `..`, backslashes, NUL/control characters, drive letters;
- symlinks, special files, encrypted ZIP entries and unsupported compression;
- duplicate or case-colliding paths;
- unknown files outside the package contract;
- oversize archive, expanded tree, entry count or single file;
- missing `extension.json`, `backend.py`, `frontend.js`, declared skill paths
  or at least one `tests/*.py`;
- unsupported dependencies, package-manager files and native binaries;
- a manifest that fails the canonical schema or semantic checks;
- any declared operation not bound by `register(sdk)`.

Never trust a client-supplied digest, validation result, permission delta,
migration plan or package path. The host recomputes the digest, binds the
server-owned validation report, and derives the delta from the immutable
manifest.

## Human approval

Only a persisted human Superadmin can approve, enable, disable, upgrade or
roll back. A chat message such as "yes, install it" is not approval. Agent
responses must return a pending review and the exact human UI path.
