# Shared agent tools

The host exposes one method dispatcher for chat and MCP. It returns ordinary
JSON and never starts a shell, HTTP client, SQL console or arbitrary
filesystem tool. Every call authorizes `system.modules` with the trusted
transport principal. A denial returns a safe error and leaves workspace files
and validation unchanged.

| Method | Result |
| --- | --- |
| `extension_sdk_index` | SDK version, packaged schema path and bounded reference index. |
| `extension_sdk_reference` | One named reference, bounded to 24 KiB. |
| `extension_workspace_create` | Seed a working SDK v2 example (`runtime` argument selects the sandboxed record-registry or the declarative notes template). |
| `extension_workspace_files` | List the actor's workspaces or one workspace's files. |
| `extension_workspace_read` | Read one supported package file. |
| `extension_workspace_write` | Write one supported package file and invalidate validation. |
| `extension_workspace_validate` | Build actual package bytes and run the fixed validator. |
| `extension_workspace_submit` | Submit verified bytes as a pending candidate. |

## Ownership and paths

Workspaces live under a server-owned root in actor-owned directories. A
workspace id is lowercase and bounded. Supported paths are exactly
`extension.json`, `backend.py`, `frontend.js`, `skills/<workspace-id>/SKILL.md`
and `tests/<name>.py`. `backend.py` is required for a sandboxed module and
rejected for a declarative one; `frontend.js` is only allowed when the manifest
declares `frontend.entry` for an isolated view. Absolute paths, `..`, nested
extra directories, symlinks, hard-linked escapes, unsupported names, oversized
files and oversized workspaces are rejected.

## Tool flow

1. Create or list a workspace.
2. Read `schema/extension.schema.json` and the reference that matches the task.
3. Edit files.
4. Validate, then inspect the seven-field report.
5. Submit. The result is pending review with a digest, not installed code. The
   stored report must be a passing SDK v2 report bound to the exact bytes.

The tool cannot approve, enable, disable, upgrade, roll back or invoke a
candidate before approval. It also cannot claim a passing validation merely
because generation compiled.

## MCP and chat parity

Both surfaces call the same dispatcher and handler. The MCP transport resolves
the trusted bearer principal; chat uses its authenticated principal. Neither
accepts an actor id, role, approval flag or validator result from arguments.
