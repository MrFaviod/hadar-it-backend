---
name: {{EXT_ID}}
description: "{{EXT_DESCRIPTION}}"
---

# {{EXT_ID}}

Use this skill when the operator asks about the module's own records.

## What it does

- `list_records`: lists records owned by this module. Optional `limit` (1-100),
  `status` (`open` or `closed`) and `asset_id` to filter linked records. Requires
  the module read permission.
- `create_record`: creates a record from a `title`, optional `status` (`open`
  by default), `notes` and `asset_id` to link it to an existing asset. Requires
  the module write permission. Linking stores only module data; it does not
  change the core asset.

## Trusted-native boundary

The backend is approved Python that runs inside the host process after a human
Superadmin installs it. It is not sandboxed at runtime. It may use only the
explicit SDK stores, notifications and canonical services exposed by its
context; it never receives the core identity database, another module's data or
an arbitrary shell/HTTP/SQL interface.

## Storage

Records live in the module-scoped `records` collection. Schema revision 2 adds
the default `open` status through the declared `normalize_status` migration;
revision 1 remains compatible for explicit rollback.
