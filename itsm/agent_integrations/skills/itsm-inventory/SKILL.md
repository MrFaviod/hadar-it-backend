---
name: itsm-inventory
description: "Trigger: asset lookup, creation, update, assignment, import or history. Operate ITSM inventory records through authorized tools."
license: UNLICENSED
metadata:
  author: "ITSM project"
  version: "1.0.0"
tools:
  - search_assets
  - get_asset
  - create_asset
  - update_asset
  - batch_update_assets
  - clone_asset
  - archive_asset
  - restore_asset
  - retire_asset
  - get_asset_history
  - get_inventory_config
  - search_locations
  - prepare_inventory_import
  - preview_bulk_operation
  - get_inventory_operation
  - resolve_import_conflict
  - apply_inventory_operation
  - assign_asset
  - return_asset
  - transfer_asset
permissions:
  - assets.view
  - assets.edit
  - assets.assign
capabilities:
  - inventory.read
  - inventory.write
---
# ITSM inventory

## Activation Contract
Load when the user asks to find, create, update, copy, assign, return, transfer, archive, restore or retire an asset, or to inspect asset history, inventory configuration or an inventory import operation.

## Hard Rules
- Resolve the asset first with `search_assets`; never invent a permanent id, quick code or field value.
- Send only fields the user supplied or explicitly confirmed.
- Permanent purge is human-only and is not an MCP tool; never claim it.
- An import becomes effective only through `apply_inventory_operation` after human approval; never apply an operation the user did not approve.
- Every mutation is audited with source `mcp`; quote the resulting id, status and changed fields.

## Decision Gates
| Need | Call |
| --- | --- |
| Unknown asset | `search_assets` |
| Known id | `get_asset` |
| Uncertain category, site or location | `get_inventory_config`, `search_locations` |
| Several edits atomically | `batch_update_assets` |
| New asset from an existing one | `clone_asset` |
| Responsibility change | `assign_asset`, `return_asset` or `transfer_asset` |
| Spreadsheet import | `prepare_inventory_import`, inspect with `get_inventory_operation`, fix rows with `resolve_import_conflict`, obtain approval outside the tools, then `apply_inventory_operation` |
| Exact bulk edit preview | `preview_bulk_operation` for supplied `asset_ids` and `changes`; it is a separate approval preview, not an import or an apply |

## Execution Steps
1. Search or read the asset and confirm its permanent id.
2. Resolve uncertain catalog values before writing.
3. Apply the smallest mutation; use one batch call when several assets change together.
4. Read the asset again when the mutation response omits the changed fields.
5. Report id, quick code, status and any history entry created.

## Output Contract
Return the asset id and quick code, the operation performed, the resulting status and the changed fields. When a tool reports `permission denied`, relay it verbatim and do not retry with invented authority.

## Example
`search_assets` with `query: "LAP-0142"` returns one asset; call `get_asset` with its `asset_id`; then `assign_asset` with `person_id`. Confirm the new responsible person and status.

## References
- [Bulk and import workflows](references/import-and-bulk.md)
