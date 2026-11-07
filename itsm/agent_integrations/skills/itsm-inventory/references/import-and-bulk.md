# Bulk and import workflows

Use `batch_update_assets` for a small atomic set of existing assets. Use the
import workflow for CSV analysis where some rows may not map to an existing
asset; it is an operation with conflicts and approval, not a direct update.

1. `prepare_inventory_import` accepts CSV **text** and optional options. It
   accepts no filesystem path, URL or attachment id; never claim it read a
   local file.
2. Read `get_inventory_operation` with the returned operation id. The page is
   bounded; inspect conflicts and receipts before proposing anything.
3. Resolve each conflict with `resolve_import_conflict`, using the row index,
   an action and either an explicit `asset_id` or corrected `values`.
   Resolution invalidates any earlier approval, so approval must come after
   the last conflict edit.
4. Human approval happens outside these tools. `apply_inventory_operation`
   executes only an operation that is already approved and revalidates the
   current bearer permissions; without approval it must fail.
5. Re-read the operation after applying. Report only persisted receipts and
   counts; never claim rows were created before the apply response says so.

`preview_bulk_operation(asset_ids, changes, action, reason)` prepares exact
targets for a separate approval; it is not an apply. Permanent purge is not an
MCP tool. An import apply is audited with source `mcp`; preserve the operation
id in the final report so the human can audit it.
