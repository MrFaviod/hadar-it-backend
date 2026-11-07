# Topology and redundancy semantics

Read the persisted graph before proposing a change. `get_asset_relations`
accepts a list of `asset_ids`; `query_relationships` traverses from one focus
(or pages the global graph) with `depth`, `direction` and `type_key`. Both
return truncation flags (`truncated`, `nodesTruncated`, `edgesTruncated`,
`depthTruncated` for the traversal view). Never present a truncated result as
the complete topology.

Relationship changes require permanent UUIDs and a reason:

- `create_relationship(source_id, target_id, type_key, reason)` creates one
  typed edge. The type must already exist in configuration; relationship-type
  management is a configuration screen, not an MCP tool.
- `remove_relationship(relationship_id, reason)` removes one edge by id.
- `move_host(child_id, new_host_id, reason)` changes a parent-host placement.
  It is not a generic relationship edit and does not alter unrelated edges.
- `save_redundancy_group` persists a group by id with its name, mode, active
  state and members; list/read first so unchanged members are preserved.

For a move, re-read `get_asset_relations` and the asset map afterwards and
report the new parent. If the user asks for a broader graph mutation, return
to the relationship type or inventory owner instead of inventing an edge.
