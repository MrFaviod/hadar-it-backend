---
name: itsm-infrastructure
description: "Trigger: topology, parent host, relationships or redundancy. Inspect and change ITSM infrastructure structure with authorized tools."
license: UNLICENSED
metadata:
  author: "ITSM project"
  version: "1.0.0"
tools:
  - search_assets
  - get_asset
  - search_locations
  - search_people
  - get_asset_relations
  - create_relationship
  - remove_relationship
  - move_host
  - get_asset_map
  - query_relationships
  - list_redundancy_groups
  - get_redundancy_group
  - save_redundancy_group
permissions:
  - assets.view
  - assets.edit
capabilities:
  - inventory.read
  - directory.read
  - relationships.read
  - relationships.write
  - redundancy.read
  - redundancy.write
---
# ITSM infrastructure

## Activation Contract
Load when the user asks how assets are connected, what a host contains, where an asset sits in the organizational map, or how a redundancy group is composed and activated.

## Hard Rules
- Read the current graph before proposing a change; never reconstruct topology from memory.
- Use permanent ids returned by `search_assets`; names are not identifiers.
- Relationship changes require a concrete `reason`; preserve any `effective_at` the user states.
- `move_host` changes the parent relationship only; it does not reassign responsibility or ownership.
- Relationship type configuration and monitoring thresholds belong to configuration screens, not these tools.

## Decision Gates
| Need | Call |
| --- | --- |
| Assets matching a term | `search_assets` |
| Direct neighbors of one asset | `get_asset_relations` |
| Traversal from a focus | `query_relationships` |
| Site map and plan positions | `get_asset_map` |
| New dependency or link | `create_relationship` |
| Remove a link | `remove_relationship` |
| New parent host | `move_host` |
| Redundancy overview | `list_redundancy_groups`, `get_redundancy_group` |

## Execution Steps
1. Resolve every asset id and the current relationship state.
2. Confirm the direction, type and effective date with the user.
3. Apply one relationship mutation per call, with its reason.
4. Re-read `get_asset_relations` or the affected redundancy group.
5. Report ids, direction, type and effective date.

## Output Contract
Return the affected asset ids, relationship direction and type, and the resulting state. Relay `permission denied` verbatim; never retry through another tool.

## Example
`search_assets` finds server `SRV-01`; `get_asset_relations` shows its current host. `move_host` with `child_id`, `new_host_id` and a reason moves it; then re-read the relations and report the new parent.

## References
- [Topology and redundancy semantics](references/topology-and-redundancy.md)
