---
name: itsm-operations
description: "Trigger: operational summary, cross-entity search, relationship graph or saved views. Read ITSM operations through authorized tools."
license: UNLICENSED
metadata:
  author: "ITSM project"
  version: "1.0.0"
tools:
  - get_operational_summary
  - search_everything
  - query_relationships
  - list_saved_views
permissions:
  - assets.view
capabilities:
  - operations.read
---
# ITSM operations

## Activation Contract
Load when the user asks for a daily operational overview, wants one search across ITSM entities, needs relationship traversal from a focus, or wants the caller's saved views, favorites and shortcuts.

## Hard Rules
- These tools are read-only. Do not claim that a summary, search or view changed any record.
- `search_everything` accepts only known result kinds and a bounded page; report `total`, `truncated` and `fallback` exactly as returned.
- `query_relationships` reports its own `truncated`, `nodesTruncated`, `edgesTruncated` and `depthTruncated` flags; never hide a truncated graph.
- Deployment maintenance and privileged host operations are not available here. They stay in the deployment's existing ops procedure and are never simulated through these tools.
- `list_saved_views` returns the caller's workspace state; it does not expose another identity's views.

## Decision Gates
| Need | Call |
| --- | --- |
| Period overview | `get_operational_summary` with a bounded `period` |
| Cross-entity search | `search_everything` with a query and optional `kinds` |
| Topology traversal | `query_relationships` with an asset id or global page |
| Caller's saved state | `list_saved_views` |
| Change a record | A domain skill such as `itsm-inventory`, not these tools |

## Execution Steps
1. Choose the narrowest tool for the question and bound its period or page.
2. Read the payload, including `truncated`, `fallback` and provenance fields.
3. Pages beyond the returned `limit` require another bounded call; do not guess missing rows.
4. Synthesize only the returned facts and cite counts.
5. Offer a domain skill when the user asks for a mutation.

## Output Contract
Return the period or query, counts, truncation flags, provenance and the returned rows or nodes. Relay `permission denied` verbatim; never present an empty result as proof that nothing exists.

## Example
`get_operational_summary` with `period: "24h"` returns asset, alert and incident counts. `search_everything` with `query: "SRV-01"` returns the matching asset and incidents. Report the counts and any truncation flag, then stop: no mutation happened.
