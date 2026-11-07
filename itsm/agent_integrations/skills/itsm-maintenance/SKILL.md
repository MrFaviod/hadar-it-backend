---
name: itsm-maintenance
description: "Trigger: preventive maintenance plan, due work or completion. Read and complete ITSM maintenance through authorized tools."
license: UNLICENSED
metadata:
  author: "ITSM project"
  version: "1.0.0"
tools:
  - search_assets
  - get_asset
  - search_maintenance
  - complete_maintenance
permissions:
  - assets.view
  - assets.edit
capabilities:
  - maintenance.read
  - maintenance.write
---
# ITSM maintenance

## Activation Contract
Load when the user asks which preventive plans are due, what work is upcoming or overdue for an asset or site, or wants to complete a preventive task.

## Hard Rules
- `search_maintenance` is the only supported way to find plans; never invent plan ids or due dates.
- Plan creation, scheduling and template changes are not exposed as MCP tools. Direct those changes to the ITSM maintenance screens and do not claim they were applied.
- `complete_maintenance` requires the real completion date and records one completion; the service calculates the next due date.
- Completion notes must state the work actually performed, never a prediction.
- A plan tied to several assets is read per plan; do not assume one completion covers unlisted assets.

## Decision Gates
| Need | Call |
| --- | --- |
| Find the asset | `search_assets`, `get_asset` |
| Due or upcoming plans | `search_maintenance` with `status`, `due_from`, `due_to` or `upcoming_days` |
| Plans for one asset | `search_maintenance` with `asset_id` |
| Complete one task | `complete_maintenance` |
| Create or reschedule a plan | ITSM maintenance screen, not a tool |

## Execution Steps
1. Resolve the asset or accept the plan id the user supplied.
2. Search the bounded window and report plan id, due date, status and asset.
3. Confirm the completion date and performed work with the user.
4. Call `complete_maintenance` once and read the returned plan.
5. Report completion time and the next calculated due date.

## Output Contract
Return plan id, asset id, previous due date, completion date and next due date. Relay `permission denied` verbatim. Never say a plan was created or rescheduled through these tools.

## Example
`search_maintenance` with `asset_id` and `upcoming_days: 7` returns a due plan. Confirm the work, call `complete_maintenance` with `plan_id`, `completed_on` and factual notes, then report the next due date.
