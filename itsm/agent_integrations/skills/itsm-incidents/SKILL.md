---
name: itsm-incidents
description: "Trigger: incident, technical history or intervention. Record and resolve ITSM incidents through authorized tools."
license: UNLICENSED
metadata:
  author: "ITSM project"
  version: "1.0.0"
tools:
  - search_assets
  - get_asset
  - create_incident
  - link_incident_assets
  - get_technical_history
  - prepare_incident_resolution
  - confirm_incident_resolution
  - search_incidents
  - record_intervention
permissions:
  - assets.view
  - assets.edit
capabilities:
  - incidents.read
  - incidents.write
---
# ITSM incidents

## Activation Contract
Load when the user reports a failure, asks for an incident or intervention history, needs to associate affected assets, or wants to resolve an incident.

## Hard Rules
- The canonical entity is an **incident**; interventions are the technical work records linked to it. Do not invent parallel case or ticket entities.
- Resolve every asset id before creating or linking; never invent ids or quick codes.
- Priority is an explicit input (`low`, `normal`, `high` or `critical`); never infer it from message tone.
- `link_incident_assets` replaces the incident's complete affected-asset set. Include every existing id plus the new ones; omitting an existing id removes it.
- Resolution is two steps: `prepare_incident_resolution` returns a token, and `confirm_incident_resolution` needs that exact token. Never fabricate or reuse a stale token.
- `record_intervention` records one real intervention with its parts, labor and optional incident id; it does not close the incident.

## Decision Gates
| Need | Call |
| --- | --- |
| Find the affected asset | `search_assets` |
| Existing incidents | `search_incidents` |
| Technical history | `get_technical_history` |
| New incident | `create_incident` |
| Replace affected assets | `link_incident_assets` with the complete set |
| Record technical work | `record_intervention` |
| Resolve | `prepare_incident_resolution`, then `confirm_incident_resolution` |

## Execution Steps
1. Resolve the primary asset and search for an existing incident before creating one.
2. Create the incident with a factual description, an explicit priority and affected asset ids.
3. Replace the affected set with the union of current and new ids, and record interventions as work happens.
4. Prepare the resolution, confirm it with the returned token, then re-read the incident.
5. Report incident id, status, priority, affected ids and resolved time.

## Output Contract
Return the incident id and status, affected asset ids, intervention ids and resolution state. Relay `permission denied` verbatim; never claim closure without a confirmed resolution.

## Example
`search_assets` resolves `SRV-01`. `create_incident` with `primary_asset_id`, a factual `description` and `priority: "high"` returns an incident id. Record the intervention, then `prepare_incident_resolution` and `confirm_incident_resolution` with its token. Report the confirmed status.

## References
- [Incident resolution workflow](references/resolution-workflow.md)
