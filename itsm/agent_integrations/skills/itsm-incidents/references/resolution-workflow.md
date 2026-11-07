# Incident resolution workflow

The canonical entities are **incidents** and **interventions**:

- An incident has a primary asset, optional affected assets, a factual
  description, an explicit priority (`low`, `normal`, `high`, `critical`) and
  a status such as `open`, `in_progress`, `resolved` or `closed`.
- An intervention is one technical work record. `record_intervention` may link
  an incident but never closes it.

`link_incident_assets(incident_id, affected_asset_ids)` **replaces** the whole
affected set. Read the current incident, preserve every id that should remain,
add the new ids and submit the complete union. Omitting an existing id removes
it.

Resolution is a two-step prepared action:

1. `prepare_incident_resolution(incident_id, note)` returns a suggestion and a
   token. It does not resolve anything.
2. `confirm_incident_resolution(incident_id, token, note)` revalidates current
   authority and state and resolves only with that exact prepared token. Never
   fabricate, reuse after failure or copy a token from another incident.

Use `get_technical_history(asset_id)` for persisted intervention and incident
history, and `search_incidents` for existing cases before creating a new one.
Report ids, status, priority, affected ids and resolution state only after the
service returns them.
