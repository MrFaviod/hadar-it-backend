# Monitoring evidence and alert lifecycle

Use bounded periods such as `24h`; never request arbitrary PromQL, URLs or
unbounded history. `get_asset_metrics` reads persisted projections for one
asset; `get_asset_availability` reports measured availability and gaps.
`investigate_outage` combines availability, metrics and persisted alerts, but
it returns evidence, not an invented root cause. State explicitly when the
returned window is insufficient.

Alert actions:

- `list_active_alerts` pages only firing alerts; report the page and
  `truncated`/paging fields instead of implying the list is exhaustive.
- `acknowledge_alert(alert_id, notes)` records acknowledgement under current
  authority. It does not resolve the alert or close an incident.
- `link_alert_incident(alert_id, incident_id)` links an existing incident; with
  no incident id the canonical service may create one atomically. Report the
  returned incident id.
- `prepare_monitoring_maintenance(alert_id)` returns a maintenance suggestion
  only. It never saves a maintenance window, creates a silence or changes
  monitoring configuration.

If evidence supports an incident, offer linking; if it supports planned work,
use the maintenance skill. Configuration changes and window creation remain in
their authorized screens and tools, not this skill.
