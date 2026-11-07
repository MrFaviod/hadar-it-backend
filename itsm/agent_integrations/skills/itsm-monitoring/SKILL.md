---
name: itsm-monitoring
description: "Trigger: availability, metrics, outage, alert or silence preparation. Investigate ITSM monitoring evidence through authorized tools."
license: UNLICENSED
metadata:
  author: "ITSM project"
  version: "1.0.0"
tools:
  - search_assets
  - get_asset_availability
  - get_asset_metrics
  - investigate_outage
  - list_active_alerts
  - acknowledge_alert
  - link_alert_incident
  - prepare_monitoring_maintenance
permissions:
  - assets.view
  - assets.edit
capabilities:
  - monitoring.read
  - monitoring.write
---
# ITSM monitoring

## Activation Contract
Load when the user asks whether an asset was available, which measurements it reported, why an outage happened, which alerts are firing, or whether an alert belongs to an incident.

## Hard Rules
- Report only measurements returned by the tools; never estimate uptime, latency or thresholds.
- Periods are bounded strings such as `24h` or `7d`; do not request unbounded history.
- `acknowledge_alert` records the operator's acknowledgement; it does not resolve the alert or close an incident.
- `prepare_monitoring_maintenance` only suggests a maintenance window; it never saves a silence or window.
- Threshold, exporter and notification configuration stay in monitoring configuration screens, not these tools.

## Decision Gates
| Need | Call |
| --- | --- |
| Find the monitored asset | `search_assets` |
| Availability and missing periods | `get_asset_availability` |
| Historical metrics | `get_asset_metrics` |
| Root-cause evidence | `investigate_outage` |
| Current alerts | `list_active_alerts` |
| Acknowledge under operator authority | `acknowledge_alert` |
| Associate an alert with an incident | `link_alert_incident` |

## Execution Steps
1. Resolve the asset id or read the alert list.
2. Request the narrowest useful period and state its provenance.
3. Follow the evidence path: availability, metrics, then outage investigation.
4. Acknowledge or link only with explicit operator intent.
5. Report the tool, period, observed values and any missing data.

## Output Contract
Return asset id, period, observed availability or measurements, missing intervals and alert ids. Label evidence as measured or reported by the monitoring source. Relay `permission denied` verbatim.

## Example
`list_active_alerts` returns a critical alert for `SRV-01`; `get_asset_availability` with its `asset_id` and `period: "24h"` shows a gap; `investigate_outage` with the same `asset_id` returns the supporting evidence. Report the gap, the evidence and the alert, then offer `link_alert_incident` if the user confirms an incident.

## References
- [Monitoring evidence and alert lifecycle](references/incident-evidence.md)
