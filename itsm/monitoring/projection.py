"""Safe summarized projections shared with the conversational agent runtime.

These projections are the only shapes agent tools receive: identifiers, states
and bounded numeric summaries. Native labels, annotations and generator URLs
never cross this boundary; the rule-provided summary and description are
included only on the alert summary by explicit contract.
"""

from __future__ import annotations

from typing import Any

MAX_SUMMARY_POINTS = 60


def _sampled(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(points) <= MAX_SUMMARY_POINTS:
        return [dict(point) for point in points]
    keep = MAX_SUMMARY_POINTS - 2
    stride = (len(points) - 2) / keep
    sampled = [dict(points[0])]
    for index in range(keep):
        sampled.append(dict(points[1 + int(index * stride)]))
    sampled.append(dict(points[-1]))
    return sampled


def summarize_device(detail: dict[str, Any], *, include_series: bool = False) -> dict[str, Any]:
    """Reduce a device detail payload to a bounded operational summary."""
    asset = detail.get("asset") or {}
    summary: dict[str, Any] = {
        "assetId": asset.get("assetId"),
        "name": asset.get("name"),
        "status": detail.get("status"),
        "reason": detail.get("reason"),
        "provenance": detail.get("provenance"),
        "uptime": detail.get("uptime"),
        "latency": detail.get("latency"),
        "checks": detail.get("checks") or [],
        "alerts": detail.get("alerts") or {},
    }
    if include_series:
        summary["series"] = [
            {
                "metric": item.get("metric"),
                "unit": item.get("unit"),
                "points": _sampled(item.get("points") or []),
            }
            for item in detail.get("series") or []
        ]
    return summary


def summarize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Reduce an alert payload; labels and annotations stay out of agent context."""
    return {
        "id": alert.get("id"),
        "assetId": alert.get("assetId"),
        "assetName": alert.get("assetName"),
        "alertName": alert.get("alertName"),
        "severity": alert.get("severity"),
        "state": alert.get("state"),
        "acknowledged": alert.get("acknowledged"),
        "silenced": alert.get("silenced"),
        "startsAt": alert.get("startsAt"),
        "endsAt": alert.get("endsAt"),
        "summary": alert.get("summary"),
        "description": alert.get("description"),
        "incident": alert.get("incident"),
    }


__all__ = ["MAX_SUMMARY_POINTS", "summarize_alert", "summarize_device"]
