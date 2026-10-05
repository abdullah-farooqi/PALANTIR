from datetime import datetime, timezone

from core.config import settings
from models.category_status import CategoryCollectionStatus

CATEGORY_ORDER = (
    "system", "storage", "network", "services", "processes",
    "connections", "containers", "vms",
)
NETDATA_CATEGORIES = {"system", "network", "processes", "containers"}
CATEGORY_LABELS = {
    "system": "System",
    "storage": "Storage",
    "network": "Network",
    "services": "Services",
    "processes": "Processes",
    "connections": "Connections",
    "containers": "Containers",
    "vms": "Virtual machines",
}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _age_seconds(value: datetime, now: datetime) -> float:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return max(0.0, (now - value).total_seconds())


def summarize_category_statuses(
    has_collector: bool,
    rows: list[CategoryCollectionStatus],
    now: datetime | None = None,
) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    by_key = {(row.category, row.source): row for row in rows}
    summaries = []

    for category in CATEGORY_ORDER:
        source_summaries = []
        for source in ("netdata", "palantir-agent"):
            row = by_key.get((category, source))
            if row is None:
                if source == "netdata":
                    base_status = "unknown" if category in NETDATA_CATEGORIES else "unsupported"
                    message = None if base_status == "unknown" else "The current Netdata collection pipeline does not collect this category."
                else:
                    base_status = "unknown" if has_collector else "not_configured"
                    message = None if has_collector else "No PALANTIR host collector is configured for this node."
                last_attempt = last_success = error_code = None
            else:
                base_status = row.status
                message = row.error_message
                last_attempt = row.last_attempt_at
                last_success = row.last_success_at
                error_code = row.error_code

            if last_success:
                if _age_seconds(last_success, now) > settings.METRIC_STALE_SECONDS:
                    effective_status = "stale"
                elif base_status == "collection_error":
                    effective_status = "collection_error"
                else:
                    effective_status = "available"
            else:
                effective_status = base_status

            source_summaries.append({
                "source": source,
                "status": effective_status,
                "last_attempt_at": _iso(last_attempt),
                "last_success_at": _iso(last_success),
                "error_code": error_code,
                "error_message": message,
            })

        statuses = [item["status"] for item in source_summaries]
        if "available" in statuses:
            status = "available"
        elif "stale" in statuses:
            status = "stale"
        elif "collection_error" in statuses:
            status = "collection_error"
        elif "unknown" in statuses:
            status = "unknown"
        elif "not_configured" in statuses:
            status = "not_configured"
        else:
            status = "unsupported"

        attempts = [item["last_attempt_at"] for item in source_summaries if item["last_attempt_at"]]
        successes = [item["last_success_at"] for item in source_summaries if item["last_success_at"]]
        errors = [
            item for item in source_summaries
            if item["error_code"] and item["status"] in {"collection_error", "unsupported", "not_configured"}
        ]
        latest_error = max(errors, key=lambda item: item["last_attempt_at"] or "", default=None)
        summaries.append({
            "category": category,
            "label": CATEGORY_LABELS[category],
            "status": status,
            "last_attempt_at": max(attempts, default=None),
            "last_success_at": max(successes, default=None),
            "error_code": latest_error["error_code"] if latest_error else None,
            "error_message": latest_error["error_message"] if latest_error else None,
            "sources": source_summaries,
        })
    return summaries
