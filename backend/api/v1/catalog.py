from fastapi import APIRouter, Depends

from core.api_auth import require_read

router = APIRouter(prefix="/metrics", tags=["Metric schema"])

_FIELDS = [
    {"name": "cpu_pct", "type": "number", "unit": "%", "label": "CPU utilization", "sources": ["netdata"]},
    {"name": "ram_used_mb", "type": "number", "unit": "MiB", "label": "Memory used", "sources": ["netdata"]},
    {"name": "ram_total_mb", "type": "number", "unit": "MiB", "label": "Total memory", "sources": ["netdata"]},
    {"name": "load_avg", "type": "number", "unit": "load average", "label": "System load", "sources": ["netdata"]},
    {"name": "swap_used_mb", "type": "number", "unit": "MiB", "label": "Swap used", "sources": ["netdata"]},
    {
        "name": "top_processes",
        "type": "array<object>",
        "unit": None,
        "label": "Top processes",
        "sources": ["netdata"],
        "items": {
            "name": {"type": "string", "unit": None},
            "cpu_pct": {"type": "number", "unit": "%"},
            "mem_mb": {"type": "number", "unit": "MiB"},
        },
    },
]

_CATEGORIES = (
    "system", "storage", "network", "services", "processes",
    "connections", "containers", "vms",
)
_NETDATA_CATEGORIES = {"system", "network", "processes", "containers"}


@router.get("/schema", dependencies=[Depends(require_read)])
async def get_metric_schema():
    return {
        "schema_version": 1,
        "snapshot_envelope": {
            "schema_version": {"type": "integer", "required": True},
            "node_id": {"type": "integer", "required": True},
            "category": {"type": "string", "required": True},
            "source": {"type": "string", "required": True},
            "collected_at": {"type": "date-time", "required": True, "timezone": "UTC"},
            "collection_status": {"type": "string", "required": True, "values": ["available"]},
            "data": {"type": "object", "required": True},
            "metrics": {"type": "object", "required": False, "description": "Available typed values from the snapshot columns."},
        },
        "categories": [
            {
                "name": category,
                "sources": {
                    "netdata": "supported" if category in _NETDATA_CATEGORIES else "unsupported",
                    "palantir-agent": "optional; availability depends on host integrations and permissions",
                },
                "typed_fields": _FIELDS,
                "data_contract": "Source-specific JSON object; fields outside typed_fields remain collector-defined.",
            }
            for category in _CATEGORIES
        ],
        "typed_fields": _FIELDS,
    }
