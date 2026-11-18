import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import get_session
from core.api_auth import require_read
from models.alert import AlertEvent
from models.investigation import AgentInvestigation
from models.metric import MetricSnapshot
from models.node import MonitoredNode

router = APIRouter(prefix="/copilot", tags=["Copilot Preview"])


class CopilotQueryRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=1000)
    host: Optional[str] = Field(default=None, max_length=128)


PRESET_PROMPTS = [
    {
        "id": "summarize_alerts",
        "label": "1. Summarize active alerts",
        "hotkey": "Alt+1",
        "prompt": "Summarize active alerts across the fleet and rank by urgency.",
    },
    {
        "id": "why_cpu_high",
        "label": "2. Why is db-02 CPU high?",
        "hotkey": "Alt+2",
        "prompt": "Why is db-02 CPU high? Check the last 15 minutes of eBPF process telemetry and recent kernel conntrack events.",
    },
    {
        "id": "inspect_socket_drops",
        "label": "3. Inspect eBPF network socket drops on web-01",
        "hotkey": "Alt+3",
        "prompt": "Inspect eBPF network socket drops on web-01 and isolate the top sending endpoints.",
    },
    {
        "id": "correlate_oomkills",
        "label": "4. Correlate OOMKills with last 1h deploy logs",
        "hotkey": "Alt+4",
        "prompt": "Correlate OOMKills with last 1h deploy logs and verify cgroup memory pressure.",
    },
]


@router.get("/presets")
async def get_copilot_presets(_role: None = Depends(require_read)) -> Dict[str, Any]:
    return {
        "presets": PRESET_PROMPTS,
        "model": "palantir-telemetry-eval-v1 (Offline Mock Mode) · Sandbox Isolation",
        "state": "SYNTHETIC EVALUATION",
        "version": "v0.4-PREVIEW",
    }


@router.post("/query")
async def execute_copilot_query(
    req: CopilotQueryRequest,
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
) -> Dict[str, Any]:
    prompt = req.prompt.strip()
    now = datetime.now(timezone.utc)

    # Fetch live nodes to ground responses in actual fleet state
    nodes_res = await session.execute(select(MonitoredNode).where(MonitoredNode.active.is_(True)).limit(10))
    nodes = nodes_res.scalars().all()
    node_names = [n.hostname for n in nodes]
    target_node = req.host or (node_names[0] if node_names else "web-01")

    # Fetch recent active alerts
    alerts_res = await session.execute(
        select(AlertEvent)
        .where(AlertEvent.status.in_(("WARNING", "CRITICAL")))
        .order_by(AlertEvent.received_at.desc())
        .limit(10)
    )
    active_alerts = alerts_res.scalars().all()

    # Route logic based on prompt content
    lower_prompt = prompt.lower()

    if "summarize active alert" in lower_prompt or "summarize alerts" in lower_prompt or "1." in prompt:
        crit_count = sum(1 for a in active_alerts if a.status == "CRITICAL")
        warn_count = sum(1 for a in active_alerts if a.status == "WARNING")
        alert_details = [f"{a.alert_name} on host node #{a.node_id} ({a.status})" for a in active_alerts[:4]]
        detail_str = "; ".join(alert_details) if alert_details else "No unresolved critical threshold breaches detected"

        narrative = (
            f"Active fleet triage identified {len(active_alerts)} unacknowledged alerts ({crit_count} Critical, {warn_count} Warning). "
            f"Key impacted resources include: {detail_str}. "
            "Telemetry indicates memory and CPU contention within containerized namespaces. Automatic PCAP capture buffers are 100% indexed."
        )
        process_profile = [
            {"name": "postgres: autovacuum worker", "pid": 44102, "cpu_pct": 71.2, "rss": "14.2 GB", "socket_backlog": "None", "bar_pct": 71.2},
            {"name": "vector-aggregator[912]", "pid": 912, "cpu_pct": 18.4, "rss": "840 MB", "socket_backlog": "2,410 pkts", "bar_pct": 18.4},
        ]
        obs = "No OS kernel panic detected. Memory pressure remains below critical threshold across fleet nodes."
        obs_badge = "SYS_OK" if crit_count == 0 else "SYS_WARN"
        sources = [
            "eBPF process_exec ring buffer (fleet aggregate)",
            "Prometheus node_cpu_seconds_total",
            "journald /var/log/syslog alert triggers",
            "Active investigation forensic archive",
        ]

    elif "why is" in lower_prompt and "cpu high" in lower_prompt or "cpu" in lower_prompt or "2." in prompt:
        matched_node = "db-02" if "db-02" in lower_prompt else target_node
        narrative = (
            f"Based on real-time snapshot telemetry for {matched_node} (10.0.4.52), CPU utilization peaked at 96.4% "
            "across 8 cores. The primary driver is an unbounded PostgreSQL vacuuming thread (pid 44102: autovacuum worker) "
            "competing with synchronous replication socket writes to db-replica-02. Conntrack table fill reached 89%, inducing "
            "selective ephemeral socket buffer thrashing."
        )
        process_profile = [
            {"name": "postgres: autovacuum worker", "pid": 44102, "cpu_pct": 71.2, "rss": "14.2 GB", "socket_backlog": "0 pkts", "bar_pct": 71.2},
            {"name": "vector-aggregator[912]", "pid": 912, "cpu_pct": 18.4, "rss": "840 MB", "socket_backlog": "2,410 pkts", "bar_pct": 18.4},
        ]
        obs = "No OS kernel panic detected. Memory pressure remains below critical threshold (74% RSS)."
        obs_badge = "SYS_OK"
        sources = [
            f"eBPF process_exec ring buffer ({matched_node})",
            "Prometheus node_cpu_seconds_total",
            "journald /var/log/postgresql.log (offset 0x88F)",
            "Inv #8f3a-9971a forensic archive",
        ]

    elif "socket drop" in lower_prompt or "network" in lower_prompt or "3." in prompt:
        matched_node = "web-01" if "web-01" in lower_prompt else target_node
        narrative = (
            f"In-kernel eBPF trace on {matched_node} shows 4,812 dropped TCP packets over interface eth0 in the last 15 minutes. "
            "Drops are concentrated on ephemeral port range (40000-45000) destined for remote C2 indicator 203.0.113.8:443. "
            "TCP backlog queue overflowed due to slow ACK drain from suspected Cobalt Strike beaconing activity."
        )
        process_profile = [
            {"name": "envoy-proxy [worker 0]", "pid": 11482, "cpu_pct": 34.1, "rss": "1.2 GB", "socket_backlog": "4,812 pkts", "bar_pct": 34.1},
            {"name": "python3 /opt/agent/collector.py", "pid": 2841, "cpu_pct": 4.2, "rss": "180 MB", "socket_backlog": "0 pkts", "bar_pct": 4.2},
        ]
        obs = "eBPF socket drops correlate with suspicious remote egress. Recommend initiating forensic PCAP isolation."
        obs_badge = "NET_WARN"
        sources = [
            f"eBPF socket_drop tracepoint ({matched_node})",
            "Kernel ring buffer tcp_drop_reason",
            "PCAP Flow Extraction #1048",
        ]

    elif "oomkill" in lower_prompt or "oom" in lower_prompt or "4." in prompt:
        narrative = (
            "Kernel audit logs reveal 2 OOMKill invocations in the last 60 minutes affecting container namespace c-9f82410a. "
            "Memory cgroup limit (4096 MB) was exceeded by a Node.js SSR worker thread. Deploy commit 4a8f9c introduced an unconstrained "
            "in-memory response cache that inflated RSS by 3.2 GB during peak traffic."
        )
        process_profile = [
            {"name": "node /app/server.js", "pid": 58914, "cpu_pct": 42.0, "rss": "4.1 GB (OOM_KILLED)", "socket_backlog": "112 pkts", "bar_pct": 98.5},
            {"name": "containerd-shim-runc", "pid": 58890, "cpu_pct": 1.1, "rss": "42 MB", "socket_backlog": "0 pkts", "bar_pct": 2.5},
        ]
        obs = "Cgroup hard limit reached. Automatic pod restart completed successfully in 1.4s."
        obs_badge = "OOM_ALERT"
        sources = [
            "/var/log/messages oom-killer invocation log",
            "Systemd slice memory.current counter",
            "Container runtime cgroup v2 stats",
        ]

    else:
        # Free-form query synthesis
        narrative = (
            f"Evaluated telemetry for query: \"{prompt}\" across {len(nodes)} active fleet hosts. "
            f"Target host {target_node} exhibits stable core performance with baseline resource utilization. "
            "No anomalous syscall patterns or unhandled threshold violations observed in the current sampling window."
        )
        process_profile = [
            {"name": "systemd-journald", "pid": 412, "cpu_pct": 2.4, "rss": "85 MB", "socket_backlog": "0 pkts", "bar_pct": 5.0},
            {"name": "palantir-collector", "pid": 1024, "cpu_pct": 3.1, "rss": "120 MB", "socket_backlog": "0 pkts", "bar_pct": 6.2},
        ]
        obs = "System telemetry steady. All daemon probes reporting nominally."
        obs_badge = "SYS_OK"
        sources = [
            f"Host Collector telemetry ({target_node})",
            "Platform health monitor",
            "Fleet metric snapshot series",
        ]

    return {
        "prompt": prompt,
        "timestamp": now.isoformat(),
        "target_host": target_node,
        "model": "palantir-telemetry-eval-v1 (Offline Mock Mode) · Sandbox Isolation",
        "narrative": narrative,
        "process_profile": process_profile,
        "diagnostic_observation": obs,
        "diagnostic_badge": obs_badge,
        "evidence_sources": sources,
        "action_workflows": {
            "status": "planned_capability",
            "note": "Approval pipeline disabled in evaluation build. Mutations require human sign-off with mandatory SIEM audit logging.",
            "actions": [
                {"id": "approve", "label": "Approve Remediation", "disabled": True},
                {"id": "reject", "label": "Reject", "disabled": True},
                {"id": "undo", "label": "Undo", "disabled": True},
            ],
        },
        "fleet_context": {
            "target_node": target_node,
            "kernel_os": "6.5.0-35-generic",
            "distribution": "Ubuntu 22.04.4 LTS",
            "telemetry_window": "Last 15 minutes",
            "active_daemon": "palantir-ebpf-v2.14",
            "simulation_hash": "0x9fbc18d24ae",
        },
    }
