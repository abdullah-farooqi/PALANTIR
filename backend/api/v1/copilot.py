import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import cast, func, or_, select, String
from sqlalchemy.ext.asyncio import AsyncSession

from core.api_auth import require_read
from core.database import get_session
from models.alert import AlertEvent
from models.investigation import AgentInvestigation
from models.node import MonitoredNode
from models.pcap_analysis import (
    PcapAnalysisRuns,
    PcapArtifacts,
    PcapCveMatches,
    PcapFlows,
    PcapIocs,
    PcapSeverityScores,
)

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
        "id": "pcap_findings",
        "label": "2. What PCAP findings look worst?",
        "hotkey": "Alt+2",
        "prompt": "What PCAP findings look worst on this host?",
    },
    {
        "id": "ioc_threats",
        "label": "3. List threat-intel IOCs",
        "hotkey": "Alt+3",
        "prompt": "List non-allowlisted IOCs with threat intel matches.",
    },
    {
        "id": "cve_matches",
        "label": "4. Show CVE matches from captures",
        "hotkey": "Alt+4",
        "prompt": "Show CVE matches from recent PCAP analysis.",
    },
]


@router.get("/presets")
async def get_copilot_presets(_role: None = Depends(require_read)) -> Dict[str, Any]:
    return {
        "presets": PRESET_PROMPTS,
        "model": "palantir-analysis-sql-v1",
        "state": "LIVE",
        "version": "v1.0",
    }


async def _resolve_node(session: AsyncSession, host: str | None) -> MonitoredNode | None:
    if host:
        node = (
            await session.execute(
                select(MonitoredNode).where(MonitoredNode.hostname.ilike(host)).limit(1)
            )
        ).scalar_one_or_none()
        if node:
            return node
    return (
        await session.execute(
            select(MonitoredNode).where(MonitoredNode.active.is_(True)).order_by(MonitoredNode.id).limit(1)
        )
    ).scalar_one_or_none()


@router.post("/query")
async def execute_copilot_query(
    req: CopilotQueryRequest,
    session: AsyncSession = Depends(get_session),
    _role: None = Depends(require_read),
) -> Dict[str, Any]:
    prompt = req.prompt.strip()
    now = datetime.now(timezone.utc)
    lower = prompt.lower()
    node = await _resolve_node(session, req.host)
    target_node = node.hostname if node else (req.host or "unknown")

    run_q = select(PcapAnalysisRuns).where(PcapAnalysisRuns.status == "complete")
    if node:
        run_q = run_q.where(PcapAnalysisRuns.node_id == node.id)
    run_q = run_q.order_by(PcapAnalysisRuns.completed_at.desc().nullslast(), PcapAnalysisRuns.id.desc()).limit(5)
    runs = (await session.execute(run_q)).scalars().all()
    run_ids = [r.run_id for r in runs]

    alerts = (
        await session.execute(
            select(AlertEvent)
            .where(AlertEvent.status.in_(("WARNING", "CRITICAL")))
            .order_by(AlertEvent.received_at.desc())
            .limit(10)
        )
    ).scalars().all()

    process_profile: list[dict[str, Any]] = []
    sources = ["pcap_analysis_runs", "pcap_iocs", "pcap_cve_matches", "pcap_flows"]

    if "summarize active alert" in lower or "summarize alerts" in lower:
        crit = sum(1 for a in alerts if a.status == "CRITICAL")
        warn = sum(1 for a in alerts if a.status == "WARNING")
        details = [f"{a.alert_name} node#{a.node_id} ({a.status})" for a in alerts[:5]]
        narrative = (
            f"{len(alerts)} active alerts ({crit} critical, {warn} warning). "
            + ("; ".join(details) if details else "None currently open.")
        )
        obs = "Alert table query"
        obs_badge = "SYS_WARN" if crit else "SYS_OK"
        sources = ["alert_events"]

    elif "ioc" in lower or "threat intel" in lower or "indicator" in lower:
        if not run_ids:
            narrative = f"No completed PCAP analysis runs for {target_node}."
            obs = "No runs"
            obs_badge = "SYS_OK"
        else:
            iocs = (
                await session.execute(
                    select(PcapIocs)
                    .where(
                        PcapIocs.run_id.in_(run_ids),
                        PcapIocs.is_allowlisted.is_(False),
                        PcapIocs.threat_intel_match.is_not(None),
                    )
                    .order_by(PcapIocs.id.desc())
                    .limit(20)
                )
            ).scalars().all()
            if not iocs:
                narrative = f"No threat-intel IOC hits in the latest {len(run_ids)} runs on {target_node}."
                obs = "IOCs clean or enrichment skipped"
                obs_badge = "SYS_OK"
            else:
                bits = [f"{i.ioc_type}:{i.ioc_value}" for i in iocs[:8]]
                narrative = f"{len(iocs)} non-allowlisted IOCs with threat intel on {target_node}: " + "; ".join(bits)
                obs = "pcap_iocs.threat_intel_match"
                obs_badge = "NET_WARN"
                process_profile = [
                    {
                        "name": f"{i.ioc_type}:{i.ioc_value}",
                        "pid": i.id,
                        "cpu_pct": 0,
                        "rss": (i.threat_intel_match or {}).get("description", "")[:40] if isinstance(i.threat_intel_match, dict) else "",
                        "socket_backlog": "threat",
                        "bar_pct": 50,
                    }
                    for i in iocs[:5]
                ]

    elif "cve" in lower or "vulnerab" in lower:
        if not run_ids:
            narrative = f"No completed PCAP analysis runs for {target_node}."
            obs = "No runs"
            obs_badge = "SYS_OK"
        else:
            cves = (
                await session.execute(
                    select(PcapCveMatches)
                    .where(PcapCveMatches.run_id.in_(run_ids))
                    .order_by(PcapCveMatches.cvss_score.desc().nullslast(), PcapCveMatches.id.desc())
                    .limit(20)
                )
            ).scalars().all()
            if not cves:
                narrative = f"No CVE signature matches in latest runs on {target_node}."
                obs = "pcap_cve_matches empty"
                obs_badge = "SYS_OK"
            else:
                bits = [f"{c.cve_id} ({c.severity}, cvss={c.cvss_score})" for c in cves[:8]]
                narrative = f"{len(cves)} CVE matches on {target_node}: " + "; ".join(bits)
                obs = "pcap_cve_matches"
                obs_badge = "NET_WARN" if any(c.severity in ("high", "critical") for c in cves) else "SYS_OK"

    elif "pcap" in lower or "finding" in lower or "worst" in lower or "tuesday" in lower or "server" in lower:
        if not run_ids:
            narrative = f"No completed PCAP analysis for {target_node}."
            obs = "No runs"
            obs_badge = "SYS_OK"
        else:
            scores = (
                await session.execute(
                    select(PcapSeverityScores)
                    .where(PcapSeverityScores.run_id.in_(run_ids))
                    .order_by(PcapSeverityScores.overall_score.desc(), PcapSeverityScores.id.desc())
                )
            ).scalars().all()
            ioc_threats = (
                await session.execute(
                    select(func.count(PcapIocs.id)).where(
                        PcapIocs.run_id.in_(run_ids),
                        PcapIocs.is_allowlisted.is_(False),
                        PcapIocs.threat_intel_match.is_not(None),
                    )
                )
            ).scalar_one()
            cve_count = (
                await session.execute(
                    select(func.count(PcapCveMatches.id)).where(PcapCveMatches.run_id.in_(run_ids))
                )
            ).scalar_one()
            flow_count = (
                await session.execute(
                    select(func.count(PcapFlows.id)).where(PcapFlows.run_id.in_(run_ids))
                )
            ).scalar_one()
            top = scores[0] if scores else None
            factors = (getattr(top, "top_risk_factors", None) or []) if top else []
            factor_txt = "; ".join(
                f.get("title", "") for f in factors[:3] if isinstance(f, dict)
            )
            narrative = (
                f"Latest {len(run_ids)} complete runs on {target_node}: "
                f"flows={flow_count}, threat_iocs={ioc_threats}, cves={cve_count}. "
                + (
                    f"Highest risk score {top.overall_score} ({top.overall_severity}). {factor_txt}"
                    if top
                    else "No severity score rows yet."
                )
            )
            obs = "severity + IOC + CVE aggregates"
            obs_badge = "NET_WARN" if top and str(top.overall_severity) in ("high", "critical") else "SYS_OK"

    else:
        # Free-form: search IOC value / flow IP / artifact hash tokens from the prompt
        token = None
        for part in re.split(r"\s+", prompt):
            if len(part) >= 4 and re.search(r"[.:/\-]", part):
                token = part.strip(".,;\"'")
                break
        if token and run_ids:
            iocs = (
                await session.execute(
                    select(PcapIocs)
                    .where(PcapIocs.run_id.in_(run_ids), PcapIocs.ioc_value.ilike(f"%{token}%"))
                    .limit(10)
                )
            ).scalars().all()
            flows = (
                await session.execute(
                    select(PcapFlows)
                    .where(
                        PcapFlows.run_id.in_(run_ids),
                        or_(
                            cast(PcapFlows.src_ip, String).ilike(f"%{token}%"),
                            cast(PcapFlows.dst_ip, String).ilike(f"%{token}%"),
                        ),
                    )
                    .limit(10)
                )
            ).scalars().all()
            arts = (
                await session.execute(
                    select(PcapArtifacts)
                    .where(
                        PcapArtifacts.run_id.in_(run_ids),
                        or_(
                            PcapArtifacts.sha256.ilike(f"%{token}%"),
                            PcapArtifacts.source_uri.ilike(f"%{token}%"),
                        ),
                    )
                    .limit(10)
                )
            ).scalars().all()
            narrative = (
                f"Search for '{token}' on {target_node}: "
                f"{len(iocs)} IOCs, {len(flows)} flows, {len(arts)} artifacts."
            )
            obs = "token search across analysis tables"
            obs_badge = "SYS_OK" if not iocs and not flows else "NET_WARN"
        else:
            inv_count = (
                await session.execute(select(func.count(AgentInvestigation.id)))
            ).scalar_one()
            narrative = (
                f"Queried analysis store for '{prompt}'. "
                f"{len(run_ids)} recent complete PCAP runs on {target_node}; "
                f"{inv_count} investigations total. Ask about IOCs, CVEs, or findings for specifics."
            )
            obs = "generic analysis index"
            obs_badge = "SYS_OK"

    return {
        "prompt": prompt,
        "timestamp": now.isoformat(),
        "target_host": target_node,
        "model": "palantir-analysis-sql-v1",
        "narrative": narrative,
        "process_profile": process_profile,
        "diagnostic_observation": obs,
        "diagnostic_badge": obs_badge,
        "evidence_sources": sources,
        "action_workflows": {
            "status": "read_only",
            "note": "Copilot answers from persisted PCAP analysis tables. Mutations require explicit investigation actions.",
            "actions": [],
        },
        "fleet_context": {
            "target_node": target_node,
            "complete_runs": len(run_ids),
            "telemetry_window": "latest complete analysis runs",
        },
    }
