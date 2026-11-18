"""Tests for IOC enrichment skip path, rollback wipe, hash dedup, and PDF export."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from core.config import settings
from core.database import get_sync_session
from models.investigation import AgentInvestigation
from models.investigation_evidence import InvestigationEvidence
from models.node import MonitoredNode
from models.pcap_analysis import PcapAnalysisRuns, PcapFlows, PcapIocs
from services.pcap_report_pdf import build_investigation_pdf
from workers.pcap_pipeline import (
    handle_chain_failure,
    pcap_analysis_enrich_iocs,
    start_pcap_analysis,
)


def _seed_evidence(tmp_path, monkeypatch, *, sha256: str | None = None, status: str = "complete"):
    monkeypatch.setattr(settings, "PCAP_STORAGE_DIR", tmp_path)
    pcap = tmp_path / "seed.pcap"
    # Minimal classic PCAP global header only is enough for storage presence checks
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    with get_sync_session() as session:
        node = MonitoredNode(hostname=f"node-{uuid4().hex[:8]}", collector_url="http://127.0.0.1:20000", active=True)
        session.add(node)
        session.flush()
        inv = AgentInvestigation(node_id=node.id, trigger_type="manual", status="complete")
        session.add(inv)
        session.flush()
        ev = InvestigationEvidence(
            investigation_id=inv.id,
            node_id=node.id,
            evidence_type="pcap_collection",
            file_name="seed.pcap",
            storage_key="seed.pcap",
            status=status,
            sha256=sha256,
            collector_sha256=sha256,
        )
        session.add(ev)
        session.commit()
        return ev.id, inv.id, node.id


def test_enrich_iocs_skips_without_api_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", "")
    monkeypatch.setattr(settings, "OTX_API_KEY", "")
    ev_id, inv_id, node_id = _seed_evidence(tmp_path, monkeypatch)
    run_id = uuid4().hex
    with get_sync_session() as session:
        session.add(
            PcapAnalysisRuns(
                run_id=run_id,
                evidence_id=ev_id,
                investigation_id=inv_id,
                node_id=node_id,
                status="running",
                current_step="extract_iocs",
            )
        )
        session.commit()

    result = pcap_analysis_enrich_iocs({"evidence_id": ev_id, "run_id": run_id})
    assert result["status"] == "complete"
    assert result["enriched"] == 0
    assert result["skipped"] == "no_api_keys"


def test_handle_chain_failure_deletes_partial_child_rows(tmp_path, monkeypatch):
    ev_id, inv_id, node_id = _seed_evidence(tmp_path, monkeypatch)
    run_id = uuid4().hex
    with get_sync_session() as session:
        session.add(
            PcapAnalysisRuns(
                run_id=run_id,
                evidence_id=ev_id,
                investigation_id=inv_id,
                node_id=node_id,
                status="running",
                current_step="extract_flows",
            )
        )
        session.flush()
        session.add(
            PcapFlows(
                run_id=run_id,
                evidence_id=ev_id,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=1234,
                dst_port=80,
                protocol="tcp",
                flow_key="10.0.0.1:1234-10.0.0.2:80-tcp",
                packet_count=2,
                byte_count=100,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
        )
        session.add(
            PcapIocs(
                run_id=run_id,
                evidence_id=ev_id,
                ioc_type="ipv4",
                ioc_value="203.0.113.9",
                context={},
                is_allowlisted=False,
            )
        )
        session.commit()

    handle_chain_failure(None, Exception("boom"), run_id=run_id, evidence_id=ev_id)

    with get_sync_session() as session:
        run = session.execute(select(PcapAnalysisRuns).where(PcapAnalysisRuns.run_id == run_id)).scalar_one()
        assert run.status == "rolled_back"
        flows = session.execute(select(func.count(PcapFlows.id)).where(PcapFlows.run_id == run_id)).scalar_one()
        iocs = session.execute(select(func.count(PcapIocs.id)).where(PcapIocs.run_id == run_id)).scalar_one()
        assert flows == 0
        assert iocs == 0
        # Original evidence row remains
        ev = session.execute(select(InvestigationEvidence).where(InvestigationEvidence.id == ev_id)).scalar_one()
        assert ev.storage_key == "seed.pcap"


def test_start_pcap_analysis_reuses_complete_run_by_sha256(tmp_path, monkeypatch):
    fingerprint = "a" * 64
    ev_id, inv_id, node_id = _seed_evidence(tmp_path, monkeypatch, sha256=fingerprint)
    prior_run = uuid4().hex
    with get_sync_session() as session:
        session.add(
            PcapAnalysisRuns(
                run_id=prior_run,
                evidence_id=ev_id,
                investigation_id=inv_id,
                node_id=node_id,
                status="complete",
                current_step="score_severity",
                completed_at=datetime.now(timezone.utc),
            )
        )
        session.commit()

    result = start_pcap_analysis(ev_id)
    assert result["reused"] is True
    assert result["run_id"] == prior_run
    assert result["status"] == "complete"


def test_build_investigation_pdf_returns_pdf_bytes():
    pdf = build_investigation_pdf(
        {
            "exported_at": "2026-11-18T00:00:00+00:00",
            "investigation": {"id": 7, "status": "complete", "trigger_type": "manual", "node": {"hostname": "web-01"}},
            "evidence_count": 1,
            "flows_count": 3,
            "iocs_count": 2,
            "cves_count": 1,
            "severity": {"overall_score": 8.1, "overall_severity": "high", "top_risk_factors": []},
            "iocs": [{"type": "ipv4", "value": "203.0.113.10", "allowlisted": False}],
            "cve_matches": [{"cve_id": "CVE-2021-44228", "cvss": 10.0, "severity": "critical"}],
            "artifacts": [{"type": "http_response", "sha256": "b" * 64}],
        }
    )
    assert pdf.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf
    assert len(pdf) > 200
