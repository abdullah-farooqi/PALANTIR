"""Minimal text PDF builder for investigation forensic exports (no extra deps)."""

from __future__ import annotations

from typing import Any


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_investigation_pdf(payload: dict[str, Any]) -> bytes:
    """Build a single-page-ish multi-line PDF from investigation export fields."""
    inv = payload.get("investigation") or {}
    node = inv.get("node") or {}
    lines = [
        "PALANTIR Forensic Investigation Report",
        f"Investigation #{inv.get('id')}  status={inv.get('status')}",
        f"Host: {node.get('hostname') or 'unknown'}  trigger={inv.get('trigger_type')}",
        f"Exported: {payload.get('exported_at')}",
        "",
        f"Evidence files: {payload.get('evidence_count', 0)}",
        f"Flows: {payload.get('flows_count', 0)}  IOCs: {payload.get('iocs_count', 0)}  CVEs: {payload.get('cves_count', 0)}",
    ]
    severity = payload.get("severity") or {}
    if severity:
        lines.append(
            f"Risk score: {severity.get('overall_score')} ({severity.get('overall_severity')})"
        )
        for factor in (severity.get("top_risk_factors") or [])[:5]:
            if isinstance(factor, dict):
                lines.append(f"  - [{factor.get('severity')}] {factor.get('title')} (+{factor.get('points')})")
    lines.append("")
    lines.append("Top IOCs:")
    for ioc in (payload.get("iocs") or [])[:15]:
        lines.append(
            f"  - {ioc.get('type')}: {ioc.get('value')} allowlisted={ioc.get('allowlisted')}"
        )
    lines.append("")
    lines.append("CVE matches:")
    for cve in (payload.get("cve_matches") or [])[:15]:
        lines.append(
            f"  - {cve.get('cve_id')} cvss={cve.get('cvss')} severity={cve.get('severity')}"
        )
    lines.append("")
    lines.append("Artifact hashes:")
    for art in (payload.get("artifacts") or [])[:15]:
        lines.append(f"  - {art.get('type')}: {art.get('sha256')}")

    content_lines = ["BT", "/F1 10 Tf", "50 780 Td", "14 TL"]
    first = True
    for line in lines:
        safe = _escape(str(line)[:110])
        if first:
            content_lines.append(f"({safe}) Tj")
            first = False
        else:
            content_lines.append("T*")
            content_lines.append(f"({safe}) Tj")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")

    objects: list[bytes] = []
    objects.append(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
    objects.append(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
    objects.append(
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n"
    )
    objects.append(
        f"4 0 obj<< /Length {len(stream)} >>stream\n".encode("ascii")
        + stream
        + b"\nendstream\nendobj\n"
    )
    objects.append(b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>endobj\n")

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(out))
        out.extend(obj)
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(out)
