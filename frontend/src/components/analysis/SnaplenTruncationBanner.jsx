import { useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronUp, ExternalLink, Info } from 'lucide-react';

export default function SnaplenTruncationBanner({ snaplen = 128, isTruncated = true }) {
  const [expanded, setExpanded] = useState(false);

  if (!isTruncated && snaplen >= 65535) return null;

  return (
    <div
      style={{
        background: 'rgba(147, 0, 10, 0.12)',
        border: '1px solid rgba(229, 72, 77, 0.45)',
        borderRadius: 6,
        padding: '10px 14px',
        margin: '0 0 14px 0',
        fontFamily: "'Space Grotesk', sans-serif",
      }}
    >
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <AlertTriangle size={18} style={{ color: '#E5484D', flexShrink: 0 }} />
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#FFB4AB' }}>
              Capture truncated at snaplen {snaplen}. Payload-dependent findings (artifacts, CVE signatures) may be incomplete.
            </div>
            <div style={{ fontSize: 10, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>
              SNAPLEN: {snaplen}B · SLICED AT ETHERNET + IP + TCP HEADERS · CONFIDENCE DEGRADED
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            style={{
              background: '#1F2022',
              border: '1px solid #343537',
              borderRadius: 4,
              padding: '4px 8px',
              fontSize: 11,
              color: '#C6FF00',
              fontFamily: "'JetBrains Mono', monospace",
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
            }}
          >
            <span>{expanded ? 'Hide Impact Matrix' : 'View Impact Matrix'}</span>
            {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </button>
        </div>
      </div>

      {expanded && (
        <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid rgba(229, 72, 77, 0.25)' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#E3E2E5', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>
            Confidence Degradation Breakdown (Snaplen {snaplen}B)
          </div>
          <table
            style={{
              width: '100%',
              borderCollapse: 'collapse',
              fontSize: 11,
              fontFamily: "'JetBrains Mono', monospace",
              textAlign: 'left',
            }}
          >
            <thead>
              <tr style={{ color: '#8D9479', borderBottom: '1px solid #262B32' }}>
                <th style={{ padding: '6px 8px' }}>Pipeline Domain</th>
                <th style={{ padding: '6px 8px' }}>Confidence</th>
                <th style={{ padding: '6px 8px' }}>Forensic Impact & Diagnostic</th>
              </tr>
            </thead>
            <tbody>
              <tr style={{ borderBottom: '1px solid #1F2022' }}>
                <td style={{ padding: '6px 8px', color: '#FFFFFF', fontWeight: 600 }}>Flows & IP Headers</td>
                <td style={{ padding: '6px 8px', color: '#C6FF00' }}>HIGH (100%)</td>
                <td style={{ padding: '6px 8px', color: '#BFC7D5' }}>Full L2-L4 IP headers retained; accurate 5-tuple routing & byte counters.</td>
              </tr>
              <tr style={{ borderBottom: '1px solid #1F2022' }}>
                <td style={{ padding: '6px 8px', color: '#FFFFFF', fontWeight: 600 }}>Session State Machine</td>
                <td style={{ padding: '6px 8px', color: '#C6FF00' }}>HIGH (98%)</td>
                <td style={{ padding: '6px 8px', color: '#BFC7D5' }}>SYN, ACK, RST, FIN sequence tracking preserved for connection state classification.</td>
              </tr>
              <tr style={{ borderBottom: '1px solid #1F2022' }}>
                <td style={{ padding: '6px 8px', color: '#FFFFFF', fontWeight: 600 }}>Application Layer (HTTP/TLS)</td>
                <td style={{ padding: '6px 8px', color: '#F5A524' }}>PARTIAL (HEAD)</td>
                <td style={{ padding: '6px 8px', color: '#BFC7D5' }}>First 128 bytes parsed (method, URI root). Extended headers or cookies sliced.</td>
              </tr>
              <tr style={{ borderBottom: '1px solid #1F2022' }}>
                <td style={{ padding: '6px 8px', color: '#FFFFFF', fontWeight: 600 }}>Artifact Reassembly</td>
                <td style={{ padding: '6px 8px', color: '#E5484D' }}>DEGRADED</td>
                <td style={{ padding: '6px 8px', color: '#BFC7D5' }}>Full payload reconstruction limited to initial segment; payload hashes marked partial.</td>
              </tr>
              <tr>
                <td style={{ padding: '6px 8px', color: '#FFFFFF', fontWeight: 600 }}>Suricata / Zeek Rules</td>
                <td style={{ padding: '6px 8px', color: '#F5A524' }}>MEDIUM</td>
                <td style={{ padding: '6px 8px', color: '#BFC7D5' }}>Header heuristics active; deep-packet inspection (content matching offset &gt; 128) skipped.</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
