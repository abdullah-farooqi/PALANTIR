import { useState } from 'react';
import { CloudDownload, Copy, Check, Lock, Play, PowerOff, ShieldAlert, Sparkles, Terminal } from 'lucide-react';

export function StateNotAnalysed({ evidence, onTrigger, canWrite }) {
  const targetName = evidence?.filename || evidence?.file_name || 'capture.pcap';
  const sha256 = evidence?.sha256 || evidence?.collector_sha256 || '';

  return (
    <div
      style={{
        background: '#14171B',
        border: '1px solid #262B32',
        borderRadius: 8,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        maxWidth: 600,
        margin: '20px auto',
        fontFamily: "'Space Grotesk', sans-serif",
      }}
    >
      <div style={{ padding: '12px 16px', borderBottom: '1px solid #262B32', background: '#101215', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#C6FF00' }} />
          <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: '#C6FF00', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            STATE 01 · NO ANALYSIS EXECUTED
          </span>
        </div>
        <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#8D9479' }}>ID: ST-01</span>
      </div>

      <div style={{ padding: 24, display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
        {/* Radar Wireframe Graphic */}
        <div
          style={{
            width: 72,
            height: 72,
            borderRadius: '50%',
            background: '#1F2022',
            border: '1px solid #434933',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            position: 'relative',
            marginBottom: 16,
          }}
        >
          <svg width="48" height="48" viewBox="0 0 40 40" fill="none" style={{ color: '#C6FF00' }}>
            <circle cx="20" cy="20" r="18" stroke="currentColor" strokeWidth="1" strokeDasharray="2 2" opacity="0.4" />
            <circle cx="20" cy="20" r="12" stroke="currentColor" strokeWidth="1" opacity="0.6" />
            <circle cx="20" cy="20" r="6" stroke="currentColor" strokeWidth="1.5" />
            <line x1="20" y1="2" x2="20" y2="38" stroke="currentColor" strokeWidth="0.75" opacity="0.3" />
            <line x1="2" y1="20" x2="38" y2="20" stroke="currentColor" strokeWidth="0.75" opacity="0.3" />
            <circle cx="27" cy="14" r="2.5" fill="#C6FF00" />
          </svg>
          <span style={{ position: 'absolute', top: 4, right: 4, width: 8, height: 8, borderRadius: '50%', background: '#C6FF00' }} />
        </div>

        <h3 style={{ fontSize: 16, fontWeight: 600, color: '#FFFFFF', margin: '0 0 8px 0' }}>
          This capture hasn't been analysed
        </h3>
        <p style={{ fontSize: 13, color: '#BFC7D5', maxWidth: 440, lineHeight: 1.5, margin: '0 0 16px 0' }}>
          PCAP payload (<span style={{ fontFamily: "'JetBrains Mono', monospace", color: '#FFFFFF' }}>{targetName}</span>) has finished uploading to sandbox storage. Run Suricata 7.0 &amp; Zeek 6.0 analysis engines to extract flows, sessions, and IOCs.
        </p>

        <div style={{ width: '100%', background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: 12, textAlign: 'left', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 18 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#8B93A0' }}>
            <span>Target Hash (SHA256):</span>
            <span style={{ color: '#FFFFFF' }}>{sha256 ? `${sha256.slice(0, 16)}…` : '—'}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#8B93A0' }}>
            <span>Evidence ID:</span>
            <span style={{ color: '#C6FF00' }}>{evidence?.file_id || evidence?.id || '—'}</span>
          </div>
        </div>
      </div>

      <div style={{ padding: '14px 20px', borderTop: '1px solid #262B32', background: '#101215', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <button
          type="button"
          onClick={onTrigger}
          disabled={!canWrite}
          style={{
            padding: '8px 18px',
            borderRadius: 4,
            border: 'none',
            background: canWrite ? '#C6FF00' : '#272B20',
            color: canWrite ? '#151F00' : '#888D79',
            fontSize: 12,
            fontWeight: 700,
            cursor: canWrite ? 'pointer' : 'not-allowed',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          <Play size={15} fill={canWrite ? '#151F00' : '#888D79'} />
          <span>Run analysis</span>
        </button>
        <span style={{ fontSize: 11, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
          Est. runtime: ~45s
        </span>
      </div>
    </div>
  );
}

export function StateInFlightTransfer({ transferProgress = 0, label = 'Transfer in progress' }) {
  const pct = Math.max(0, Math.min(100, Number(transferProgress) || 0));
  return (
    <div
      style={{
        background: '#14171B',
        border: '1px solid #262B32',
        borderRadius: 8,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        maxWidth: 600,
        margin: '20px auto',
        fontFamily: "'Space Grotesk', sans-serif",
      }}
    >
      <div style={{ padding: '12px 16px', borderBottom: '1px solid #262B32', background: '#101215', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#F5A524' }} />
          <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: '#F5A524', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            STATE 02 · PCAP TRANSFER IN FLIGHT
          </span>
        </div>
        <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#8D9479' }}>ID: ST-02</span>
      </div>

      <div style={{ padding: 24, display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
        <div
          style={{
            width: 72,
            height: 72,
            borderRadius: '50%',
            background: '#1F2022',
            border: '2px solid rgba(198, 255, 0, 0.3)',
            borderTopColor: '#C6FF00',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            position: 'relative',
            marginBottom: 16,
            animation: 'spin 1.2s linear infinite',
          }}
        >
          <CloudDownload size={28} style={{ color: '#C6FF00' }} />
        </div>

        <h3 style={{ fontSize: 16, fontWeight: 600, color: '#FFFFFF', margin: '0 0 8px 0' }}>
          Packet capture is still transferring ({pct}%)
        </h3>
        <p style={{ fontSize: 13, color: '#BFC7D5', maxWidth: 440, lineHeight: 1.5, margin: '0 0 16px 0' }}>
          {label}. Analysis starts after the capture is fully stored and verified.
        </p>

        <div style={{ width: '100%', marginBottom: 12, textAlign: 'left' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, fontFamily: "'JetBrains Mono', monospace", marginBottom: 6 }}>
            <span style={{ color: '#8B93A0' }}>Transfer progress</span>
            <span style={{ color: '#C6FF00', fontWeight: 600 }}>{pct}%</span>
          </div>
          <div style={{ width: '100%', height: 6, background: '#0D0E10', borderRadius: 3, overflow: 'hidden', border: '1px solid #262B32' }}>
            <div style={{ width: `${pct}%`, height: '100%', background: '#C6FF00' }} />
          </div>
        </div>
      </div>

      <div style={{ padding: '14px 20px', borderTop: '1px solid #262B32', background: '#101215', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ position: 'relative' }}>
          <button
            type="button"
            disabled
            style={{
              padding: '8px 18px',
              borderRadius: 4,
              border: '1px solid #343537',
              background: '#1F2022',
              color: '#888D79',
              fontSize: 12,
              fontWeight: 700,
              cursor: 'not-allowed',
              opacity: 0.7,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <Play size={15} fill="#888D79" />
            <span>Run analysis</span>
          </button>
        </div>
        <span style={{ fontSize: 11, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
          Verifying MD5 integrity
        </span>
      </div>
    </div>
  );
}

export function StateUnconfiguredDaemon() {
  const [copied, setCopied] = useState(false);
  const snippet = `[pcap_capture]
enabled = true
interface = any
snaplen = 128
buffer_size_mb = 64`;

  return (
    <div
      style={{
        background: '#14171B',
        border: '1px solid #262B32',
        borderRadius: 8,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        maxWidth: 600,
        margin: '20px auto',
        fontFamily: "'Space Grotesk', sans-serif",
      }}
    >
      <div style={{ padding: '12px 16px', borderBottom: '1px solid #262B32', background: '#101215', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#8D9479' }} />
          <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: '#8D9479', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            STATE 03 · PACKET CAPTURE UNCONFIGURED
          </span>
        </div>
        <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#8D9479' }}>ID: ST-03</span>
      </div>

      <div style={{ padding: 24, display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
        <div
          style={{
            width: 72,
            height: 72,
            borderRadius: '50%',
            background: '#1F2022',
            border: '1px solid #343537',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: 16,
          }}
        >
          <PowerOff size={30} style={{ color: '#8D9479' }} />
        </div>

        <h3 style={{ fontSize: 16, fontWeight: 600, color: '#FFFFFF', margin: '0 0 8px 0' }}>
          Packet capture was not enabled on this host
        </h3>
        <p style={{ fontSize: 13, color: '#BFC7D5', maxWidth: 440, lineHeight: 1.5, margin: '0 0 16px 0' }}>
          Host agent is running in telemetry-only mode (metrics + auditd). Network socket ring capture requires kernel socket filter configuration.
        </p>

        <div style={{ width: '100%', background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: 12, textAlign: 'left', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, position: 'relative' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6, color: '#8D9479', fontSize: 10 }}>
            <span>/etc/palantir/agent.conf</span>
            <button
              type="button"
              onClick={() => {
                navigator.clipboard.writeText(snippet);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              style={{ background: 'transparent', border: 0, color: '#C6FF00', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontSize: 10 }}
            >
              {copied ? <Check size={12} /> : <Copy size={12} />}
              <span>{copied ? 'COPIED' : 'COPY'}</span>
            </button>
          </div>
          <pre style={{ margin: 0, color: '#C6FF00', fontSize: 11, lineHeight: 1.4 }}>{snippet}</pre>
        </div>
      </div>
    </div>
  );
}

export function StateRbacReadOnly() {
  return (
    <div
      style={{
        background: '#14171B',
        border: '1px solid #262B32',
        borderRadius: 8,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        maxWidth: 600,
        margin: '20px auto',
        fontFamily: "'Space Grotesk', sans-serif",
      }}
    >
      <div style={{ padding: '12px 16px', borderBottom: '1px solid #262B32', background: '#101215', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#BFC7D5' }} />
          <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: '#BFC7D5', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            STATE 04 · RBAC PERMISSION BOUNDARY
          </span>
        </div>
        <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#8D9479' }}>ID: ST-04</span>
      </div>

      <div style={{ padding: 24, display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: '8px 12px', marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Lock size={16} style={{ color: '#8B93A0' }} />
            <span style={{ fontSize: 11, fontWeight: 700, color: '#BFC7D5', fontFamily: "'JetBrains Mono', monospace" }}>
              ROLE: SOC_ANALYST_L1
            </span>
          </div>
          <span style={{ fontSize: 10, fontWeight: 700, background: '#1F2022', border: '1px solid #343537', color: '#BFC7D5', padding: '2px 6px', borderRadius: 4 }}>
            READ-ONLY
          </span>
        </div>

        <h3 style={{ fontSize: 15, fontWeight: 600, color: '#FFFFFF', margin: '0 0 6px 0' }}>
          Forensic results visible · Administrative triggers locked
        </h3>
        <p style={{ fontSize: 13, color: '#BFC7D5', lineHeight: 1.5, margin: '0 0 16px 0' }}>
          Suricata &amp; Zeek findings from active runs are accessible for inspection, filtering, and STIX export. Triggering new analyses requires Admin or Forensics Tier-3 privileges.
        </p>
      </div>
    </div>
  );
}
