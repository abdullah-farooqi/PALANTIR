import { useState } from 'react';
import { Play, RotateCcw, X, Info } from 'lucide-react';

export default function ReRunAnalysisModal({
  isOpen,
  onClose,
  onConfirm,
  isSubmitting,
  investigationId,
  scope,
  latestRunId,
}) {
  const [suricataEnabled, setSuricataEnabled] = useState(true);
  const [zeekEnabled, setZeekEnabled] = useState(true);
  const [snortEnabled, setSnortEnabled] = useState(false);

  if (!isOpen) return null;

  const targetFilename = scope?.filename || 'capture.pcap.gz';
  const targetSizeFormatted = scope?.size_formatted || '12.4 MB';

  return (
    <div
      className="analysis-confirm-backdrop"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !isSubmitting) onClose();
      }}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(0, 0, 0, 0.78)',
        backdropFilter: 'blur(3px)',
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="rerun-modal-title"
        style={{
          width: 'min(100%, 520px)',
          background: '#14171B',
          border: '1px solid #262B32',
          borderRadius: 8,
          boxShadow: '0 20px 48px rgba(0,0,0,0.65)',
          padding: 24,
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
          color: '#E3E2E5',
          fontFamily: "'Space Grotesk', sans-serif",
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #262B32', paddingBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 32, height: 32, borderRadius: 6, background: '#1F2022', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid #262B32', color: '#C6FF00' }}>
              <RotateCcw size={18} />
            </div>
            <div>
              <div style={{ fontSize: 9, fontFamily: "'JetBrains Mono', monospace", color: '#8D9479', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                Execution Confirmation · Frame 01
              </div>
              <h2 id="rerun-modal-title" style={{ margin: 0, fontSize: 16, fontWeight: 600, color: '#FFFFFF' }}>
                Re-run analysis?
              </h2>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={isSubmitting}
            style={{ background: 'transparent', border: 0, color: '#8B93A0', cursor: 'pointer', padding: 4 }}
            aria-label="Close dialog"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <p style={{ margin: 0, fontSize: 13, color: '#BFC7D5', lineHeight: 1.5 }}>
            A new forensic analysis run will be triggered for{' '}
            <span style={{ fontFamily: "'JetBrains Mono', monospace", background: '#1F2022', border: '1px solid #343537', padding: '2px 6px', borderRadius: 4, color: '#C6FF00' }}>
              {targetFilename}
            </span>. Extracted flows, sessions, reconstructed artifacts, and IOC correlations will be recomputed. Previous runs are archived.
          </p>

          {/* Target Metadata Summary Box */}
          <div style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: 12, display: 'flex', flexDirection: 'column', gap: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1F2022', paddingBottom: 6 }}>
              <span style={{ color: '#8D9479', textTransform: 'uppercase', fontSize: 10 }}>Target PCAP</span>
              <span style={{ color: '#FFFFFF' }}>{targetFilename} <span style={{ color: '#8B93A0' }}>({targetSizeFormatted})</span></span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1F2022', paddingBottom: 6 }}>
              <span style={{ color: '#8D9479', textTransform: 'uppercase', fontSize: 10 }}>Investigation</span>
              <span style={{ color: '#C6FF00' }}>#INV-{investigationId}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1F2022', paddingBottom: 6 }}>
              <span style={{ color: '#8D9479', textTransform: 'uppercase', fontSize: 10 }}>Pipeline Baseline</span>
              <span style={{ color: '#FFFFFF' }}>Supersedes {latestRunId ? latestRunId.slice(0, 12) : 'active baseline'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: '#8D9479', textTransform: 'uppercase', fontSize: 10 }}>Worker Pool</span>
              <span style={{ color: '#C6FF00' }}>pcap-worker-pool-01 (ready)</span>
            </div>
          </div>

          {/* Engine Selection Toggles */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: '#8D9479', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Forensic Analysis Engines
            </span>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 10px', background: '#1F2022', border: `1px solid ${suricataEnabled ? '#C6FF00' : '#262B32'}`, borderRadius: 4, cursor: 'pointer', fontSize: 11 }}>
                <input
                  type="checkbox"
                  checked={suricataEnabled}
                  onChange={(e) => setSuricataEnabled(e.target.checked)}
                  style={{ accentColor: '#C6FF00' }}
                />
                <div>
                  <div style={{ fontWeight: 600, color: '#FFFFFF' }}>Suricata 7.0</div>
                  <div style={{ fontSize: 9, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace" }}>Signatures</div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 10px', background: '#1F2022', border: `1px solid ${zeekEnabled ? '#C6FF00' : '#262B32'}`, borderRadius: 4, cursor: 'pointer', fontSize: 11 }}>
                <input
                  type="checkbox"
                  checked={zeekEnabled}
                  onChange={(e) => setZeekEnabled(e.target.checked)}
                  style={{ accentColor: '#C6FF00' }}
                />
                <div>
                  <div style={{ fontWeight: 600, color: '#FFFFFF' }}>Zeek 6.0</div>
                  <div style={{ fontSize: 9, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace" }}>Behavioral</div>
                </div>
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 10px', background: '#1F2022', border: `1px solid ${snortEnabled ? '#C6FF00' : '#262B32'}`, borderRadius: 4, cursor: 'pointer', fontSize: 11 }}>
                <input
                  type="checkbox"
                  checked={snortEnabled}
                  onChange={(e) => setSnortEnabled(e.target.checked)}
                  style={{ accentColor: '#C6FF00' }}
                />
                <div>
                  <div style={{ fontWeight: 600, color: '#FFFFFF' }}>Snort 3</div>
                  <div style={{ fontSize: 9, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace" }}>Lightweight</div>
                </div>
              </label>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace" }}>
            <Info size={14} style={{ color: '#8D9479' }} />
            <span>Typical execution time: ~38 seconds for {targetSizeFormatted}.</span>
          </div>
        </div>

        {/* Footer */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 10, borderTop: '1px solid #262B32', paddingTop: 16 }}>
          <button
            type="button"
            onClick={onClose}
            disabled={isSubmitting}
            style={{
              padding: '8px 16px',
              borderRadius: 4,
              border: '1px solid #343537',
              background: '#1F2022',
              color: '#BFC7D5',
              cursor: 'pointer',
              fontSize: 12,
              fontFamily: "'Space Grotesk', sans-serif",
              fontWeight: 500,
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => onConfirm({ suricata: suricataEnabled, zeek: zeekEnabled, snort: snortEnabled })}
            disabled={isSubmitting || (!suricataEnabled && !zeekEnabled && !snortEnabled)}
            style={{
              padding: '8px 18px',
              borderRadius: 4,
              border: 'none',
              background: '#C6FF00',
              color: '#151F00',
              cursor: isSubmitting ? 'wait' : 'pointer',
              fontSize: 12,
              fontFamily: "'Space Grotesk', sans-serif",
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <Play size={15} fill="#151F00" />
            <span>{isSubmitting ? 'Queueing…' : 'Run analysis'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
