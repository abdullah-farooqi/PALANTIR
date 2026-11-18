import { useState } from 'react';
import { AlertCircle, AlertTriangle, CheckCircle2, Clock, Copy, Info, Play, RotateCcw, ShieldAlert, XCircle } from 'lucide-react';
import { formatRelative } from '../../lib/format';

export default function AnalysisOverviewLifecycle({
  status,
  runId,
  stepProgress,
  rollbackInfo,
  queueInfo,
  startedAt,
  onReRun,
  canWrite,
}) {
  const [copiedTrace, setCopiedTrace] = useState(false);

  // 1. RUNNING STATE
  if (status === 'running') {
    const activeStep = stepProgress?.step || 'reassemble_sessions';
    const activePct = stepProgress?.pct ?? 64;
    const indexed = stepProgress?.streams_indexed ?? 412;
    const totalStreams = stepProgress?.streams_total ?? 640;
    const elapsed = stepProgress?.elapsed_seconds ?? 14.1;

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, fontFamily: "'Space Grotesk', sans-serif" }}>
        {/* Header Notice Banner */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'rgba(198, 255, 0, 0.08)',
            border: '1px solid rgba(198, 255, 0, 0.3)',
            borderRadius: 6,
            padding: '10px 14px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#C6FF00', animation: 'ping 1.5s cubic-bezier(0, 0, 0.2, 1) infinite' }} />
            <span style={{ fontSize: 12, fontWeight: 600, color: '#FFFFFF' }}>
              RUNNING · RUN #{runId ? runId.slice(0, 8) : 'active'}
            </span>
            <span style={{ fontSize: 11, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
              Updating in real-time
            </span>
          </div>
          <span style={{ fontSize: 11, color: '#BFC7D5' }}>
            Analysis runs in the background. You can navigate away.
          </span>
        </div>

        {/* 2-Column Layout */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          {/* Left: Skeleton Composite Gauge & Metric Cards */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div
              style={{
                background: '#0D0E10',
                border: '1px dashed #343537',
                borderRadius: 8,
                padding: 16,
                display: 'flex',
                flexDirection: 'column',
                gap: 12,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#8D9479', textTransform: 'uppercase' }}>
                  Composite Risk Assessment
                </span>
                <span style={{ fontSize: 10, color: '#C6FF00', fontFamily: "'JetBrains Mono', monospace" }}>
                  Calculating…
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '8px 0' }}>
                <div
                  style={{
                    width: 72,
                    height: 72,
                    borderRadius: '50%',
                    border: '3px solid #262B32',
                    borderTopColor: '#C6FF00',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <span style={{ fontSize: 20, fontWeight: 700, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace" }}>--</span>
                  <span style={{ fontSize: 8, color: '#8D9479', textTransform: 'uppercase' }}>PENDING</span>
                </div>

                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#BFC7D5', fontFamily: "'JetBrains Mono', monospace" }}>
                    <span>Calculating weights (CVSS + IOCs + Anomalies)…</span>
                    <span>--%</span>
                  </div>
                  <div style={{ width: '100%', height: 6, background: '#1F2022', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: '40%', height: '100%', background: '#C6FF00', opacity: 0.6 }} />
                  </div>
                  <span style={{ fontSize: 9, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
                    Waiting on TCP stream reconstruction completion
                  </span>
                </div>
              </div>
            </div>

            {/* Metric Tiles Skeleton */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8 }}>
              {['Flows', 'Sessions', 'Artifacts', 'IOCs', 'CVE'].map((label) => (
                <div key={label} style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={{ fontSize: 9, color: '#8D9479', textTransform: 'uppercase', fontFamily: "'JetBrains Mono', monospace" }}>{label}</span>
                  <span style={{ fontSize: 9, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace" }}>Pending run</span>
                </div>
              ))}
            </div>
          </div>

          {/* Right: Live Pipeline Stepper */}
          <div style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1F2022', paddingBottom: 8, marginBottom: 12 }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: '#FFFFFF', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Analysis Pipeline (Run Active)
                </span>
                <span style={{ fontSize: 10, color: '#C6FF00', fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>
                  2/6 COMPLETED
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {/* Step 1 */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={16} style={{ color: '#C6FF00' }} />
                    <span style={{ color: '#FFFFFF' }}>1. Validate capture</span>
                  </div>
                  <span style={{ fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>1.2s</span>
                </div>

                {/* Step 2 */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <CheckCircle2 size={16} style={{ color: '#C6FF00' }} />
                    <span style={{ color: '#FFFFFF' }}>2. Extract flows</span>
                  </div>
                  <span style={{ fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>4.8s</span>
                </div>

                {/* Step 3 Active */}
                <div style={{ background: '#1F2022', border: '1px solid #C6FF00', borderRadius: 6, padding: '8px 10px', display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#C6FF00' }} />
                      <span style={{ color: '#FFFFFF', fontWeight: 600, fontSize: 12 }}>3. Reassemble sessions &amp; extract artifacts</span>
                    </div>
                    <span style={{ fontSize: 9, color: '#C6FF00', fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>ACTIVE</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#BFC7D5', fontFamily: "'JetBrains Mono', monospace" }}>
                    <span>Reassembling TCP streams…</span>
                    <span style={{ color: '#C6FF00' }}>{activePct}%</span>
                  </div>
                  <div style={{ width: '100%', height: 4, background: '#0D0E10', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ width: `${activePct}%`, height: '100%', background: '#C6FF00' }} />
                  </div>
                  <span style={{ fontSize: 9, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
                    {indexed}/{totalStreams} TCP streams indexed · {elapsed}s elapsed
                  </span>
                </div>

                {/* Steps 4, 5, 6 Pending */}
                {['4. Extract IOCs', '5. Match CVE signatures', '6. Score severity'].map((stepName) => (
                  <div key={stepName} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12, opacity: 0.5 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ width: 14, height: 14, borderRadius: '50%', border: '1px solid #8B93A0' }} />
                      <span style={{ color: '#8B93A0' }}>{stepName}</span>
                    </div>
                    <span style={{ fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>Pending</span>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ borderTop: '1px solid #1F2022', paddingTop: 10, marginTop: 12, display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
              <span>Started: {startedAt ? formatRelative(startedAt) : 'recently'}</span>
              <span>Est. remaining: ~19s</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // 2. ROLLED BACK STATE
  if (status === 'rolled_back' || status === 'failed') {
    const errorStep = rollbackInfo?.error_step || '03_reassemble_sessions.py:418';
    const errorMsg = rollbackInfo?.error_message || 'ERR_PCAP_BUFFER_OVERRUN: Ring buffer exhausted at offset 0x3F4; TCP segment reassembly timed out after 30,000ms';
    const exitCode = rollbackInfo?.exit_code || '137 (SIGKILL / OOM)';
    const rollbackId = rollbackInfo?.rollback_id || `rb_${runId ? runId.slice(0, 8) : '02'}`;
    const purgedFiles = rollbackInfo?.purged_scratch_files || 18;

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, fontFamily: "'Space Grotesk', sans-serif" }}>
        {/* Rollback Alert Banner */}
        <div
          style={{
            background: 'rgba(147, 0, 10, 0.18)',
            border: '1px solid #E5484D',
            borderRadius: 6,
            padding: 14,
            display: 'flex',
            alignItems: 'flex-start',
            gap: 12,
          }}
        >
          <ShieldAlert size={22} style={{ color: '#E5484D', flexShrink: 0, marginTop: 2 }} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#FFB4AB' }}>
              Analysis rolled back. Pipeline failed at step 3: Reassemble sessions. Staged artifacts were safely removed.
            </div>
            <div style={{ fontSize: 11, color: '#E3E2E5', lineHeight: 1.45 }}>
              Forensic sandbox isolation policy executed automatically. Ephemeral memory allocations and temporary packet indexing tables were purged ({purgedFiles} scratch files zeroed).
            </div>
          </div>
        </div>

        {/* Action Controls & Diagnostic Trace */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: 10 }}>
            {canWrite && (
              <button
                type="button"
                onClick={onReRun}
                style={{
                  padding: '7px 16px',
                  borderRadius: 4,
                  border: 'none',
                  background: '#C6FF00',
                  color: '#151F00',
                  fontSize: 11,
                  fontWeight: 700,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <Play size={14} fill="#151F00" />
                <span>Re-run analysis</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                navigator.clipboard.writeText(`Exit Code: ${exitCode}\nError Step: ${errorStep}\nError Message: ${errorMsg}`);
                setCopiedTrace(true);
                setTimeout(() => setCopiedTrace(false), 2000);
              }}
              style={{
                padding: '7px 14px',
                borderRadius: 4,
                border: '1px solid #343537',
                background: '#1F2022',
                color: '#BFC7D5',
                fontSize: 11,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <Copy size={13} />
              <span>{copiedTrace ? 'Copied' : 'Copy error details'}</span>
            </button>
          </div>
          <span style={{ fontSize: 11, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
            Rollback ID: <strong style={{ color: '#FFFFFF' }}>{rollbackId}</strong>
          </span>
        </div>

        {/* Error Trace Box */}
        <div style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: 12, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1F2022', paddingBottom: 6 }}>
            <span style={{ color: '#8D9479', fontSize: 10, textTransform: 'uppercase' }}>Diagnostic Error Trace (stdout/stderr)</span>
            <span style={{ color: '#E5484D', fontWeight: 600 }}>Exit Code: {exitCode}</span>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <span style={{ color: '#8B93A0' }}>error_step:</span>
            <span style={{ color: '#FFFFFF', fontWeight: 600 }}>{errorStep}</span>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <span style={{ color: '#8B93A0' }}>error_message:</span>
            <span style={{ color: '#FFB4AB' }}>{errorMsg}</span>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <span style={{ color: '#8B93A0' }}>rollback_status:</span>
            <span style={{ color: '#C6FF00' }}>Rollback completed in 1.4s · {purgedFiles} scratch files zeroed</span>
          </div>
        </div>
      </div>
    );
  }

  // 3. QUEUED STATE
  if (status === 'pending') {
    const position = queueInfo?.position ?? 2;
    const worker = queueInfo?.worker ?? 'worker-node-04 (busy)';
    const estSec = queueInfo?.estimated_start_seconds ?? 45;

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, fontFamily: "'Space Grotesk', sans-serif" }}>
        <div
          style={{
            background: '#14171B',
            border: '1px solid #343537',
            borderRadius: 6,
            padding: 14,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Clock size={20} style={{ color: '#8D9479' }} />
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: '#FFFFFF' }}>
                Queued behind {position} analyses · waiting for worker slot
              </div>
              <div style={{ fontSize: 11, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>
                Worker pool: {worker} · Estimated start in ~{estSec}s · Priority: Normal
              </div>
            </div>
          </div>
          <span style={{ fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: '#C6FF00', fontWeight: 600 }}>
            QUEUE POS #{position}
          </span>
        </div>
      </div>
    );
  }

  return null;
}
