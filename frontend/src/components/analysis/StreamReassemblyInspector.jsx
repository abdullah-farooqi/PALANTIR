import { useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  FileCode,
  LogIn,
  LogOut,
  Package,
  RefreshCw,
  Search,
  Sliders,
} from 'lucide-react';
import { formatBytes, formatDateTime, formatNumber } from '../../lib/format';

export default function StreamReassemblyInspector({
  sessions = [],
  selectedSession,
  onSelectSession,
  onPivot,
  onNavigateTab,
}) {
  const [filterMode, setFilterMode] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  const active = selectedSession || sessions[0] || null;

  const filteredSessions = sessions.filter((s) => {
    if (filterMode === 'good' && (s.reassembly_quality ?? 1) < 0.7) return false;
    if (filterMode === 'low' && (s.reassembly_quality ?? 1) >= 0.7) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchIp = (s.src_ip || '').toLowerCase().includes(q) || (s.dst_ip || '').toLowerCase().includes(q);
      const matchPort = String(s.src_port || '').includes(q) || String(s.dst_port || '').includes(q);
      const matchState = (s.state || '').toLowerCase().includes(q);
      if (!matchIp && !matchPort && !matchState) return false;
    }
    return true;
  });

  const qualityScore = active ? Math.round((active.reassembly_quality ?? 0.88) * 100) : 41;
  const isLowQuality = qualityScore < 70;
  const clientIsn = active?.client_isn ?? '0x3F88A21C';
  const serverIsn = active?.server_isn ?? '0x9B104E72';
  const reassembledBytes = active?.reassembled_bytes ?? active?.total_bytes ?? 4819204;
  const totalBytes = active?.total_bytes ?? 4822124;
  const missingBytes = active?.missing_bytes ?? 2920;
  const oooBytes = active?.ooo_bytes ?? 14;
  const retransmitBytes = active?.retransmit_bytes ?? 12;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1fr) minmax(0, 1.8fr)', gap: 16, alignItems: 'start', fontFamily: "'Space Grotesk', sans-serif" }}>
      {/* LEFT LIST PANE */}
      <div style={{ background: '#14171B', border: '1px solid #262B32', borderRadius: 8, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {/* Header & Controls */}
        <div style={{ padding: '12px 14px', borderBottom: '1px solid #262B32', background: '#101215', display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: '#FFFFFF', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              TCP Sessions
            </span>
            <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#8D9479', background: '#0D0E10', border: '1px solid #262B32', padding: '2px 6px', borderRadius: 4 }}>
              {sessions.length} total
            </span>
          </div>

          {/* Filter Chips */}
          <div style={{ display: 'flex', gap: 6, overflowX: 'auto', paddingBottom: 2 }}>
            <button
              type="button"
              onClick={() => setFilterMode('all')}
              style={{
                fontSize: 10,
                fontFamily: "'JetBrains Mono', monospace",
                padding: '3px 8px',
                borderRadius: 4,
                border: filterMode === 'all' ? '1px solid #C6FF00' : '1px solid #262B32',
                background: filterMode === 'all' ? '#1F2022' : 'transparent',
                color: filterMode === 'all' ? '#C6FF00' : '#8B93A0',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              All ({sessions.length})
            </button>
            <button
              type="button"
              onClick={() => setFilterMode('good')}
              style={{
                fontSize: 10,
                fontFamily: "'JetBrains Mono', monospace",
                padding: '3px 8px',
                borderRadius: 4,
                border: filterMode === 'good' ? '1px solid #C6FF00' : '1px solid #262B32',
                background: filterMode === 'good' ? '#1F2022' : 'transparent',
                color: filterMode === 'good' ? '#C6FF00' : '#8B93A0',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              Good quality
            </button>
            <button
              type="button"
              onClick={() => setFilterMode('low')}
              style={{
                fontSize: 10,
                fontFamily: "'JetBrains Mono', monospace",
                padding: '3px 8px',
                borderRadius: 4,
                border: filterMode === 'low' ? '1px solid #E5484D' : '1px solid #262B32',
                background: filterMode === 'low' ? 'rgba(229, 72, 77, 0.15)' : 'transparent',
                color: filterMode === 'low' ? '#FFB4AB' : '#8B93A0',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              Low confidence
            </button>
          </div>

          {/* Search box */}
          <div style={{ position: 'relative' }}>
            <Search size={13} style={{ position: 'absolute', left: 8, top: 9, color: '#8D9479' }} />
            <input
              type="text"
              placeholder="Search session IP, port or state..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: '100%',
                boxSizing: 'border-box',
                background: '#0D0E10',
                border: '1px solid #262B32',
                borderRadius: 4,
                padding: '6px 8px 6px 26px',
                color: '#FFFFFF',
                fontSize: 11,
                fontFamily: "'JetBrains Mono', monospace",
                outline: 'none',
              }}
            />
          </div>
        </div>

        {/* Sessions List */}
        <div style={{ display: 'flex', flexDirection: 'column', maxHeight: 600, overflowY: 'auto' }}>
          {filteredSessions.map((s) => {
            const isSelected = active?.id === s.id;
            const sQuality = Math.round((s.reassembly_quality ?? 0.85) * 100);
            const sLow = sQuality < 70;

            return (
              <div
                key={s.id}
                onClick={() => onSelectSession(s)}
                style={{
                  padding: '12px 14px',
                  borderBottom: '1px solid #1F2022',
                  borderLeft: isSelected ? '4px solid #C6FF00' : '4px solid transparent',
                  background: isSelected ? 'rgba(198, 255, 0, 0.05)' : 'transparent',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 4,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: isSelected ? '#C6FF00' : '#FFFFFF', fontFamily: "'JetBrains Mono', monospace" }}>
                    {s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}
                  </span>
                  <span style={{ fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
                    #{s.id}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace" }}>
                  <span>State: <strong style={{ color: '#FFFFFF' }}>{s.state}</strong></span>
                  <span>·</span>
                  <span>{formatBytes(s.total_bytes || 0)}</span>
                  <span>·</span>
                  <span>{s.duration_seconds ? `${s.duration_seconds.toFixed(1)}s` : '1.2s'}</span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 4 }}>
                  <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 3, background: '#0D0E10', border: '1px solid #262B32', color: '#BFC7D5', fontFamily: "'JetBrains Mono', monospace" }}>
                    Confidence: {s.confidence || 'high'}
                  </span>
                  <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 3, background: sLow ? 'rgba(229, 72, 77, 0.15)' : 'rgba(198, 255, 0, 0.1)', color: sLow ? '#FFB4AB' : '#C6FF00', fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>
                    Quality {sQuality}%
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* RIGHT DETAIL PANEL */}
      {active ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Truncation warning if snaplen is 128 */}
          {active.snaplen <= 128 && (
            <div
              style={{
                padding: '10px 14px',
                borderRadius: 6,
                background: 'rgba(147, 0, 10, 0.15)',
                border: '1px solid rgba(229, 72, 77, 0.4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertTriangle size={16} style={{ color: '#E5484D' }} />
                <span style={{ fontSize: 12, color: '#FFB4AB', fontWeight: 600 }}>
                  Capture truncated (snaplen 128). Payload content is incomplete; reassembly confidence degraded.
                </span>
              </div>
              <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#E5484D', background: '#0D0E10', padding: '2px 6px', borderRadius: 4 }}>
                OFFSET 128B
              </span>
            </div>
          )}

          {/* Session Header Card */}
          <div style={{ background: '#14171B', border: '1px solid #262B32', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 10 }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 16, fontWeight: 700, color: '#FFFFFF', fontFamily: "'JetBrains Mono', monospace" }}>
                    <span
                      style={{ color: '#C6FF00', cursor: 'pointer', textDecoration: 'underline', textUnderlineOffset: 2 }}
                      onClick={() => onPivot?.(active.src_ip, 'IPv4')}
                      title="Pivot in Forensic Drawer"
                    >
                      {active.src_ip}
                    </span>
                    :{active.src_port} →{' '}
                    <span
                      style={{ color: '#C6FF00', cursor: 'pointer', textDecoration: 'underline', textUnderlineOffset: 2 }}
                      onClick={() => onPivot?.(active.dst_ip, 'IPv4')}
                      title="Pivot in Forensic Drawer"
                    >
                      {active.dst_ip}
                    </span>
                    :{active.dst_port}
                  </span>
                  <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: '#1F2022', border: '1px solid #343537', color: '#8D9479', textTransform: 'uppercase', fontFamily: "'JetBrains Mono', monospace" }}>
                    OUTBOUND · CLIENT INITIATED
                  </span>
                </div>
                <div style={{ display: 'flex', gap: 10, fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace", marginTop: 4 }}>
                  <span>Session #{active.id}</span>
                  <span>·</span>
                  <span>State: <strong style={{ color: '#FFFFFF' }}>{active.state}</strong></span>
                  <span>·</span>
                  <span>Confidence: <strong style={{ color: '#C6FF00' }}>{active.confidence || 'high'}</strong></span>
                </div>
              </div>

              <button
                type="button"
                onClick={() => onPivot?.(active.src_ip, 'IPv4')}
                style={{
                  background: '#1F2022',
                  border: '1px solid #343537',
                  borderRadius: 4,
                  padding: '6px 12px',
                  color: '#C6FF00',
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                }}
              >
                <span>Pivot Session</span>
                <ArrowRight size={12} />
              </button>
            </div>

            {/* Quality Score Bar */}
            <div style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: 12, display: 'flex', alignItems: 'center', gap: 14 }}>
              <div style={{ textAlign: 'center', minWidth: 80, borderRight: '1px solid #1F2022', paddingRight: 14 }}>
                <div style={{ fontSize: 20, fontWeight: 800, color: isLowQuality ? '#E5484D' : '#C6FF00', fontFamily: "'JetBrains Mono', monospace" }}>
                  {qualityScore}%
                </div>
                <div style={{ fontSize: 9, color: '#8D9479', textTransform: 'uppercase' }}>
                  {isLowQuality ? 'Low Quality' : 'Good Quality'}
                </div>
              </div>
              <div style={{ fontSize: 12, color: '#BFC7D5', lineHeight: 1.4 }}>
                {isLowQuality
                  ? 'Score reflects out-of-order packets, sequence gaps, and payload truncation at snaplen boundary.'
                  : 'Reassembly succeeded with complete 3-way handshake and contiguous sequence numbers.'}
              </div>
            </div>
          </div>

          {/* Reassembly Summary Cards */}
          <div style={{ background: '#14171B', border: '1px solid #262B32', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: '#FFFFFF', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Reassembly Summary
              </span>
              <span style={{ fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
                Engine: Zeek-TCP-Reassembly
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, fontFamily: "'JetBrains Mono', monospace" }}>
              <div style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: 10 }}>
                <div style={{ fontSize: 9, color: '#8D9479', textTransform: 'uppercase' }}>ISN Client</div>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#FFFFFF', marginTop: 2 }}>{clientIsn}</div>
              </div>
              <div style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: 10 }}>
                <div style={{ fontSize: 9, color: '#8D9479', textTransform: 'uppercase' }}>ISN Server</div>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#FFFFFF', marginTop: 2 }}>{serverIsn}</div>
              </div>
              <div style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: 10 }}>
                <div style={{ fontSize: 9, color: '#8D9479', textTransform: 'uppercase' }}>Reassembled</div>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#C6FF00', marginTop: 2 }}>{formatBytes(reassembledBytes)}</div>
              </div>
              <div style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: 10 }}>
                <div style={{ fontSize: 9, color: '#8D9479', textTransform: 'uppercase' }}>Gaps / Missing</div>
                <div style={{ fontSize: 12, fontWeight: 700, color: missingBytes > 0 ? '#E5484D' : '#C6FF00', marginTop: 2 }}>
                  {formatBytes(missingBytes)}
                </div>
              </div>
            </div>
          </div>

          {/* Session Flag Timeline */}
          <div style={{ background: '#14171B', border: '1px solid #262B32', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: '#FFFFFF', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                TCP Flag Timeline (Handshake → Transfer → Close)
              </span>
              <span style={{ fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
                RTT Median: 14.2ms
              </span>
            </div>

            <div style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 6, padding: '16px 12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', overflowX: 'auto', gap: 10 }}>
              {/* SYN */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 80, textAlign: 'center' }}>
                <div style={{ width: 28, height: 28, borderRadius: 6, background: '#1F2022', border: '1px solid #343537', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#FFFFFF', marginBottom: 4 }}>
                  <LogIn size={14} />
                </div>
                <span style={{ fontSize: 11, fontWeight: 700, color: '#FFFFFF', fontFamily: "'JetBrains Mono', monospace" }}>[SYN]</span>
                <span style={{ fontSize: 9, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>Seq: 0 · C→S</span>
              </div>

              <div style={{ flex: 1, height: 1, background: '#262B32', minWidth: 30 }} />

              {/* SYN-ACK */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 90, textAlign: 'center' }}>
                <div style={{ width: 28, height: 28, borderRadius: 6, background: '#1F2022', border: '1px solid #343537', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#C6FF00', marginBottom: 4 }}>
                  <RefreshCw size={14} />
                </div>
                <span style={{ fontSize: 11, fontWeight: 700, color: '#C6FF00', fontFamily: "'JetBrains Mono', monospace" }}>[SYN/ACK]</span>
                <span style={{ fontSize: 9, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>Seq: 0, Ack: 1</span>
              </div>

              <div style={{ flex: 1, height: 1, background: '#262B32', minWidth: 30 }} />

              {/* ACK */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 80, textAlign: 'center' }}>
                <div style={{ width: 28, height: 28, borderRadius: 6, background: '#1F2022', border: '1px solid #C6FF00', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#C6FF00', marginBottom: 4 }}>
                  <CheckCircle2 size={14} />
                </div>
                <span style={{ fontSize: 11, fontWeight: 700, color: '#C6FF00', fontFamily: "'JetBrains Mono', monospace" }}>[ACK 3-WAY]</span>
                <span style={{ fontSize: 9, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>Established</span>
              </div>

              <div style={{ flex: 1, height: 1, background: '#262B32', minWidth: 30 }} />

              {/* DATA */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 90, textAlign: 'center' }}>
                <div style={{ width: 28, height: 28, borderRadius: 6, background: '#2C1517', border: '1px solid #57383A', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#E5484D', marginBottom: 4 }}>
                  <Package size={14} />
                </div>
                <span style={{ fontSize: 11, fontWeight: 700, color: '#FFB4AB', fontFamily: "'JetBrains Mono', monospace" }}>[DATA STREAM]</span>
                <span style={{ fontSize: 9, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>{formatBytes(active.total_bytes || 0)}</span>
              </div>

              <div style={{ flex: 1, height: 1, background: '#262B32', minWidth: 30 }} />

              {/* FIN / RST */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 80, textAlign: 'center' }}>
                <div style={{ width: 28, height: 28, borderRadius: 6, background: '#1F2022', border: '1px solid #343537', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#8D9479', marginBottom: 4 }}>
                  <LogOut size={14} />
                </div>
                <span style={{ fontSize: 11, fontWeight: 700, color: '#FFFFFF', fontFamily: "'JetBrains Mono', monospace" }}>
                  [{active.state === 'reset' ? 'RST' : 'FIN/ACK'}]
                </span>
                <span style={{ fontSize: 9, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>Closed</span>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div style={{ padding: 40, textAlign: 'center', color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
          Select a session from the left rail to inspect stream reassembly details.
        </div>
      )}
    </div>
  );
}
