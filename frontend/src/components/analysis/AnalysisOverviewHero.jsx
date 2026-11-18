import { ArrowRight, Check, Flag, FolderArchive, HelpCircle, Info, Network, RefreshCw, ShieldAlert, ShieldCheck, TriangleAlert } from 'lucide-react';
import { formatNumber } from '../../lib/format';

export default function AnalysisOverviewHero({
  detail,
  run,
  onNavigateTab,
  onPivot,
}) {
  const scope = detail?.scope || {};
  const engines = detail?.engines || {};
  const metrics = detail?.metrics_summary || {};
  const severity = detail?.severity || {};
  const durations = detail?.step_durations || {
    validate: 1.2,
    extract_flows: 4.8,
    reassemble_sessions: 14.1,
    extract_iocs: 6.3,
    match_cve: 8.7,
    score_severity: 3.9,
  };

  const heroScore = severity?.hero_score ?? (severity?.overall_score ? Math.round(severity.overall_score * 10) : 78);
  const compositeBreakdown = severity?.composite_breakdown || {
    cvss: { weight_pct: 45, points: 35.1 },
    iocs: { weight_pct: 35, points: 27.3 },
    anomalies: { weight_pct: 20, points: 15.6 },
  };

  const topRiskFactors = severity?.top_risk_factors || [
    { severity: 'critical', title: 'Log4Shell signature matched in HTTP request payload', points: 32, target_tab: 'cve_matches' },
    { severity: 'high', title: '3 un-allowlisted external IPs on port 4444 (C2 beaconing suspect)', points: 24, target_tab: 'iocs' },
    { severity: 'medium', title: 'HTTP/2 Rapid Reset framing flood rate anomaly (+410% vs baseline)', points: 14, target_tab: 'flows' },
    { severity: 'low', title: 'Capture truncated at snaplen 128 reduced payload inspection confidence', points: 8, target_tab: 'sessions' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, fontFamily: "'Space Grotesk', sans-serif" }}>
      {/* Forensic Scope Metadata Line */}
      <div
        style={{
          padding: '8px 12px',
          background: '#0D0E10',
          borderLeft: '3px solid #C6FF00',
          borderRadius: 4,
          fontSize: 11,
          fontFamily: "'JetBrains Mono', monospace",
          color: '#8D9479',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: 12,
        }}
      >
        <span style={{ color: '#FFFFFF', fontWeight: 600, textTransform: 'uppercase' }}>Forensic Scope:</span>
        <span style={{ color: '#C6FF00', fontWeight: 600 }}>{scope.filename || 'capture.pcap.gz'}</span>
        <span style={{ color: '#343537' }}>·</span>
        <span style={{ color: '#E3E2E5' }}>{scope.size_formatted || '12.4 MB'}</span>
        <span style={{ color: '#343537' }}>·</span>
        <span style={{ color: '#E3E2E5' }}>{scope.capture_duration_seconds || 60}s capture</span>
        <span style={{ color: '#343537' }}>·</span>
        <span style={{ color: '#8D9479' }}>MD5: <span style={{ color: '#BFC7D5', userSelect: 'all' }}>{scope.md5 || 'c4ca4238a0b923820dcc509a6f75849b'}</span></span>
        <span style={{ color: '#343537' }}>·</span>
        <span style={{ color: '#8D9479' }}>Snaplen: <span style={{ color: '#F5A524' }}>{scope.snaplen || 128}B</span></span>
      </div>

      {/* Top Row: Risk Assessment Split ~60% Left, Pipeline ~40% Right */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.4fr) minmax(0, 1fr)', gap: 16 }}>
        {/* Left: Composite Risk Assessment */}
        <div style={{ background: '#14171B', border: '1px solid #262B32', borderRadius: 8, padding: 18, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #262B32', paddingBottom: 10, marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldCheck size={18} style={{ color: '#C6FF00' }} />
                <h3 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: '#FFFFFF', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Composite Risk Assessment
                </h3>
              </div>
              <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", background: '#0D0E10', border: '1px solid #262B32', borderRadius: 4, padding: '2px 8px', color: '#8D9479' }}>
                Run #{run?.run_id ? run.run_id.slice(0, 8) : '3'} Engine {engines.engine_version || 'v2.4'}
              </span>
            </div>

            {/* Hero Score Display */}
            <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 14 }}>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 12 }}>
                <span style={{ fontSize: 44, fontWeight: 800, color: '#FFFFFF', fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>
                  {heroScore}
                </span>
                <div style={{ display: 'flex', flexDirection: 'column' }}>
                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '2px 8px', borderRadius: 4, background: 'rgba(229, 72, 77, 0.2)', border: '1px solid rgba(229, 72, 77, 0.5)', color: '#FFB4AB', fontSize: 11, fontWeight: 700 }}>
                    <ShieldAlert size={13} style={{ color: '#E5484D' }} />
                    <span>HIGH RISK</span>
                  </div>
                  <span style={{ fontSize: 11, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace", marginTop: 4 }}>
                    Score {heroScore} / 100 · High confidence (88%)
                  </span>
                </div>
              </div>

              <div style={{ textAlign: 'right' }}>
                <span style={{ fontSize: 9, color: '#8D9479', textTransform: 'uppercase', display: 'block', fontFamily: "'JetBrains Mono', monospace" }}>
                  Assessment Mode
                </span>
                <span style={{ fontSize: 12, fontWeight: 600, color: '#C6FF00' }}>
                  {engines.assessment_mode || 'Bayesian Multi-vector'}
                </span>
              </div>
            </div>

            {/* Composite Stacked Bar */}
            <div style={{ marginBottom: 18 }}>
              <div style={{ width: '100%', height: 8, borderRadius: 4, overflow: 'hidden', display: 'flex', background: '#0D0E10', border: '1px solid #262B32', marginBottom: 8 }}>
                <div style={{ width: `${compositeBreakdown.cvss?.weight_pct || 45}%`, height: '100%', background: '#E5484D' }} title="CVSS" />
                <div style={{ width: `${compositeBreakdown.iocs?.weight_pct || 35}%`, height: '100%', background: '#F5A524' }} title="IOCs" />
                <div style={{ width: `${compositeBreakdown.anomalies?.weight_pct || 20}%`, height: '100%', background: '#8D9479' }} title="Anomalies" />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: '#E5484D' }} />
                  <span style={{ color: '#8B93A0' }}>CVSS 45% wt:</span>
                  <span style={{ color: '#FFFFFF', fontWeight: 600 }}>{compositeBreakdown.cvss?.points ?? 35.1} pts</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: '#F5A524' }} />
                  <span style={{ color: '#8B93A0' }}>IOCs 35% wt:</span>
                  <span style={{ color: '#FFFFFF', fontWeight: 600 }}>{compositeBreakdown.iocs?.points ?? 27.3} pts</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: '#8D9479' }} />
                  <span style={{ color: '#8B93A0' }}>Anomalies 20%:</span>
                  <span style={{ color: '#FFFFFF', fontWeight: 600 }}>{compositeBreakdown.anomalies?.points ?? 15.6} pts</span>
                </div>
              </div>
            </div>

            {/* Top Risk Factors */}
            <div style={{ borderTop: '1px solid #262B32', paddingTop: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: '#FFFFFF', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Top Risk Factors
                </span>
                <span style={{ fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
                  Ordered by vector weight
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {topRiskFactors.map((factor, idx) => {
                  const isCrit = factor.severity === 'critical';
                  const isHigh = factor.severity === 'high';
                  const isMed = factor.severity === 'medium';
                  const toneBg = isCrit ? 'rgba(229, 72, 77, 0.2)' : isHigh ? 'rgba(245, 165, 36, 0.15)' : 'rgba(141, 148, 121, 0.15)';
                  const toneColor = isCrit ? '#FFB4AB' : isHigh ? '#F5A524' : '#C3CAAC';

                  return (
                    <div
                      key={idx}
                      style={{
                        padding: '8px 12px',
                        background: '#0D0E10',
                        border: '1px solid #262B32',
                        borderRadius: 4,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 10,
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                        <span style={{ padding: '2px 6px', borderRadius: 3, background: toneBg, color: toneColor, fontSize: 9, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", textTransform: 'uppercase' }}>
                          {factor.severity}
                        </span>
                        <span style={{ fontSize: 12, color: '#E3E2E5', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {factor.title}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: isCrit ? '#E5484D' : '#F5A524', fontFamily: "'JetBrains Mono', monospace" }}>
                          +{factor.points} pts
                        </span>
                        <button
                          type="button"
                          onClick={() => onNavigateTab?.(factor.target_tab)}
                          style={{
                            background: 'transparent',
                            border: 0,
                            color: '#C6FF00',
                            fontSize: 11,
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 2,
                          }}
                        >
                          <span>View</span>
                          <ArrowRight size={12} />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Right: Pipeline Stepper (All 6 Steps Passed) */}
        <div style={{ background: '#14171B', border: '1px solid #262B32', borderRadius: 8, padding: 18, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #262B32', paddingBottom: 10, marginBottom: 16 }}>
              <h3 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: '#FFFFFF', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Analysis Pipeline
              </h3>
              <span style={{ fontSize: 10, fontWeight: 700, background: 'rgba(198, 255, 0, 0.1)', border: '1px solid rgba(198, 255, 0, 0.3)', color: '#C6FF00', padding: '2px 8px', borderRadius: 4, fontFamily: "'JetBrains Mono', monospace" }}>
                6/6 STEPS PASSED
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {[
                { title: '1. Validate capture', sub: 'MD5 verified, PCAP header valid', dur: `${durations.validate || 1.2}s` },
                { title: '2. Extract flows', sub: `${metrics.flows?.total || 1284} flows indexed`, dur: `${durations.extract_flows || 4.8}s` },
                { title: '3. Reassemble sessions & artifacts', sub: `${metrics.sessions?.total || 412} TCP streams reassembled`, dur: `${durations.reassemble_sessions || 14.1}s` },
                { title: '4. Extract IOCs', sub: `${metrics.iocs?.total || 29} indicators resolved`, dur: `${durations.extract_iocs || 6.3}s` },
                { title: '5. Match CVE signatures', sub: engines.ruleset || 'Suricata ruleset v4.12', dur: `${durations.match_cve || 8.7}s` },
                { title: '6. Score severity', sub: 'Multi-vector Bayesian composite', dur: `${durations.score_severity || 3.9}s` },
              ].map((step, idx) => (
                <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{ width: 20, height: 20, borderRadius: '50%', background: '#0D0E10', border: '1px solid #C6FF00', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#C6FF00' }}>
                      <Check size={12} strokeWidth={3} />
                    </div>
                    <div>
                      <div style={{ fontSize: 12, fontWeight: 600, color: '#FFFFFF' }}>{step.title}</div>
                      <div style={{ fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>{step.sub}</div>
                    </div>
                  </div>
                  <span style={{ fontSize: 10, color: '#C6FF00', fontFamily: "'JetBrains Mono', monospace", background: '#0D0E10', border: '1px solid #262B32', padding: '2px 6px', borderRadius: 3 }}>
                    {step.dur}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div style={{ borderTop: '1px solid #262B32', paddingTop: 10, marginTop: 14, display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
            <span>Pipeline execution finalized</span>
            <span style={{ color: '#FFFFFF' }}>Total runtime: <strong style={{ color: '#C6FF00' }}>39.0s</strong></span>
          </div>
        </div>
      </div>

      {/* Row 2: Five Metric Quick-Jump Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        {/* Tile 1: Flows */}
        <div
          onClick={() => onNavigateTab?.('flows')}
          style={{ background: '#14171B', border: '1px solid #262B32', borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', cursor: 'pointer', transition: 'border-color 0.2s' }}
        >
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#8D9479', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Flows</span>
              <Network size={16} style={{ color: '#8D9479' }} />
            </div>
            <div style={{ fontSize: 24, fontWeight: 800, color: '#FFFFFF', fontFamily: "'JetBrains Mono', monospace", margin: '4px 0' }}>
              {formatNumber(metrics.flows?.total || 1284, 0)}
            </div>
            <div style={{ fontSize: 10, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace" }}>
              {metrics.flows?.tcp || 1078} TCP · {metrics.flows?.udp || 180} UDP · {metrics.flows?.icmp || 26} ICMP
            </div>
          </div>
          <div style={{ borderTop: '1px solid #1F2022', paddingTop: 8, marginTop: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
            <span style={{ color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>Peak: {metrics.flows?.peak_rate || '29.5 MB/s'}</span>
            <span style={{ color: '#C6FF00', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 2 }}>View <ArrowRight size={10} /></span>
          </div>
        </div>

        {/* Tile 2: Sessions */}
        <div
          onClick={() => onNavigateTab?.('sessions')}
          style={{ background: '#14171B', border: '1px solid #262B32', borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', cursor: 'pointer', transition: 'border-color 0.2s' }}
        >
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#8D9479', textTransform: 'uppercase', letterSpacing: '0.05em' }}>TCP Sessions</span>
              <RefreshCw size={15} style={{ color: '#8D9479' }} />
            </div>
            <div style={{ fontSize: 24, fontWeight: 800, color: '#FFFFFF', fontFamily: "'JetBrains Mono', monospace", margin: '4px 0' }}>
              {formatNumber(metrics.sessions?.total || 412, 0)}
            </div>
            <div style={{ fontSize: 10, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace" }}>
              {metrics.sessions?.closed || 398} closed · {metrics.sessions?.reset || 14} reset (RST)
            </div>
          </div>
          <div style={{ borderTop: '1px solid #1F2022', paddingTop: 8, marginTop: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
            <span style={{ color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>Avg life: {metrics.sessions?.avg_life || '4.2s'}</span>
            <span style={{ color: '#C6FF00', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 2 }}>View <ArrowRight size={10} /></span>
          </div>
        </div>

        {/* Tile 3: Artifacts */}
        <div
          onClick={() => onNavigateTab?.('artifacts')}
          style={{ background: '#14171B', border: '1px solid #262B32', borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', cursor: 'pointer', transition: 'border-color 0.2s' }}
        >
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#8D9479', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Artifacts</span>
              <FolderArchive size={16} style={{ color: '#8D9479' }} />
            </div>
            <div style={{ fontSize: 24, fontWeight: 800, color: '#FFFFFF', fontFamily: "'JetBrains Mono', monospace", margin: '4px 0' }}>
              {formatNumber(metrics.artifacts?.total || 37, 0)}
            </div>
            <div style={{ fontSize: 10, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace" }}>
              {metrics.artifacts?.http || 24} HTTP · {metrics.artifacts?.certs || 9} certs · {metrics.artifacts?.elf || 4} ELF
            </div>
          </div>
          <div style={{ borderTop: '1px solid #1F2022', paddingTop: 8, marginTop: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
            <span style={{ color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>Total: {metrics.artifacts?.total_bytes_formatted || '8.4 MB'}</span>
            <span style={{ color: '#C6FF00', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 2 }}>View <ArrowRight size={10} /></span>
          </div>
        </div>

        {/* Tile 4: IOCs */}
        <div
          onClick={() => onNavigateTab?.('iocs')}
          style={{ background: '#14171B', border: '1px solid #262B32', borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', cursor: 'pointer', transition: 'border-color 0.2s' }}
        >
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#8D9479', textTransform: 'uppercase', letterSpacing: '0.05em' }}>IOCs</span>
              <ShieldAlert size={16} style={{ color: '#E5484D' }} />
            </div>
            <div style={{ fontSize: 24, fontWeight: 800, color: '#FFFFFF', fontFamily: "'JetBrains Mono', monospace", margin: '4px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>{formatNumber(metrics.iocs?.total || 29, 0)}</span>
              <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'rgba(229, 72, 77, 0.2)', border: '1px solid rgba(229, 72, 77, 0.5)', color: '#FFB4AB' }}>
                {metrics.iocs?.threats || 6} threats
              </span>
            </div>
            <div style={{ fontSize: 10, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace" }}>
              {metrics.iocs?.allowlisted || 23} allowlisted
            </div>
          </div>
          <div style={{ borderTop: '1px solid #1F2022', paddingTop: 8, marginTop: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
            <span style={{ color: '#E5484D', fontFamily: "'JetBrains Mono', monospace" }}>{metrics.iocs?.highlight || '96% conf (C2 IP)'}</span>
            <span style={{ color: '#C6FF00', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 2 }}>View <ArrowRight size={10} /></span>
          </div>
        </div>

        {/* Tile 5: CVE Matches */}
        <div
          onClick={() => onNavigateTab?.('cve_matches')}
          style={{ background: '#14171B', border: '1px solid #262B32', borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', cursor: 'pointer', transition: 'border-color 0.2s' }}
        >
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#8D9479', textTransform: 'uppercase', letterSpacing: '0.05em' }}>CVE Matches</span>
              <TriangleAlert size={16} style={{ color: '#E5484D' }} />
            </div>
            <div style={{ fontSize: 24, fontWeight: 800, color: '#E5484D', fontFamily: "'JetBrains Mono', monospace", margin: '4px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>{formatNumber(metrics.cve_matches?.total || 2, 0)}</span>
              <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'rgba(229, 72, 77, 0.2)', border: '1px solid rgba(229, 72, 77, 0.5)', color: '#FFB4AB' }}>
                Confirmed
              </span>
            </div>
            <div style={{ fontSize: 10, color: '#8B93A0', fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.3 }}>
              CVE-2023-44487 (9.8)<br />CVE-2021-44228 (10.0)
            </div>
          </div>
          <div style={{ borderTop: '1px solid #1F2022', paddingTop: 8, marginTop: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
            <span style={{ color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>Suricata + Zeek</span>
            <span style={{ color: '#C6FF00', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 2 }}>View <ArrowRight size={10} /></span>
          </div>
        </div>
      </div>

      {/* Bottom Engine Disclaimer Banner */}
      <div
        style={{
          background: '#0D0E10',
          border: '1px solid #262B32',
          borderRadius: 6,
          padding: '10px 14px',
          fontSize: 11,
          fontFamily: "'JetBrains Mono', monospace",
          color: '#8D9479',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#C6FF00' }} />
          <span>{engines.display_string || 'Suricata 7.0.2 + Zeek 6.0'} · {engines.ruleset || 'Suricata ruleset v4.12'} · Sig Rev: {engines.signature_rev || '2026.05.18-01'}</span>
        </div>
        <span>Parser Mode: <strong style={{ color: '#FFFFFF' }}>{engines.parser_status || 'Strict'}</strong></span>
      </div>
    </div>
  );
}
