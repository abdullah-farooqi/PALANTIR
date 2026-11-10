import React, { memo, useMemo, useState } from 'react';
import { formatNetworkSpeed, formatBytes } from '../lib/format';

// Static Icon Primitives (SVG Vector only)
const IconAlertTriangle = memo(() => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
    <line x1="12" y1="9" x2="12" y2="13" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
));

const IconCross = memo(() => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <circle cx="12" cy="12" r="10" />
    <line x1="15" y1="9" x2="9" y2="15" />
    <line x1="9" y1="9" x2="15" y2="15" />
  </svg>
));

// MOCK DATA: Continuous Network Flows & Threat Signatures
const DEFAULT_FLOWS = [
  { id: 'FL-9021', proto: 'TCP', src: '192.168.1.104:49152', dst: '10.0.4.15:443', pkts: '482,104', bytes: '684.2 MB', status: 'ESTABLISHED', sev: 'info' },
  { id: 'FL-9022', proto: 'UDP', src: '192.168.1.12:53', dst: '1.1.1.1:53', pkts: '14,291', bytes: '1.8 MB', status: 'COMPLETED', sev: 'info' },
  { id: 'FL-9023', proto: 'TCP', src: '10.0.2.88:445', dst: '10.0.1.4:445', pkts: '104,821', bytes: '128.4 MB', status: 'ANOMALOUS SMB', sev: 'crit' },
  { id: 'FL-9024', proto: 'TCP', src: '10.0.1.4:8080', dst: '198.51.100.42:80', pkts: '6,119', bytes: '4.1 MB', status: 'BEACON SPURT', sev: 'med' },
  { id: 'FL-9025', proto: 'ICMP', src: '192.168.1.1:0', dst: '192.168.1.104:0', pkts: '320', bytes: '28 KB', status: 'ROUTINE ECHO', sev: 'info' },
  { id: 'FL-9026', proto: 'TLS', src: '10.0.3.19:51200', dst: '140.82.112.4:443', pkts: '32,190', bytes: '19.4 MB', status: 'ESTABLISHED', sev: 'info' },
  { id: 'FL-9027', proto: 'SSH', src: '192.168.1.99:58300', dst: '10.0.1.2:22', pkts: '8,410', bytes: '3.2 MB', status: 'SESSION ACTIVE', sev: 'info' },
];

const DEFAULT_ALERTS = [
  { id: 'ALT-101', time: '09:12:01', rule: 'Lateral SMB Relay (CVE-2020-1472)', target: '10.0.1.4:445', sev: 'crit', detail: 'Exploitation attempt detected via Zerologon signature' },
  { id: 'ALT-102', time: '09:08:44', rule: 'DNS Exfiltration Burst > 50kbps', target: '10.0.1.8:53', sev: 'med', detail: 'High entropy queries detected against unauthorized resolver' },
  { id: 'ALT-103', time: '08:59:12', rule: 'SSH Authentication Spray (22 targets)', target: '10.0.2.14:22', sev: 'med', detail: 'Rapid consecutive authentication failures from single subnet' },
];

export default function ObservabilityTab({ nodes = [], searchFilter = '', onSelectNode, onChangeView }) {
  const [selectedFlow, setSelectedFlow] = useState(null);

  // Derived filtered items (Vercel React Best Practices: avoid sync useState in useEffect)
  const filteredFlows = useMemo(() => {
    if (!searchFilter.trim()) return DEFAULT_FLOWS;
    const q = searchFilter.toLowerCase();
    return DEFAULT_FLOWS.filter(
      (f) =>
        f.src.toLowerCase().includes(q) ||
        f.dst.toLowerCase().includes(q) ||
        f.status.toLowerCase().includes(q) ||
        f.proto.toLowerCase().includes(q)
    );
  }, [searchFilter]);

  // Aggregate fleet reachability counts
  const fleetOnline = useMemo(() => nodes.filter((n) => n.reachability === 'reachable').length, [nodes]);

  return (
    <div className="flex flex-col gap-4">
      {/* 1. Hero KPI Bar: Exactly ONE hero metric receives lime spotlight */}
      <section className="grid grid-cols-1 md:grid-cols-4 gap-3" aria-label="Ingest Metrics Summary">
        {/* LOUD LIME: Reserved for the single most critical throughput metric */}
        <div className="bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-col justify-between">
          <span className="font-mono text-xs text-[#8B93A0] uppercase tracking-wider">
            HERO: Aggregated Ingest Throughput
          </span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="font-mono text-3xl font-extrabold text-[#C6FF00] tracking-tight">
              48.24
            </span>
            <span className="font-mono text-sm font-bold text-[#8B93A0]">Gbps</span>
          </div>
          <span className="font-mono text-[11px] text-[#656C77] mt-2">
            Peak: 54.10 Gbps | Real-time 1s sliding delta
          </span>
        </div>

        <div className="bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-col justify-between">
          <span className="font-mono text-xs text-[#8B93A0] uppercase tracking-wider">
            Active Monitored Hosts
          </span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="font-mono text-3xl font-bold text-[#E8EAED]">
              {nodes.length > 0 ? `${fleetOnline} / ${nodes.length}` : '5 Active'}
            </span>
            <span className="font-mono text-xs text-[#8B93A0]">Nodes</span>
          </div>
          <span className="font-mono text-[11px] text-[#656C77] mt-2">
            Zero missed heartbeat intervals
          </span>
        </div>

        <div className="bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-col justify-between">
          <span className="font-mono text-xs text-[#8B93A0] uppercase tracking-wider">
            Concurrent Socket Sessions
          </span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="font-mono text-3xl font-bold text-[#E8EAED]">1,842,910</span>
          </div>
          <span className="font-mono text-[11px] text-[#656C77] mt-2">
            Kernel packet drop rate: 0.0001%
          </span>
        </div>

        <div className="bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-col justify-between">
          <span className="font-mono text-xs text-[#8B93A0] uppercase tracking-wider">
            Correlated Incident Alerts
          </span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="font-mono text-3xl font-bold text-[#FFA4A7]">
              {DEFAULT_ALERTS.length} Triggered
            </span>
          </div>
          <span className="font-mono text-[11px] text-[#656C77] mt-2">
            1 Critical CVE, 2 Medium Anomalies
          </span>
        </div>
      </section>

      {/* 2. Middle Row: Spectrum Traffic Distribution & Threat Feed */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Spectrum Traffic Histogram (Graphite ramp, no lime decoration) */}
        <div className="lg:col-span-2 bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-col">
          <div className="flex items-center justify-between border-b border-[#1D2126] pb-2.5 mb-3">
            <h2 className="font-sans font-semibold text-xs tracking-wider uppercase text-[#E8EAED]">
              Live Ingest Bandwidth Spectrum (Last 60 Minutes)
            </h2>
            <span className="font-mono text-xs text-[#656C77]">100 MHz Channel Bins</span>
          </div>

          {/* Monochromatic Bar Representation */}
          <div className="h-44 flex items-end gap-1 pt-4 pb-1" aria-label="Traffic Volume Bar Visualizer">
            {[42, 48, 55, 62, 78, 90, 85, 70, 64, 52, 48, 60, 72, 88, 95, 80, 68, 54, 61, 74, 82, 91, 77, 65, 59, 71, 84, 96, 88, 79, 62, 54, 70, 82, 91].map((val, idx) => (
              <div key={idx} className="flex-1 flex flex-col items-center gap-1 group">
                <div
                  style={{ height: `${val}%` }}
                  className="w-full bg-[#21262D] border-t border-[#3D444F] group-hover:bg-[#8B93A0] transition-colors"
                  title={`Bucket -${35 - idx}m: ${val} Gbps`}
                />
              </div>
            ))}
          </div>
          <div className="flex justify-between font-mono text-[11px] text-[#656C77] border-t border-[#1D2126] pt-2">
            <span>-60 min</span>
            <span>-30 min</span>
            <span>Current (T-0)</span>
          </div>
        </div>

        {/* Alerts Column: Functional Color Exceptions with Dual Icon + Label */}
        <div className="bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-col">
          <div className="flex items-center justify-between border-b border-[#1D2126] pb-2.5 mb-3">
            <h2 className="font-sans font-semibold text-xs tracking-wider uppercase text-[#E8EAED]">
              High-Priority Alert Queue
            </h2>
            <span className="font-mono text-xs text-[#656C77]">{DEFAULT_ALERTS.length} unassigned</span>
          </div>

          <div className="flex flex-col gap-2.5">
            {DEFAULT_ALERTS.map((alert) => {
              const isCrit = alert.sev === 'crit';
              return (
                <div
                  key={alert.id}
                  className={`p-3 rounded-[4px] border flex flex-col gap-1.5 ${
                    isCrit
                      ? 'bg-[rgba(229,72,77,0.12)] border-[rgba(229,72,77,0.40)]'
                      : 'bg-[rgba(245,165,36,0.12)] border-[rgba(245,165,36,0.40)]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 font-mono text-xs font-bold">
                      {isCrit ? (
                        <>
                          <IconCross />
                          <span className="text-[#FFA4A7]">[CRITICAL]</span>
                        </>
                      ) : (
                        <>
                          <IconAlertTriangle />
                          <span className="text-[#FFD485]">[MEDIUM]</span>
                        </>
                      )}
                    </span>
                    <span className="font-mono text-[11px] text-[#8B93A0]">{alert.time} UTC</span>
                  </div>
                  <span className="text-xs font-semibold text-[#E8EAED]">{alert.rule}</span>
                  <span className="font-mono text-[11px] text-[#8B93A0]">Target: {alert.target}</span>
                  <p className="text-[11px] text-[#656C77] font-sans">{alert.detail}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* 3. Bottom Row: Active Network Sessions Table */}
      <section className="bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-col" aria-label="Session Telemetry Data">
        <div className="flex items-center justify-between border-b border-[#1D2126] pb-3 mb-2">
          <div>
            <h2 className="font-sans font-semibold text-xs tracking-wider uppercase text-[#E8EAED]">
              Top Asymmetric Network Flows
            </h2>
            <p className="text-xs text-[#8B93A0] font-sans mt-0.5">
              Live socket flows captured by the telemetry probe
            </p>
          </div>
          <span className="font-mono text-xs text-[#656C77]">Showing {filteredFlows.length} flows</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-xs" role="table">
            <thead>
              <tr className="border-b border-[#262B32] text-[#8B93A0]">
                <th scope="col" className="py-2.5 px-3 font-semibold">FLOW ID</th>
                <th scope="col" className="py-2.5 px-3 font-semibold">PROTO</th>
                <th scope="col" className="py-2.5 px-3 font-semibold">SOURCE SOCKET</th>
                <th scope="col" className="py-2.5 px-3 font-semibold">DESTINATION SOCKET</th>
                <th scope="col" className="py-2.5 px-3 font-semibold text-right">PACKETS</th>
                <th scope="col" className="py-2.5 px-3 font-semibold text-right">BYTES</th>
                <th scope="col" className="py-2.5 px-3 font-semibold">ANALYSIS / FLAG</th>
              </tr>
            </thead>
            <tbody>
              {filteredFlows.map((flow) => {
                const isAnomalous = flow.sev === 'crit';
                const isBeacon = flow.sev === 'med';
                const isSelected = selectedFlow?.id === flow.id;
                return (
                  <tr
                    key={flow.id}
                    onClick={() => setSelectedFlow(flow)}
                    onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && setSelectedFlow(flow)}
                    tabIndex={0}
                    role="row"
                    className={`border-b border-[#1D2126] cursor-pointer transition-colors focus:outline-none ${
                      isSelected
                        ? 'bg-[#1B1F24] border-l-2 border-l-[#C6FF00] text-[#E8EAED]'
                        : 'hover:bg-[#1B1F24] text-[#8B93A0]'
                    }`}
                  >
                    <td className={`py-2.5 px-3 font-bold ${isSelected ? 'text-[#C6FF00]' : 'text-[#E8EAED]'}`}>
                      {flow.id}
                    </td>
                    <td className="py-2.5 px-3 text-[#8B93A0]">{flow.proto}</td>
                    <td className="py-2.5 px-3 text-[#E8EAED]">{flow.src}</td>
                    <td className="py-2.5 px-3 text-[#E8EAED]">{flow.dst}</td>
                    <td className="py-2.5 px-3 text-right text-[#E8EAED]">{flow.pkts}</td>
                    <td className="py-2.5 px-3 text-right text-[#E8EAED]">{flow.bytes}</td>
                    <td className="py-2.5 px-3">
                      {isAnomalous && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[rgba(229,72,77,0.12)] border border-[rgba(229,72,77,0.40)] text-[#FFA4A7] text-[11px] font-bold">
                          <IconCross /> {flow.status}
                        </span>
                      )}
                      {isBeacon && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[rgba(245,165,36,0.12)] border border-[rgba(245,165,36,0.40)] text-[#FFD485] text-[11px] font-bold">
                          <IconAlertTriangle /> {flow.status}
                        </span>
                      )}
                      {!isAnomalous && !isBeacon && (
                        <span className="text-[#656C77] font-medium">{flow.status}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
