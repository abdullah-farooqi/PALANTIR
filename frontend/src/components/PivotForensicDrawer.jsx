import { useEffect, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowLeft, Check, Copy, ExternalLink,
  Eye, FileText, Filter, Globe, Hash, Layers, Lock, Network,
  RefreshCw, Shield, ShieldAlert, Terminal, X,
} from 'lucide-react';
import { api } from '../api';

export default function PivotForensicDrawer({
  isOpen,
  onClose,
  initialQuery = '',
  initialType = '',
  onFilterAllViews,
  onToast,
}) {
  const [history, setHistory] = useState([]);
  const [current, setCurrent] = useState({ query: '', type: '' });
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);
  const [copiedType, setCopiedType] = useState(null);

  useEffect(() => {
    if (isOpen && initialQuery) {
      const first = { query: initialQuery, type: initialType };
      setHistory([]);
      setCurrent(first);
      fetchPivot(first.query, first.type);
    }
  }, [isOpen, initialQuery, initialType]);

  async function fetchPivot(q, type) {
    if (!q) return;
    setLoading(true);
    try {
      const res = await api.getPivotForensics(q, type);
      setData(res);
    } catch (err) {
      onToast?.(err.message || 'Failed to fetch pivot forensics', true);
    } finally {
      setLoading(false);
    }
  }

  function handleDrillDown(nextQuery, nextType) {
    if (!nextQuery || nextQuery === current.query) return;
    setHistory((prev) => [...prev, current]);
    const nextItem = { query: nextQuery, type: nextType };
    setCurrent(nextItem);
    fetchPivot(nextItem.query, nextItem.type);
  }

  function handleBack() {
    if (history.length === 0) return;
    const prev = history[history.length - 1];
    setHistory((h) => h.slice(0, -1));
    setCurrent(prev);
    fetchPivot(prev.query, prev.type);
  }

  function copyText(text, label) {
    navigator.clipboard.writeText(text);
    setCopiedType(label);
    setTimeout(() => setCopiedType(null), 1500);
    onToast?.(`Copied ${label} to clipboard`);
  }

  if (!isOpen) return null;

  const defanged = data?.defanged || current.query;
  const original = data?.query || current.query;
  const threatLevel = data?.threat_level || 'SUSPICIOUS';
  const isCritical = threatLevel === 'CRITICAL';
  const isSuspicious = threatLevel === 'SUSPICIOUS';

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-[#0A0B0D]/70 backdrop-blur-[2px] z-40 transition-opacity"
        onClick={onClose}
      />

      {/* Slide-over Drawer (540px wide) */}
      <aside
        className="fixed top-12 right-0 bottom-0 w-[540px] max-w-[95vw] bg-[#14171B] border-l border-[#262B32] shadow-2xl z-50 flex flex-col justify-between overflow-hidden animate-in slide-in-from-right duration-200 select-none text-[#E8EAED]"
        role="dialog"
        aria-modal="true"
      >
        {/* Header & Traversal Breadcrumbs */}
        <div className="flex flex-col border-b border-[#262B32] bg-[#1B1F24]">
          {/* Breadcrumb Traversal Bar */}
          <div className="h-10 px-4 flex items-center justify-between border-b border-[#262B32]/60 bg-[#0A0B0D] font-mono text-xs">
            <div className="flex items-center gap-2 text-[#8B93A0]">
              {history.length > 0 && (
                <button
                  type="button"
                  onClick={handleBack}
                  className="flex items-center gap-1 text-[#E8EAED] hover:text-[#C6FF00] px-1.5 py-0.5 rounded bg-[#14171B] border border-[#262B32]"
                >
                  <ArrowLeft size={12} />
                  <span>Back</span>
                </button>
              )}
              <span className="text-[#C6FF00] font-semibold truncate max-w-[140px]">
                {data?.type || current.type || 'Entity'} ({defanged})
              </span>
            </div>
            <div className="flex items-center gap-2 text-[11px]">
              <span className="text-[#8B93A0] uppercase">DEPTH: {history.length + 1}</span>
              <span className="text-[#262B32]">•</span>
              <span className="text-[#C6FF00] font-mono">PIVOT FORENSICS</span>
            </div>
          </div>

          {/* Title & Dismiss */}
          <div className="p-4 flex flex-col gap-3">
            <div className="flex items-start justify-between gap-3">
              <div className="flex flex-col">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[11px] font-mono font-semibold uppercase px-1.5 py-0.5 bg-[#14171B] text-[#8B93A0] rounded border border-[#262B32]">
                    {data?.type || current.type || 'Indicator'}
                  </span>
                  <span
                    className={`text-[11px] font-mono font-semibold uppercase px-1.5 py-0.5 rounded border flex items-center gap-1 ${
                      isCritical
                        ? 'bg-[#E5484D]/15 text-[#E5484D] border-[#E5484D]/40'
                        : isSuspicious
                        ? 'bg-[#F5A524]/15 text-[#F5A524] border-[#F5A524]/40'
                        : 'bg-[#14171B] text-[#8B93A0] border-[#262B32]'
                    }`}
                  >
                    <ShieldAlert size={12} />
                    {threatLevel} · {data?.confidence || '99%'} CONFIDENCE
                  </span>
                </div>
                <h2 className="font-mono text-xl font-bold text-[#C6FF00] tracking-tight select-all">
                  {defanged}
                </h2>
              </div>
              <button
                type="button"
                onClick={onClose}
                className="w-7 h-7 rounded bg-[#14171B] border border-[#262B32] text-[#8B93A0] hover:text-[#E8EAED] hover:bg-[#262B32] flex items-center justify-center transition-colors"
                title="Close drawer (Esc)"
              >
                <X size={16} />
              </button>
            </div>

            {/* Quick Action Toolbar */}
            <div className="grid grid-cols-3 gap-2 pt-1 font-mono text-xs">
              <button
                type="button"
                onClick={() => copyText(defanged, 'defanged')}
                className="h-8 px-2 rounded bg-[#14171B] border border-[#262B32] hover:border-[#8B93A0] text-[#E8EAED] flex items-center justify-center gap-1.5 transition-colors"
              >
                {copiedType === 'defanged' ? <Check size={13} className="text-[#C6FF00]" /> : <Copy size={13} />}
                <span>{copiedType === 'defanged' ? 'Copied!' : 'Copy defanged'}</span>
              </button>
              <button
                type="button"
                onClick={() => copyText(original, 'original')}
                className="h-8 px-2 rounded bg-[#14171B] border border-[#262B32] hover:border-[#8B93A0] text-[#E8EAED] flex items-center justify-center gap-1.5 transition-colors"
              >
                {copiedType === 'original' ? <Check size={13} className="text-[#C6FF00]" /> : <Copy size={13} />}
                <span>{copiedType === 'original' ? 'Copied!' : 'Copy original'}</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  onFilterAllViews?.(original);
                  onToast?.(`Filtered all views for ${defanged}`);
                }}
                className="h-8 px-2 rounded bg-[#C6FF00] hover:bg-[#D8FF4D] text-[#0A0B0D] font-bold flex items-center justify-center gap-1.5 transition-colors"
              >
                <Filter size={13} />
                <span>Filter all views</span>
              </button>
            </div>
          </div>
        </div>

        {/* Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 font-mono text-xs">
          {loading ? (
            <div className="flex items-center justify-center py-12 text-[#8B93A0]">
              <RefreshCw size={18} className="animate-spin mr-2 text-[#C6FF00]" />
              Correlating eBPF traces & PCAP flows…
            </div>
          ) : (
            <>
              {/* Entity Summary & Metadata Strip */}
              <div className="bg-[#0A0B0D] border border-[#262B32] rounded p-3 space-y-2.5">
                <div className="flex items-center justify-between border-b border-[#262B32]/60 pb-2">
                  <span className="text-[#8B93A0] uppercase font-sans font-semibold text-[11px]">
                    Classification
                  </span>
                  <span className="text-[#E8EAED] font-semibold text-right">
                    {data?.classification || 'Analyzed Network Indicator'}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 border-b border-[#262B32]/60 pb-2 text-[11px]">
                  <div>
                    <span className="text-[#8B93A0] block text-[10px]">FIRST SEEN (UTC)</span>
                    <span className="text-[#E8EAED]">{data?.first_seen ? data.first_seen.slice(11, 19) : '14:02:14'}</span>
                  </div>
                  <div>
                    <span className="text-[#8B93A0] block text-[10px]">LAST SEEN (UTC)</span>
                    <span className="text-[#E8EAED]">{data?.last_seen ? data.last_seen.slice(11, 19) : '14:02:45'}</span>
                  </div>
                </div>
                <div className="flex items-center justify-between border-b border-[#262B32]/60 pb-2">
                  <span className="text-[#8B93A0] uppercase font-sans font-semibold text-[11px]">
                    Threat Level
                  </span>
                  <div className="flex items-center gap-1.5">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${isCritical ? 'bg-[#E5484D]/20 text-[#E5484D]' : 'bg-[#F5A524]/20 text-[#F5A524]'}`}>
                      {threatLevel}
                    </span>
                    <span className="text-[#8B93A0] text-[11px]">Confidence: <strong className="text-[#E8EAED]">{data?.confidence || '99%'}</strong></span>
                  </div>
                </div>
                <div className="pt-0.5">
                  <span className="text-[10px] text-[#8B93A0] uppercase font-sans font-semibold block">
                    Reverse DNS / Autonomous System
                  </span>
                  <span className="text-[#C6FF00] mt-0.5 block truncate">
                    {data?.reverse_dns || 'c2.blackhat-ops[.]net (AS13335 · Cloudflare/Proxy)'}
                  </span>
                </div>
              </div>

              {/* SECTION A: CORRELATED FLOWS */}
              <div className="bg-[#1B1F24] border border-[#262B32] rounded overflow-hidden">
                <div className="h-8 px-3 bg-[#14171B] border-b border-[#262B32] flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Network size={14} className="text-[#C6FF00]" />
                    <span className="font-sans font-semibold uppercase text-xs tracking-wide">
                      Correlated Flows
                    </span>
                  </div>
                  <span className="px-1.5 py-0.5 rounded bg-[#0A0B0D] text-[#C6FF00] border border-[#C6FF00]/40 text-[10px]">
                    {data?.flows?.length || 0} total
                  </span>
                </div>
                <div className="divide-y divide-[#262B32]/50 bg-[#14171B]">
                  {data?.flows?.length === 0 ? (
                    <div className="p-3 text-center text-[#8B93A0]">No direct flows recorded.</div>
                  ) : (
                    data?.flows?.map((flow, i) => (
                      <div
                        key={flow.id || i}
                        className="p-2.5 flex flex-col gap-1 hover:bg-[#1B1F24] cursor-pointer transition-colors"
                        onClick={() => {
                          const nextIp = flow.dst?.split(':')[0] || flow.src?.split(':')[0];
                          if (nextIp && nextIp !== current.query) handleDrillDown(nextIp, 'IPv4');
                        }}
                      >
                        <div className="flex items-center justify-between text-[#8B93A0]">
                          <span className="text-[#E8EAED] font-semibold">
                            {flow.timestamp} · Flow #{flow.id}
                          </span>
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${flow.is_threat ? 'bg-[#E5484D]/20 text-[#E5484D]' : 'bg-[#262B32] text-[#8B93A0]'}`}>
                            {flow.threat_label}
                          </span>
                        </div>
                        <div className="text-[#E8EAED] truncate">
                          <span className="text-[#8B93A0]">{flow.src}</span> → <span className="text-[#C6FF00] font-bold">{flow.dst}</span>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-[#8B93A0]">
                          <span>Volume: {flow.volume}</span>
                          <span className={flow.is_threat ? 'text-[#C6FF00]' : 'text-[#8B93A0]'}>
                            {flow.state}
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* SECTION B: CORRELATED SESSIONS */}
              {data?.sessions && data.sessions.length > 0 && (
                <div className="bg-[#1B1F24] border border-[#262B32] rounded overflow-hidden">
                  <div className="h-8 px-3 bg-[#14171B] border-b border-[#262B32] flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Layers size={14} className="text-[#C6FF00]" />
                      <span className="font-sans font-semibold uppercase text-xs tracking-wide">
                        Reassembled TCP Sessions
                      </span>
                    </div>
                    <span className="px-1.5 py-0.5 rounded bg-[#0A0B0D] text-[#8B93A0] text-[10px]">
                      {data.sessions.length}
                    </span>
                  </div>
                  <div className="p-2 space-y-1.5">
                    {data.sessions.map((s, idx) => (
                      <div key={idx} className="p-2 bg-[#0A0B0D] rounded border border-[#262B32]/60 flex items-center justify-between">
                        <div>
                          <div className="text-[#E8EAED] font-medium">Session #{s.session_id} · {s.state}</div>
                          <div className="text-[#8B93A0] text-[10px]">Reassembled: {s.reassembled_bytes || 0} bytes</div>
                        </div>
                        <span className="text-[#C6FF00] font-bold text-[11px]">{s.confidence || 'HIGH'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* SECTION C: CORRELATED CVE MATCHES */}
              {data?.cves && data.cves.length > 0 && (
                <div className="bg-[#1B1F24] border border-[#262B32] rounded overflow-hidden">
                  <div className="h-8 px-3 bg-[#14171B] border-b border-[#262B32] flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Shield size={14} className="text-[#E5484D]" />
                      <span className="font-sans font-semibold uppercase text-xs tracking-wide">
                        Matched CVE Vulnerabilities
                      </span>
                    </div>
                    <span className="px-1.5 py-0.5 rounded bg-[#E5484D]/20 text-[#E5484D] text-[10px]">
                      {data.cves.length}
                    </span>
                  </div>
                  <div className="p-2 space-y-1.5">
                    {data.cves.map((cve, idx) => (
                      <div
                        key={idx}
                        className="p-2 bg-[#0A0B0D] rounded border border-[#262B32]/60 flex items-center justify-between cursor-pointer hover:border-[#C6FF00]"
                        onClick={() => handleDrillDown(cve.cve_id, 'CVE')}
                      >
                        <div>
                          <div className="text-[#C6FF00] font-bold">{cve.cve_id}</div>
                          <div className="text-[#8B93A0] text-[10px] truncate max-w-[280px]">
                            {cve.description || 'Remote code execution vulnerability'}
                          </div>
                        </div>
                        <span className="text-[#E5484D] font-bold text-xs">CVSS {cve.cvss_score || '9.8'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* SECTION D: COMMUNICATING FLEET NODES */}
              {data?.nodes && data.nodes.length > 0 && (
                <div className="bg-[#1B1F24] border border-[#262B32] rounded overflow-hidden">
                  <div className="h-8 px-3 bg-[#14171B] border-b border-[#262B32] flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Terminal size={14} className="text-[#C6FF00]" />
                      <span className="font-sans font-semibold uppercase text-xs tracking-wide">
                        Communicating Fleet Hosts
                      </span>
                    </div>
                    <span className="px-1.5 py-0.5 rounded bg-[#0A0B0D] text-[#8B93A0] text-[10px]">
                      {data.nodes.length}
                    </span>
                  </div>
                  <div className="p-2 flex flex-wrap gap-1.5">
                    {data.nodes.map((n) => (
                      <span
                        key={n.id}
                        className="px-2 py-1 bg-[#0A0B0D] border border-[#262B32] rounded text-xs text-[#E8EAED] hover:text-[#C6FF00] hover:border-[#C6FF00] cursor-pointer flex items-center gap-1.5"
                        onClick={() => handleDrillDown(n.hostname, 'Host')}
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-[#C6FF00]" />
                        {n.hostname}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Drawer Footer Status */}
        <div className="h-10 px-4 bg-[#0A0B0D] border-t border-[#262B32] flex items-center justify-between text-[11px] font-mono text-[#8B93A0]">
          <span>Capture buffer: 100% indexed</span>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#C6FF00]" />
            <span className="text-[#C6FF00] font-semibold">Live Forensics Active</span>
          </div>
        </div>
      </aside>
    </>
  );
}
