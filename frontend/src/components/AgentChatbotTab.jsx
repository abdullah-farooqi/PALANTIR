import { useEffect, useState } from 'react';
import {
  Activity, ArrowDown, ArrowRight, Bot, Check, Cpu, Database,
  ExternalLink, FileText, Info, Lock, MessageSquare, Network,
  Play, RefreshCw, Send, Shield, ShieldAlert, Sparkles, Terminal,
  Undo2, User, X,
} from 'lucide-react';
import { api } from '../api';

const PRESET_OPTIONS = [
  {
    id: 'summarize_alerts',
    label: '1. Summarize active alerts',
    hotkey: 'Alt+1',
    prompt: 'Summarize active alerts across the fleet and rank by urgency.',
  },
  {
    id: 'why_cpu_high',
    label: '2. Why is db-02 CPU high?',
    hotkey: 'Alt+2',
    prompt: 'Why is db-02 CPU high? Check the last 15 minutes of eBPF process telemetry and recent kernel conntrack events.',
  },
  {
    id: 'inspect_socket_drops',
    label: '3. Inspect eBPF network socket drops on web-01',
    hotkey: 'Alt+3',
    prompt: 'Inspect eBPF network socket drops on web-01 and isolate the top sending endpoints.',
  },
  {
    id: 'correlate_oomkills',
    label: '4. Correlate OOMKills with last 1h deploy logs',
    hotkey: 'Alt+4',
    prompt: 'Correlate OOMKills with last 1h deploy logs and verify cgroup memory pressure.',
  },
];

export default function AgentChatbotTab({ onToast, onChangeView }) {
  const [activePreset, setActivePreset] = useState('why_cpu_high');
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState([]);

  useEffect(() => {
    // Initial query on mount
    runQuery(PRESET_OPTIONS[1].prompt, 'why_cpu_high');
  }, []);

  useEffect(() => {
    function handleKeyDown(e) {
      if (e.altKey && e.key === '1') {
        e.preventDefault();
        runQuery(PRESET_OPTIONS[0].prompt, 'summarize_alerts');
      } else if (e.altKey && e.key === '2') {
        e.preventDefault();
        runQuery(PRESET_OPTIONS[1].prompt, 'why_cpu_high');
      } else if (e.altKey && e.key === '3') {
        e.preventDefault();
        runQuery(PRESET_OPTIONS[2].prompt, 'inspect_socket_drops');
      } else if (e.altKey && e.key === '4') {
        e.preventDefault();
        runQuery(PRESET_OPTIONS[3].prompt, 'correlate_oomkills');
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  async function runQuery(promptText, presetId = null) {
    if (!promptText.trim()) return;
    if (presetId) setActivePreset(presetId);
    else setActivePreset(null);

    const userMsg = {
      role: 'user',
      author: 'E. Vance',
      badge: 'L3 SOC ANALYST',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      text: promptText,
    };

    setMessages((prev) => [...prev, userMsg]);
    setLoading(true);

    try {
      const res = await api.queryCopilot(promptText);
      const botMsg = {
        role: 'assistant',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        ...res,
      };
      setMessages((prev) => [...prev, botMsg]);
    } catch (err) {
      onToast?.(err.message || 'Copilot query failed', true);
    } finally {
      setLoading(false);
    }
  }

  function handleSend(e) {
    e.preventDefault();
    if (!inputText.trim() || loading) return;
    const txt = inputText;
    setInputText('');
    runQuery(txt);
  }

  return (
    <div className="w-full min-h-screen text-[#E8EAED] font-sans p-6 select-none bg-[#0A0B0D]">
      {/* Top Section / Screen Header */}
      <div className="flex flex-col gap-2 mb-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="font-mono text-2xl font-bold tracking-tight uppercase text-[#E8EAED]">
              COPILOT PREVIEW
            </h1>
            <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-[#1B1F24] text-[#8B93A0] border border-[#262B32] tracking-wider uppercase font-semibold">
              EARLY ACCESS ARCHETYPE · v0.4-PREVIEW
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#C6FF00] animate-pulse" />
            <span className="font-mono text-xs text-[#8B93A0] uppercase tracking-widest">
              STATE: SYNTHETIC EVALUATION
            </span>
          </div>
        </div>
        <p className="text-sm text-[#8B93A0]">
          Simulated investigative reasoning & telemetry copilot assistant for SRE / SOC operations.
        </p>

        {/* Persistent Preview Banner */}
        <div className="w-full bg-[#14171B] border border-[#262B32] rounded px-4 py-2.5 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs text-[#8B93A0]">
          <div className="flex items-center gap-2">
            <Info size={16} className="text-[#C6FF00] shrink-0" />
            <span className="text-[#E8EAED]">
              Connected to local fleet telemetry backend with automated safety constraints.
            </span>
          </div>
          <div className="font-mono text-[11px] text-[#8B93A0] bg-[#0A0B0D] px-2 py-1 rounded border border-[#262B32] flex items-center gap-1.5 self-start md:self-auto">
            <Shield size={13} className="text-[#C6FF00]" />
            <span>Model: palantir-telemetry-eval-v1 · Sandbox Isolation</span>
          </div>
        </div>
      </div>

      {/* Main Grid: 2-Column Split Chat Experience */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left / Main Chat Canvas (8 cols on desktop) */}
        <div className="xl:col-span-8 flex flex-col bg-[#14171B] border border-[#262B32] rounded-lg overflow-hidden">
          {/* Suggested Exploration Prompts Bar */}
          <div className="p-4 border-b border-[#262B32] bg-[#0A0B0D]">
            <div className="flex items-center justify-between mb-3">
              <span className="font-mono text-xs text-[#8B93A0] uppercase tracking-wider flex items-center gap-1.5 font-bold">
                <Sparkles size={14} className="text-[#C6FF00]" />
                SUGGESTED EXPLORATION PROMPTS
              </span>
              <span className="font-mono text-[10px] text-[#8B93A0]">SIMULATION PRESETS</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {PRESET_OPTIONS.map((opt) => {
                const isActive = activePreset === opt.id;
                return (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => runQuery(opt.prompt, opt.id)}
                    className={`h-7 px-2.5 rounded font-mono text-xs flex items-center gap-2 text-left transition-colors ${
                      isActive
                        ? 'bg-[#1B1F24] border border-[#C6FF00] text-[#C6FF00]'
                        : 'bg-[#14171B] border border-[#262B32] text-[#E8EAED] hover:border-[#8B93A0]'
                    }`}
                  >
                    {isActive && <span className="w-1.5 h-1.5 rounded-full bg-[#C6FF00]" />}
                    <span>{opt.label}</span>
                    <kbd
                      className={`text-[10px] px-1 py-0.5 rounded border ${
                        isActive
                          ? 'bg-[#0A0B0D] border-[#C6FF00]/40 text-[#C6FF00]'
                          : 'bg-[#0A0B0D] border-[#262B32] text-[#8B93A0]'
                      }`}
                    >
                      {isActive ? 'Active' : opt.hotkey}
                    </kbd>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Chat Thread Canvas */}
          <div className="p-4 flex flex-col gap-6 bg-[#14171B] min-h-[520px] max-h-[620px] overflow-y-auto">
            {messages.map((msg, i) => {
              if (msg.role === 'user') {
                return (
                  <div key={i} className="flex gap-3 items-start">
                    <div className="w-7 h-7 rounded-full bg-[#262B32] flex items-center justify-center shrink-0 text-[#E8EAED] font-mono text-xs font-bold">
                      EV
                    </div>
                    <div className="flex-1 flex flex-col gap-1 max-w-2xl">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-xs text-[#E8EAED]">{msg.author}</span>
                        <span className="text-[10px] font-mono text-[#C6FF00] font-bold uppercase">{msg.badge}</span>
                        <span className="text-[#8B93A0] text-[10px]">•</span>
                        <span className="text-[11px] font-mono text-[#8B93A0]">{msg.timestamp}</span>
                      </div>
                      <div className="p-3 bg-[#1B1F24] rounded border border-[#262B32] text-xs text-[#E8EAED]">
                        {msg.text}
                      </div>
                    </div>
                  </div>
                );
              }

              // Assistant message
              return (
                <div key={i} className="flex gap-3 items-start animate-in fade-in duration-150">
                  <div className="w-7 h-7 rounded-full bg-[#C6FF00]/20 border border-[#C6FF00]/50 flex items-center justify-center shrink-0 text-[#C6FF00]">
                    <Bot size={16} />
                  </div>
                  <div className="flex-1 flex flex-col gap-3">
                    {/* Header */}
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-xs text-[#E8EAED] font-mono">PALANTIR COPILOT</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#C6FF00]/20 text-[#C6FF00] border border-[#C6FF00]/40 font-mono font-bold">
                          AI
                        </span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#262B32] text-[#8B93A0] font-mono">
                          TELEMETRY COPILOT
                        </span>
                      </div>
                      <span className="text-[11px] font-mono text-[#8B93A0]">
                        Generated at {msg.timestamp}
                      </span>
                    </div>

                    {/* Narrative */}
                    <div className="bg-[#1B1F24] p-4 rounded border border-[#262B32] flex flex-col gap-4 text-xs">
                      <p className="text-[#E8EAED] leading-relaxed font-sans">{msg.narrative}</p>

                      {/* Process Profiles */}
                      {msg.process_profile && msg.process_profile.length > 0 && (
                        <div className="flex flex-col gap-2">
                          <div className="flex items-center justify-between">
                            <span className="text-[11px] font-mono text-[#8B93A0] uppercase tracking-wider font-semibold">
                              TELEMETRY PROCESS PROFILE (eBPF RING BUFFER)
                            </span>
                            <span className="font-mono text-[10px] text-[#8B93A0]">eBPF sampled @ 100Hz</span>
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {msg.process_profile.map((proc, pIdx) => (
                              <div key={pIdx} className="bg-[#0A0B0D] p-3 rounded border border-[#262B32] flex flex-col gap-1 font-mono text-xs">
                                <div className="flex items-center justify-between">
                                  <span className="font-semibold text-[#E8EAED] truncate">{proc.name}</span>
                                  <span className="text-[10px] px-1 py-0.5 rounded bg-[#1B1F24] text-[#8B93A0] border border-[#262B32]">
                                    PID {proc.pid}
                                  </span>
                                </div>
                                <div className="flex items-center justify-between mt-1">
                                  <span className="text-[#8B93A0]">Core CPU Load:</span>
                                  <span className="text-[#C6FF00] font-bold">{proc.cpu_pct}%</span>
                                </div>
                                <div className="flex items-center justify-between">
                                  <span className="text-[#8B93A0]">Resident Set (RSS):</span>
                                  <span className="text-[#E8EAED]">{proc.rss}</span>
                                </div>
                                {proc.socket_backlog && (
                                  <div className="flex items-center justify-between">
                                    <span className="text-[#8B93A0]">eBPF Socket Backlog:</span>
                                    <span className="text-[#8B93A0]">{proc.socket_backlog}</span>
                                  </div>
                                )}
                                <div className="w-full bg-[#1B1F24] h-1 rounded-full overflow-hidden mt-1">
                                  <div className="bg-[#C6FF00] h-full" style={{ width: `${Math.min(proc.bar_pct || proc.cpu_pct, 100)}%` }} />
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Diagnostic Observation */}
                      {msg.diagnostic_observation && (
                        <div className="px-3 py-2 bg-[#0A0B0D] border border-[#262B32] rounded flex items-center justify-between text-[#8B93A0]">
                          <div className="flex items-center gap-2">
                            <Shield size={14} className="text-[#C6FF00]" />
                            <span className="text-xs text-[#E8EAED]">Diagnostic Observation:</span>
                            <span className="text-xs text-[#8B93A0]">{msg.diagnostic_observation}</span>
                          </div>
                          <span className="text-[10px] font-mono text-[#C6FF00] font-bold px-1.5 py-0.5 rounded bg-[#C6FF00]/10 border border-[#C6FF00]/30">
                            {msg.diagnostic_badge || 'SYS_OK'}
                          </span>
                        </div>
                      )}

                      {/* Evidence & Sources */}
                      {msg.evidence_sources && msg.evidence_sources.length > 0 && (
                        <div className="pt-2 border-t border-[#262B32]/60 flex flex-col gap-1.5">
                          <span className="text-[10px] font-mono text-[#8B93A0] uppercase tracking-wider font-semibold">
                            EVIDENCE & SOURCES [CONNECTED PIPELINE]:
                          </span>
                          <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                            {msg.evidence_sources.map((src, sIdx) => (
                              <div key={sIdx} className="flex items-center gap-1.5 px-2 py-1 rounded bg-[#0A0B0D] border border-[#262B32] text-[#8B93A0]">
                                <span className="text-[9px] px-1 bg-[#14171B] text-[#C6FF00] rounded border border-[#262B32] uppercase">
                                  Verified
                                </span>
                                <span className="text-[#E8EAED]">{src}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Action Workflows */}
                      <div className="p-3 rounded border border-dashed border-[#262B32] bg-[#0A0B0D]/60 flex flex-col gap-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5 text-[#8B93A0] font-mono text-[11px]">
                            <Lock size={13} />
                            <span className="uppercase font-semibold">PLANNED CAPABILITY: ACTION WORKFLOWS</span>
                          </div>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#1B1F24] text-[#8B93A0] border border-[#262B32]">
                            Operator Sign-Off Required
                          </span>
                        </div>
                        <p className="text-[11px] text-[#8B93A0]">
                          Remediation actions require two-person operator sign-off with mandatory SIEM audit logging and instant rollback.
                        </p>
                        <div className="flex flex-wrap items-center gap-2 mt-1">
                          <button
                            type="button"
                            disabled
                            className="h-7 px-3 rounded border border-dashed border-[#262B32] text-[#8B93A0] bg-transparent cursor-not-allowed font-mono text-[11px] flex items-center gap-1.5 opacity-50"
                          >
                            <Play size={12} />
                            <span>Approve Remediation</span>
                          </button>
                          <button
                            type="button"
                            disabled
                            className="h-7 px-3 rounded border border-dashed border-[#262B32] text-[#8B93A0] bg-transparent cursor-not-allowed font-mono text-[11px] flex items-center gap-1.5 opacity-50"
                          >
                            <X size={12} />
                            <span>Reject</span>
                          </button>
                          <button
                            type="button"
                            disabled
                            className="h-7 px-3 rounded border border-dashed border-[#262B32] text-[#8B93A0] bg-transparent cursor-not-allowed font-mono text-[11px] flex items-center gap-1.5 opacity-50"
                          >
                            <Undo2 size={12} />
                            <span>Undo</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}

            {loading && (
              <div className="flex items-center gap-3 p-4 text-[#8B93A0] font-mono text-xs">
                <RefreshCw size={15} className="animate-spin text-[#C6FF00]" />
                <span>Evaluating telemetry models and querying kernel buffers…</span>
              </div>
            )}
          </div>

          {/* Interactive Chat Input Bar */}
          <form onSubmit={handleSend} className="p-3 border-t border-[#262B32] bg-[#0A0B0D] flex flex-col gap-2">
            <div className="relative flex items-center">
              <span className="absolute left-3 font-mono text-[#C6FF00] font-bold text-sm">&gt;_</span>
              <input
                type="text"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Ask Copilot a question (e.g. why is cpu high, check socket drops, summarize alerts)..."
                className="w-full h-10 pl-8 pr-24 bg-[#14171B] border border-[#262B32] rounded text-xs text-[#E8EAED] font-mono placeholder:text-[#8B93A0] focus:border-[#C6FF00] focus:outline-none"
              />
              <button
                type="submit"
                disabled={loading || !inputText.trim()}
                className="absolute right-2 h-7 px-3 rounded bg-[#C6FF00] hover:bg-[#D8FF4D] text-[#0A0B0D] font-mono text-xs font-bold flex items-center gap-1 transition-colors disabled:opacity-40"
              >
                <Send size={13} />
                <span>Send</span>
              </button>
            </div>
            <div className="flex items-center justify-between text-[11px] font-mono text-[#8B93A0] px-1">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#C6FF00]" />
                <span>eBPF Telemetry Pipeline connected · Querying live fleet metrics</span>
              </div>
              <span>Read-only sandbox</span>
            </div>
          </form>
        </div>

        {/* Right Column / Context Inspector Panel (4 cols on desktop) */}
        <div className="xl:col-span-4 flex flex-col gap-4">
          <div className="flex items-center justify-between px-1">
            <span className="font-mono text-xs font-bold text-[#E8EAED] uppercase tracking-wider flex items-center gap-1.5">
              <Activity size={15} className="text-[#C6FF00]" />
              PREVIEW CONTEXT & CONSTRAINTS
            </span>
            <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[#1B1F24] text-[#8B93A0] border border-[#262B32]">
              AIR-GAPPED
            </span>
          </div>

          {/* Card 1: Safety Boundary */}
          <div className="p-4 bg-[#14171B] border border-[#262B32] rounded-lg flex flex-col gap-3">
            <div className="flex items-center justify-between pb-2 border-b border-[#262B32]">
              <span className="font-semibold text-xs text-[#E8EAED] flex items-center gap-1.5">
                <Shield size={14} className="text-[#C6FF00]" />
                Current Safety Boundary
              </span>
              <span className="font-mono text-[10px] text-[#C6FF00] font-bold uppercase">ENFORCED</span>
            </div>
            <ul className="flex flex-col gap-2 font-mono text-[11px] text-[#8B93A0]">
              <li className="flex items-start gap-2 text-[#E8EAED]">
                <Check size={14} className="text-[#C6FF00] shrink-0 mt-0.5" />
                <span>Zero write permissions (read-only telemetry observer)</span>
              </li>
              <li className="flex items-start gap-2 text-[#E8EAED]">
                <Check size={14} className="text-[#C6FF00] shrink-0 mt-0.5" />
                <span>Deterministic synthetic fixtures & grounded fleet data</span>
              </li>
              <li className="flex items-start gap-2 text-[#E8EAED]">
                <Check size={14} className="text-[#C6FF00] shrink-0 mt-0.5" />
                <span>No live cluster probe mutations without 2-man authorization</span>
              </li>
              <li className="flex items-start gap-2 text-[#E8EAED]">
                <Check size={14} className="text-[#C6FF00] shrink-0 mt-0.5" />
                <span>Retains zero chat history to cloud or third-party endpoints</span>
              </li>
            </ul>
          </div>

          {/* Card 2: Target Architecture Pipeline */}
          <div className="p-4 bg-[#14171B] border border-[#262B32] rounded-lg flex flex-col gap-3">
            <div className="flex items-center justify-between pb-2 border-b border-[#262B32]">
              <span className="font-semibold text-xs text-[#E8EAED] flex items-center gap-1.5">
                <Network size={14} className="text-[#8B93A0]" />
                Target Architecture Pipeline
              </span>
              <span className="font-mono text-[10px] text-[#8B93A0]">RFC-409</span>
            </div>
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-2 p-2 rounded bg-[#0A0B0D] border border-[#262B32]">
                <span className="w-5 h-5 rounded bg-[#14171B] border border-[#262B32] flex items-center justify-center font-mono text-[10px] text-[#8B93A0]">
                  01
                </span>
                <div className="flex flex-col">
                  <span className="font-mono text-xs text-[#E8EAED] font-medium">Local eBPF Aggregator</span>
                  <span className="text-[10px] text-[#8B93A0]">In-kernel ringbuffer filter for process & TCP drops</span>
                </div>
              </div>

              <div className="flex items-center gap-2 p-2 rounded bg-[#0A0B0D] border border-[#262B32]">
                <span className="w-5 h-5 rounded bg-[#14171B] border border-[#262B32] flex items-center justify-center font-mono text-[10px] text-[#8B93A0]">
                  02
                </span>
                <div className="flex flex-col">
                  <span className="font-mono text-xs text-[#E8EAED] font-medium">Redaction & Privacy Mask</span>
                  <span className="text-[10px] text-[#8B93A0]">SHA-256 scrubbing of PII, secrets, and auth tokens</span>
                </div>
              </div>

              <div className="flex items-center gap-2 p-2 rounded bg-[#0A0B0D] border border-[#262B32]">
                <span className="w-5 h-5 rounded bg-[#14171B] border border-[#262B32] flex items-center justify-center font-mono text-[10px] text-[#8B93A0]">
                  03
                </span>
                <div className="flex flex-col">
                  <span className="font-mono text-xs text-[#E8EAED] font-medium">Operator Approval Gate</span>
                  <span className="text-[10px] text-[#8B93A0]">Mandatory 2-man human sign-off for mutating runs</span>
                </div>
              </div>

              <div className="flex items-center gap-2 p-2 rounded bg-[#0A0B0D] border border-[#262B32]">
                <span className="w-5 h-5 rounded bg-[#14171B] border border-[#262B32] flex items-center justify-center font-mono text-[10px] text-[#8B93A0]">
                  04
                </span>
                <div className="flex flex-col">
                  <span className="font-mono text-xs text-[#E8EAED] font-medium">Execution Daemon</span>
                  <span className="text-[10px] text-[#8B93A0]">Rootless isolated cgroup remediation script</span>
                </div>
              </div>
            </div>
          </div>

          {/* Card 3: Simulated Host Context */}
          <div className="p-4 bg-[#14171B] border border-[#262B32] rounded-lg flex flex-col gap-3 font-mono text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-[#262B32]">
              <span className="font-semibold text-xs text-[#E8EAED] font-sans flex items-center gap-1.5">
                <Terminal size={14} className="text-[#8B93A0]" />
                Simulated Host Context
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#0A0B0D] text-[#8B93A0] border border-[#262B32]">
                FIXTURE
              </span>
            </div>
            <div className="flex flex-col gap-1.5 text-[11px]">
              <div className="flex items-center justify-between py-1 border-b border-[#262B32]/40">
                <span className="text-[#8B93A0]">Target Node:</span>
                <span className="text-[#C6FF00] font-semibold">db-02 (10.0.4.52)</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[#262B32]/40">
                <span className="text-[#8B93A0]">Kernel OS:</span>
                <span className="text-[#E8EAED]">5.15.0-91-generic</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[#262B32]/40">
                <span className="text-[#8B93A0]">Distribution:</span>
                <span className="text-[#E8EAED]">Ubuntu 22.04.4 LTS</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[#262B32]/40">
                <span className="text-[#8B93A0]">Active Daemon:</span>
                <span className="text-[#E8EAED] font-semibold">palantir-ebpf-v2.14</span>
              </div>
            </div>
            <div className="mt-1 p-2 rounded bg-[#0A0B0D] border border-[#262B32] flex items-center gap-2 text-[10px] text-[#8B93A0]">
              <Terminal size={12} className="text-[#C6FF00]" />
              <span>Simulation Hash: <code>0x9fbc18d24ae</code></span>
            </div>
          </div>

          {/* Quick Action: Go to Settings */}
          <button
            type="button"
            onClick={() => onChangeView?.('settings')}
            className="h-9 px-4 rounded bg-[#14171B] border border-[#262B32] hover:border-[#8B93A0] hover:bg-[#1B1F24] text-xs flex items-center justify-between text-[#8B93A0] hover:text-[#E8EAED] transition-colors"
          >
            <div className="flex items-center gap-2">
              <Sparkles size={14} className="text-[#C6FF00]" />
              <span>Configure LLM Gateway in Settings</span>
            </div>
            <ArrowRight size={14} />
          </button>
        </div>
      </div>
    </div>
  );
}
