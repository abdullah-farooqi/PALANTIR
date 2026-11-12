import React, { useState, useCallback, useRef, useEffect } from 'react';

const INITIAL_MESSAGES = [
  {
    id: 'MSG-01',
    sender: 'agent',
    timestamp: '09:14:20 UTC',
    text: 'Forensic evaluation complete for PCAP artifact `incident-2026-11-10_apt29.pcap`. Reconstructed flow #104 contains an active Cobalt Strike stager transmitting over port 8080.',
    citations: [
      { id: 'CIT-1', label: 'PCAP Flow #104 @ 08:14:03 UTC', snippet: 'GET /jquery-3.3.1.slim.min.js HTTP/1.1' },
      { id: 'CIT-2', label: 'YARA Rule APT_CobaltStrike_Beacon', snippet: 'Matched hex signature offset 0x4A20' },
      { id: 'CIT-3', label: 'Suricata Alert SID:2019842', snippet: 'ET MALWARE Cobalt Strike Malleable C2' },
    ],
    confidence: '94% (High Statistical Certainty)',
    actionPlan: {
      action: 'Isolate Host 10.0.1.4 on Core Switch VLAN 99 & Terminate TCP Socket 8080',
      status: 'pending', // 'pending' | 'approved' | 'rejected' | 'reverted'
    },
  },
];

export default function AgentChatbotTab({ onToast }) {
  const [messages, setMessages] = useState(INITIAL_MESSAGES);
  const [inputQuery, setInputQuery] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const [undoSeconds, setUndoSeconds] = useState(null);
  const undoTimerRef = useRef(null);

  // Approve action flow with 30s reversible buffer
  const handleApproveAction = useCallback((msgId) => {
    setMessages((prev) =>
      prev.map((m) => (m.id === msgId ? { ...m, actionPlan: { ...m.actionPlan, status: 'approved' } } : m))
    );
    setUndoSeconds(30);
    if (onToast) onToast('Containment instruction queued. 30s safety buffer active.');
  }, [onToast]);

  const handleRejectAction = useCallback((msgId) => {
    setMessages((prev) =>
      prev.map((m) => (m.id === msgId ? { ...m, actionPlan: { ...m.actionPlan, status: 'rejected' } } : m))
    );
    if (onToast) onToast('Intervention dismissed by operator.');
  }, [onToast]);

  const handleUndo = useCallback((msgId) => {
    clearInterval(undoTimerRef.current);
    setUndoSeconds(null);
    setMessages((prev) =>
      prev.map((m) => (m.id === msgId ? { ...m, actionPlan: { ...m.actionPlan, status: 'reverted' } } : m))
    );
    if (onToast) onToast('Action cancelled: socket termination aborted.');
  }, [onToast]);

  useEffect(() => {
    if (undoSeconds !== null && undoSeconds > 0) {
      undoTimerRef.current = setTimeout(() => {
        setUndoSeconds((s) => (s > 0 ? s - 1 : null));
      }, 1000);
    }
    return () => clearTimeout(undoTimerRef.current);
  }, [undoSeconds]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!inputQuery.trim()) return;

    const queryText = inputQuery.trim();
    const userMsg = {
      id: `USER-${Date.now()}`,
      sender: 'user',
      timestamp: new Date().toISOString().slice(11, 19) + ' UTC',
      text: queryText,
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setIsStreaming(true);

    // Mock calibrated streaming agent response with Vercel React Best Practices
    setTimeout(() => {
      const responseMsg = {
        id: `AGENT-${Date.now()}`,
        sender: 'agent',
        timestamp: new Date().toISOString().slice(11, 19) + ' UTC',
        text: `Forensic audit response for "${queryText}": Analyzed 14 correlated log entries and process tree for 10.0.1.4. Host telemetry confirms process 'stress-ng' (PID 2190) executed with zero kernel OOM kills. Outbound connection to 198.51.100.42 remains quarantined.`,
        citations: [
          { id: 'CIT-4', label: 'BGP Routing Table Core-01', snippet: 'Route 10.0.1.4/32 -> Null0 (Blackhole)' },
          { id: 'CIT-5', label: 'Host Telemetry Process Tree', snippet: 'PID 2190 spawned from /tmp/stager' },
        ],
        confidence: '98% (Verified via Router Telemetry & Collector)',
      };
      setMessages((prev) => [...prev, responseMsg]);
      setIsStreaming(false);
    }, 1100);
  };

  return (
    <div className="flex flex-col gap-4 h-[calc(100vh-140px)]">
      {/* Copilot Header */}
      <section className="bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-wrap justify-between items-center gap-3">
        <div>
          <span className="font-mono text-xs text-[#656C77] uppercase tracking-wider">
            RAG Knowledge Plane & Multi-Modal Engine
          </span>
          <h1 className="font-mono font-bold text-sm text-[#E8EAED] mt-0.5">
            Demo Forensic Agent · Illustrative PCAP, IDS, and host-process examples
          </h1>
          <p className="text-xs text-[#8B93A0] mt-2 mb-0">
            Demo content only. This panel does not inspect live captures or execute network actions.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* LOUD LIME: Streaming status indicator */}
          <span className="font-mono text-xs text-[#C6FF00] flex items-center gap-1.5 font-bold">
            <span className="w-2 h-2 rounded-full bg-[#C6FF00] animate-pulse" aria-hidden="true" />
            Demo Mode
          </span>
        </div>
      </section>

      {/* Chat Timeline Frame */}
      <div className="flex-1 bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] overflow-y-auto flex flex-col gap-4">
        {messages.map((msg) => {
          const isAgent = msg.sender === 'agent';
          return (
            <div
              key={msg.id}
              className={`flex flex-col gap-2 max-w-3xl p-4 rounded-[4px] border ${
                isAgent
                  ? 'bg-[#1B1F24] border-[#262B32] text-[#E8EAED]'
                  : 'bg-[#0A0B0D] border-[#1D2126] ml-auto text-[#E8EAED]'
              }`}
            >
              <div className="flex justify-between items-center font-mono text-xs text-[#656C77] border-b border-[#1D2126] pb-1.5">
                <span className="font-bold uppercase tracking-wider text-[#8B93A0]">
                  {isAgent ? 'Autonomous Forensic Agent' : 'Forensic Investigator'}
                </span>
                <span>{msg.timestamp}</span>
              </div>

              <p className="font-sans text-sm leading-relaxed text-[#E8EAED] mt-1">{msg.text}</p>

              {/* Citations & Evidence Callouts */}
              {msg.citations && (
                <div className="flex flex-col gap-1.5 mt-2 pt-2 border-t border-[#1D2126]">
                  <span className="font-mono text-[11px] text-[#656C77] uppercase font-semibold">
                    Illustrative Sample References:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {msg.citations.map((c) => (
                      <span
                        key={c.id}
                        className="px-2 py-0.5 rounded bg-[#0A0B0D] border border-[#262B32] font-mono text-[11px] text-[#8B93A0]"
                        title={c.snippet}
                      >
                        [Ref: {c.label}]
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Confidence Metric */}
              {msg.confidence && (
                <div className="font-mono text-[11px] text-[#656C77] mt-1">
                  Confidence Score: <span className="text-[#E8EAED] font-medium">{msg.confidence}</span>
                </div>
              )}

              {/* Human-in-the-Loop Agent Action Intervention Drawer */}
              {msg.actionPlan && (
                <div className="mt-3 p-3 bg-[#0A0B0D] border border-[#262B32] rounded-[4px] flex flex-col gap-2">
                  <div className="font-mono text-xs font-bold uppercase text-[#E8EAED] flex items-center justify-between">
                    <span>Proposed Containment Intervention:</span>
                    <span className="text-[#656C77] font-normal">State: {msg.actionPlan.status.toUpperCase()}</span>
                  </div>
                  <p className="font-sans text-xs text-[#8B93A0]">{msg.actionPlan.action}</p>

                  <div className="flex items-center gap-3 mt-2">
                    {msg.actionPlan.status === 'pending' && (
                      <>
                        {/* LOUD LIME: Primary Action for confirming containment */}
                        <button
                          onClick={() => handleApproveAction(msg.id)}
                          className="px-3 py-1.5 bg-[#C6FF00] hover:bg-[#D8FF4D] active:bg-[#A8DB00] text-[#0A0B0D] font-mono font-bold text-xs rounded-[4px] transition-colors focus:outline-none"
                        >
                          Approve Containment
                        </button>
                        <button
                          onClick={() => handleRejectAction(msg.id)}
                          className="px-3 py-1.5 bg-[#21262D] hover:bg-[#262B32] text-[#E8EAED] font-mono text-xs rounded-[4px] transition-colors focus:outline-none"
                        >
                          Dismiss Action
                        </button>
                      </>
                    )}

                    {msg.actionPlan.status === 'approved' && undoSeconds !== null && (
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-xs text-[#C6FF00]">✔ Executing in {undoSeconds}s</span>
                        <button
                          onClick={() => handleUndo(msg.id)}
                          className="px-2.5 py-1 bg-[rgba(229,72,77,0.12)] border border-[rgba(229,72,77,0.40)] text-[#FFA4A7] font-mono text-xs rounded-[4px]"
                        >
                          Undo Execution
                        </button>
                      </div>
                    )}

                    {msg.actionPlan.status === 'approved' && undoSeconds === null && (
                      <span className="font-mono text-xs text-[#8B93A0]">✔ Intervention dispatched to core switch.</span>
                    )}

                    {msg.actionPlan.status === 'reverted' && (
                      <span className="font-mono text-xs text-[#656C77]">Intervention execution cancelled by operator.</span>
                    )}

                    {msg.actionPlan.status === 'rejected' && (
                      <span className="font-mono text-xs text-[#656C77]">Intervention rejected by operator.</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}

        {isStreaming && (
          <div className="flex items-center gap-2 font-mono text-xs text-[#656C77] p-2">
            <span className="w-2 h-2 rounded-full bg-[#C6FF00] animate-ping" aria-hidden="true" />
            Synthesizing grounded forensic assessment...
          </div>
        )}
      </div>

      {/* Input Prompt Control */}
      <form onSubmit={handleSubmit} className="flex gap-2">
        <input
          type="text"
          value={inputQuery}
          onChange={(e) => setInputQuery(e.target.value)}
          placeholder="Query evidence, request packet decodes, or issue verified containment actions..."
          aria-label="Agent Prompt Input"
          className="flex-1 bg-[#14171B] border border-[#262B32] rounded-[4px] px-4 py-2.5 text-xs font-mono text-[#E8EAED] placeholder:text-[#656C77] focus:outline-none focus:border-[#C6FF00]"
        />
        {/* LOUD LIME: Primary Action to submit query */}
        <button
          type="submit"
          disabled={!inputQuery.trim() || isStreaming}
          className="px-5 py-2.5 bg-[#C6FF00] hover:bg-[#D8FF4D] active:bg-[#A8DB00] disabled:bg-[#1B1F24] disabled:text-[#656C77] text-[#0A0B0D] font-mono font-bold text-xs rounded-[4px] transition-colors focus:outline-none"
        >
          Dispatch
        </button>
      </form>
    </div>
  );
}
