import { useEffect, useState } from 'react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { describeTrigger } from '../lib/events';
import { formatDateTime } from '../lib/format';
import { Badge, Box, Empty, ErrorLine, Spinner } from './ui';
import NetworkEvidence from './NetworkEvidence';

export default function PcapTab({ onOpenInvestigations }) {
  const state = usePolling(() => api.searchInvestigations({ limit: 100 }), [], 10000, true);
  const investigations = state.data?.items || [];
  const [selectedId, setSelectedId] = useState(null);
  useEffect(() => {
    if (!selectedId && investigations.length) setSelectedId(investigations[0].id);
  }, [investigations, selectedId]);
  const selected = investigations.find((item) => item.id === selectedId) || null;

  return (
    <div className="flex flex-col gap-4">
      <section className="bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="font-mono text-xs text-[#8B93A0] uppercase tracking-wider">Network Evidence</div>
          <h1 className="font-mono font-bold text-sm text-[#E8EAED] mt-1">Captured files linked to investigations</h1>
          <p className="text-xs text-[#8B93A0] mt-2 mb-0">Capture metadata and download status come from the collector and master evidence store.</p>
        </div>
        {onOpenInvestigations && (
          <button type="button" className="btn sm" onClick={onOpenInvestigations} style={{ minHeight: 40 }}>
            Open Investigations
          </button>
        )}
      </section>

      {state.error && <ErrorLine>{state.error}</ErrorLine>}
      {state.loading && !state.data ? (
        <Empty><Spinner /> loading investigations…</Empty>
      ) : investigations.length === 0 ? (
        <Empty>No investigations are available yet. WARNING and CRITICAL alerts create investigation records.</Empty>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-start">
          <Box n={4} title="INVESTIGATIONS" right={<span className="font-mono text-xs text-[#8B93A0]">{investigations.length} RECORDS</span>}>
            <div className="flex flex-col gap-1.5 max-h-[calc(100vh-250px)] overflow-y-auto">
              {investigations.map((item) => {
                const active = selectedId === item.id;
                return (
                  <button
                    type="button"
                    key={item.id}
                    aria-pressed={active}
                    onClick={() => setSelectedId(item.id)}
                    className="text-left rounded border px-3 py-2.5 focus-visible:outline focus-visible:outline-2 focus-visible:outline-[#C6FF00]"
                    style={{ background: active ? '#1B1F24' : '#0A0B0D', borderColor: active ? '#4c6b20' : '#262B32', color: '#E8EAED' }}
                  >
                    <span className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-[#C6FF00]">INV #{item.id}</span>
                      <Badge tone={item.status === 'complete' ? 'green' : item.status === 'failed' ? 'red' : 'yellow'}>{item.status}</Badge>
                    </span>
                    <span className="block mt-1 text-xs">{item.node_hostname || `Node #${item.node_id}`}</span>
                    <span className="block mt-1 font-mono text-[11px] text-[#8B93A0]">{describeTrigger(item)} · {formatDateTime(item.queued_at)}</span>
                  </button>
                );
              })}
            </div>
          </Box>
          <Box n={8} title={selected ? `INVESTIGATION #${selected.id}` : 'NETWORK EVIDENCE'}>
            {selected ? <NetworkEvidence investigation={selected} /> : <Empty>Select an investigation to view network evidence.</Empty>}
          </Box>
        </div>
      )}
    </div>
  );
}
