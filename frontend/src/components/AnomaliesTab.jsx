import clsx from 'clsx';
import { CheckCircle2, ShieldAlert, Brain, ArrowUpRight } from 'lucide-react';
import { Badge, Card, EmptyState, RelativeTime, SectionTitle, Spinner, useNow } from './ui';
import { formatDateTime, scoreToPercent } from '../lib/format';

function ScoreRing({ percent }) {
  const color = percent >= 90 ? '#f87171' : '#fbbf24';
  const shown = percent === null ? '—' : `${Math.round(percent)}%`;
  return (
    <div
      className="flex h-16 w-16 shrink-0 items-center justify-center rounded-full"
      style={{ background: `conic-gradient(${color} ${(percent || 0) * 3.6}deg, #1c2740 0deg)` }}
      title="Peak anomaly score"
    >
      <div className="tabular flex h-12 w-12 items-center justify-center rounded-full bg-panel text-sm font-semibold text-white">
        {shown}
      </div>
    </div>
  );
}

function ContextBar({ name, percent }) {
  const color = percent >= 90 ? 'bg-rose-400' : 'bg-amber-400';
  return (
    <div className="flex items-center gap-3 text-xs">
      <span className="w-40 shrink-0 truncate font-mono text-slate-300" title={name}>{name}</span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-edge">
        <div className={clsx('h-full rounded-full', color)} style={{ width: `${Math.min(100, percent || 0)}%` }} />
      </div>
      <span className="tabular w-12 text-right text-slate-300">{percent === null ? '—' : `${percent.toFixed(1)}%`}</span>
    </div>
  );
}

export default function AnomaliesTab({ anomalies, hostname, onInvestigate, onOpenInvestigation, investigating }) {
  const now = useNow(15000);

  return (
    <div className="space-y-4">
      <SectionTitle
        icon={ShieldAlert}
        title="Anomaly events"
        subtitle="Raised when at least 2 watched metrics (CPU, memory, load) stay far above their recent baseline (10 min cooldown)."
        right={<Badge tone="amber">{anomalies.length} events</Badge>}
      />

      {anomalies.length === 0 ? (
        <EmptyState icon={CheckCircle2} tone="green" title="No anomaly events recorded">
          No anomaly event has been recorded for {hostname}. Detection needs about 30 minutes of collected
          history before it can score anything.
        </EmptyState>
      ) : (
        anomalies.map((a) => {
          const peak = scoreToPercent(a.max_score);
          const scores = a.scores && typeof a.scores === 'object' ? a.scores : {};
          const names = Array.isArray(a.contexts) && a.contexts.length ? a.contexts : Object.keys(scores);
          return (
            <Card key={a.id} className="flex flex-wrap items-center gap-5 p-4">
              <ScoreRing percent={peak} />

              <div className="min-w-[16rem] flex-1 space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold text-white">Anomaly #{a.id}</span>
                  <Badge tone={peak >= 90 ? 'red' : 'amber'}>{peak >= 90 ? 'Severe' : 'High'}</Badge>
                  <span className="text-xs text-slate-500">
                    {formatDateTime(a.detected_at)} · <RelativeTime value={a.detected_at} now={now} />
                  </span>
                </div>
                <div className="space-y-1.5">
                  {names.map((name) => (
                    <ContextBar key={name} name={name} percent={scoreToPercent(scores[name])} />
                  ))}
                </div>
              </div>

              <div className="shrink-0">
                {a.investigation_id ? (
                  <button onClick={() => onOpenInvestigation(a.investigation_id)} className="btn btn-ghost text-xs">
                    <Brain className="h-3.5 w-3.5 text-indigo-400" />
                    Investigation #{a.investigation_id}
                    <ArrowUpRight className="h-3.5 w-3.5" />
                  </button>
                ) : (
                  <button onClick={() => onInvestigate('anomaly', a.id)} disabled={investigating} className="btn btn-ai text-xs">
                    {investigating ? <Spinner className="h-3.5 w-3.5" /> : <Brain className="h-3.5 w-3.5" />}
                    Investigate
                  </button>
                )}
              </div>
            </Card>
          );
        })
      )}
    </div>
  );
}
