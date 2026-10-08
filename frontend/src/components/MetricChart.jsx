import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Card, Spinner } from './ui';
import { formatTime, formatDateTime, formatValue } from '../lib/format';
import { latestOf } from '../lib/metrics';

function ChartTooltip({ active, payload, label, meta }) {
  if (!active || !payload || payload.length === 0) return null;
  const rows = payload
    .filter((item) => typeof item.value === 'number')
    .sort((a, b) => b.value - a.value);
  return (
    <div className="rounded-lg border border-edge2 bg-base/95 px-3 py-2 text-xs shadow-xl backdrop-blur">
      <div className="mb-1.5 font-mono text-[11px] text-slate-400">{formatDateTime(label)}</div>
      {rows.map((item) => (
        <div key={item.dataKey} className="flex items-center justify-between gap-4">
          <span className="flex items-center gap-1.5 text-slate-300">
            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
            {item.name}
          </span>
          <span className="tabular font-semibold text-white">{formatValue(item.value, meta.kind, meta.suffix)}</span>
        </div>
      ))}
    </div>
  );
}

// One chart card. `chart` comes from buildCharts(), `points` is the shared history for the category.
export default function MetricChart({ chart, points }) {
  const { meta, series, hidden } = chart;
  const gid = `g-${chart.id.replace(/[^a-zA-Z0-9]/g, '-')}`;
  const single = series.length === 1;
  const headline = single ? latestOf(points, series[0].key) : null;
  const yMax = meta.yMax ? meta.yMax : (max) => (max > 0 ? max : 1);

  return (
    <Card className="flex flex-col p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold text-white">{meta.title}</h3>
          <p className="truncate font-mono text-[11px] text-slate-500">{chart.context}</p>
        </div>
        {single && (
          <div className="tabular text-right text-lg font-semibold leading-none text-white">
            {formatValue(headline, meta.kind, meta.suffix)}
          </div>
        )}
      </div>

      <div className="mt-3 h-44">
        {points.length === 0 ? (
          <div className="flex h-full items-center justify-center gap-2 text-xs text-slate-500">
            <Spinner className="h-3.5 w-3.5" /> Waiting for data…
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={points} margin={{ top: 6, right: 8, left: 0, bottom: 0 }}>
              <defs>
                {series.map((s, i) => (
                  <linearGradient key={s.key} id={`${gid}-${i}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={s.color} stopOpacity={single ? 0.35 : 0.2} />
                    <stop offset="100%" stopColor={s.color} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1c2740" vertical={false} />
              <XAxis
                dataKey="t"
                type="number"
                scale="time"
                domain={['dataMin', 'dataMax']}
                tickFormatter={formatTime}
                tick={{ fontSize: 10, fill: '#64748b' }}
                stroke="#1c2740"
                tickLine={false}
                minTickGap={48}
              />
              <YAxis
                width={66}
                domain={[0, yMax]}
                tickFormatter={(v) => formatValue(v, meta.kind, meta.suffix)}
                tick={{ fontSize: 10, fill: '#64748b' }}
                stroke="#1c2740"
                tickLine={false}
                axisLine={false}
              />
              <Tooltip
                content={<ChartTooltip meta={meta} />}
                cursor={{ stroke: '#2b3a5a', strokeWidth: 1 }}
              />
              {series.map((s, i) => (
                <Area
                  key={s.key}
                  type="monotone"
                  dataKey={s.key}
                  name={s.label}
                  stroke={s.color}
                  strokeWidth={1.75}
                  fill={`url(#${gid}-${i})`}
                  dot={false}
                  activeDot={{ r: 3 }}
                  isAnimationActive={false}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      {!single && (
        <div className="mt-3 space-y-1 border-t border-edge pt-3">
          {series.map((s) => (
            <div key={s.key} className="flex items-center justify-between gap-3 text-xs">
              <span className="flex min-w-0 items-center gap-2 text-slate-300">
                <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: s.color }} />
                <span className="truncate">{s.label}</span>
              </span>
              <span className="tabular font-medium text-white">
                {formatValue(latestOf(points, s.key), meta.kind, meta.suffix)}
              </span>
            </div>
          ))}
          {hidden > 0 && <div className="pt-1 text-[11px] text-slate-500">+{hidden} more with lower usage</div>}
        </div>
      )}
    </Card>
  );
}
