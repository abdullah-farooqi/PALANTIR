import React, { useEffect, useState } from 'react';
import { api } from '../api';
import { REFRESH_OPTIONS } from './Layout';
import { Box, Dot, Empty, ErrorLine, Spinner } from './ui';
import { AGENT } from '../lib/metrics';
import { formatRelative } from '../lib/format';
import { statusTone } from '../lib/events';

export default function SettingsTab({ node, data, fleet, refreshMs, setRefreshMs, onRefresh, refreshing, onBack, onToast }) {
  const [thresholds, setThresholds] = useState([]);
  const [loadingThresholds, setLoadingThresholds] = useState(false);
  const [savingId, setSavingId] = useState(null);
  const [editValues, setEditValues] = useState({});

  useEffect(() => {
    let mounted = true;
    setLoadingThresholds(true);
    api.getThresholds()
      .then((items) => {
        if (!mounted) return;
        setThresholds(items || []);
        const initial = {};
        (items || []).forEach((t) => {
          initial[t.id] = { warn: t.warning_val, crit: t.critical_val };
        });
        setEditValues(initial);
      })
      .catch((err) => {
        if (!mounted) return;
        onToast && onToast(err.message || 'Failed to load alert thresholds', true);
      })
      .finally(() => {
        if (mounted) setLoadingThresholds(false);
      });
    return () => { mounted = false; };
  }, [onToast]);

  const handleSaveThreshold = async (id) => {
    const vals = editValues[id];
    if (!vals) return;
    const warn = parseFloat(vals.warn);
    const crit = parseFloat(vals.crit);
    if (Number.isNaN(warn) || Number.isNaN(crit)) {
      onToast && onToast('Threshold values must be valid numbers', true);
      return;
    }
    if (warn < 0 || crit < 0) {
      onToast && onToast('Threshold values cannot be negative', true);
      return;
    }
    setSavingId(id);
    try {
      const updated = await api.updateThreshold(id, { warning_val: warn, critical_val: crit });
      setThresholds((prev) => prev.map((t) => (t.id === id ? updated : t)));
      onToast && onToast(`Updated ${updated.id.toUpperCase()} threshold (Warning: ${warn}%, Critical: ${crit}%)`);
    } catch (err) {
      onToast && onToast(err.message || 'Failed to save threshold', true);
    } finally {
      setSavingId(null);
    }
  };

  const cats = (data && data.status && data.status.categories) || [];
  const age = (iso) => (iso ? formatRelative(iso) : '—');

  const cell = (c, source) => {
    const s = (c.sources || []).find((x) => x.source === source);
    if (!s) return <span className="tone-dim">—</span>;
    const tone = statusTone(s.status);
    return (
      <span title={`${s.status}${s.error_message ? ` — ${s.error_message}` : ''}`} className="row" style={{ gap: 5 }}>
        <Dot tone={tone} />
        <span className={tone === 'dim' ? 'tone-dim' : ''}>{s.status === 'available' ? age(s.last_success_at) : s.status.replace('_', ' ')}</span>
      </span>
    );
  };

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Top Header Bar matching Cyber Theme */}
      <div
        className="overview-header-bar"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 16px',
          background: '#080d09',
          borderRadius: 10,
          border: '1.5px solid #193822',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          {onBack && (
            <button
              className="btn primary"
              onClick={onBack}
              title="Go back"
              style={{
                width: 38,
                height: 38,
                padding: 0,
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: 8,
                fontSize: 20,
                fontWeight: 'bold',
              }}
            >
              <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <line x1="19" y1="12" x2="5" y2="12"></line>
                <polyline points="12 19 5 12 12 5"></polyline>
              </svg>
            </button>
          )}
          <span style={{ fontSize: '1.25rem', fontWeight: 800, color: '#fff' }}>
            SYSTEM SETTINGS
          </span>
          <span className="tone-dim" style={{ fontSize: '0.9rem', fontFamily: 'JetBrains Mono, monospace' }}>
            CONFIGURATION & SENSORS
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span
            style={{
              background: 'rgba(18, 38, 22, 0.8)',
              border: '1px solid #1c4524',
              borderRadius: 6,
              padding: '4px 10px',
              fontSize: 12,
              fontWeight: 700,
              color: '#39e569',
              letterSpacing: '0.04em',
            }}
          >
            GLOBAL ENGINE
          </span>
        </div>
      </div>

      {/* Grid: Alert Thresholds & Telemetry Refresh */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(520px, 1fr))', gap: 14 }}>
        {/* Box 1: Alert Thresholds */}
        <Box
          n={1}
          title="ALERT THRESHOLDS"
          hot
          right={<span className="tone-dim">LIVE EVALUATION</span>}
        >
          <div style={{ padding: '6px 4px' }}>
            <p style={{ color: '#7a9680', fontSize: '12px', marginTop: 0, marginBottom: 14 }}>
              Define when metric conditions trigger WARNING and CRITICAL alerts across all host agents.
            </p>

            {loadingThresholds ? (
              <div style={{ padding: 20, textAlign: 'center' }}>
                <Spinner /> <span className="tone-dim">loading thresholds…</span>
              </div>
            ) : thresholds.length === 0 ? (
              <Empty>No configurable thresholds found.</Empty>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {thresholds.map((t) => {
                  const currentVals = editValues[t.id] || { warn: t.warning_val, crit: t.critical_val };
                  const isDirty =
                    Number(currentVals.warn) !== Number(t.warning_val) ||
                    Number(currentVals.crit) !== Number(t.critical_val);
                  const isSaving = savingId === t.id;

                  return (
                    <div
                      key={t.id}
                      style={{
                        background: '#0d1710',
                        border: isDirty ? '1px solid #39e569' : '1px solid #193822',
                        borderRadius: 8,
                        padding: '12px 14px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 10,
                        transition: 'border 0.2s ease',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div>
                          <span
                            style={{
                              color: '#22d3ee',
                              fontWeight: 800,
                              fontSize: 12,
                              fontFamily: 'JetBrains Mono, monospace',
                              textTransform: 'uppercase',
                              marginRight: 8,
                            }}
                          >
                            {t.id}
                          </span>
                          <span style={{ color: '#e2e8f0', fontWeight: 600, fontSize: 12 }}>
                            {t.name}
                          </span>
                        </div>
                        <span className="tone-dim" style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}>
                          chart: {t.chart}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
                        {/* WARNING threshold input */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span
                            style={{
                              background: 'rgba(251, 191, 36, 0.14)',
                              border: '1px solid #78350f',
                              color: '#fbbf24',
                              fontSize: 10.5,
                              fontWeight: 800,
                              padding: '2px 6px',
                              borderRadius: 4,
                            }}
                          >
                            WARN ≥
                          </span>
                          <input
                            type="number"
                            className="in"
                            style={{
                              width: 72,
                              background: '#040805',
                              border: '1px solid #1c3823',
                              padding: '4px 8px',
                              color: '#fff',
                              borderRadius: 6,
                              fontFamily: 'JetBrains Mono, monospace',
                              fontSize: 12,
                            }}
                            value={currentVals.warn}
                            onChange={(e) => {
                              const val = e.target.value;
                              setEditValues((prev) => ({
                                ...prev,
                                [t.id]: { ...prev[t.id], warn: val },
                              }));
                            }}
                          />
                          <span className="tone-dim">{t.units}</span>
                        </div>

                        {/* CRITICAL threshold input */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span
                            style={{
                              background: 'rgba(239, 68, 68, 0.14)',
                              border: '1px solid #7f1d1d',
                              color: '#f87171',
                              fontSize: 10.5,
                              fontWeight: 800,
                              padding: '2px 6px',
                              borderRadius: 4,
                            }}
                          >
                            CRIT ≥
                          </span>
                          <input
                            type="number"
                            className="in"
                            style={{
                              width: 72,
                              background: '#040805',
                              border: '1px solid #1c3823',
                              padding: '4px 8px',
                              color: '#fff',
                              borderRadius: 6,
                              fontFamily: 'JetBrains Mono, monospace',
                              fontSize: 12,
                            }}
                            value={currentVals.crit}
                            onChange={(e) => {
                              const val = e.target.value;
                              setEditValues((prev) => ({
                                ...prev,
                                [t.id]: { ...prev[t.id], crit: val },
                              }));
                            }}
                          />
                          <span className="tone-dim">{t.units}</span>
                        </div>

                        {/* Save Action Button */}
                        <div style={{ marginLeft: 'auto' }}>
                          <button
                            className="btn primary sm"
                            disabled={!isDirty || isSaving}
                            onClick={() => handleSaveThreshold(t.id)}
                            style={{
                              padding: '4px 12px',
                              fontSize: 11,
                              borderRadius: 6,
                              opacity: !isDirty ? 0.45 : 1,
                              cursor: !isDirty ? 'default' : 'pointer',
                            }}
                          >
                            {isSaving ? 'Saving…' : isDirty ? 'Apply Changes' : 'Saved'}
                          </button>
                        </div>
                      </div>

                      {t.description && (
                        <div style={{ fontSize: 11, color: '#68846e' }}>
                          {t.description}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </Box>

        {/* Box 2: Telemetry Refresh Settings */}
        <Box
          n={2}
          title="TELEMETRY REFRESH"
          hot
          right={<span className="tone-dim">POLLING CADENCE</span>}
        >
          <div style={{ padding: '6px 4px' }}>
            <p style={{ color: '#7a9680', fontSize: '12px', marginTop: 0, marginBottom: 14 }}>
              Configure how frequently central workers fetch live telemetry snapshots from target host collectors.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: 10, marginBottom: 16 }}>
              {REFRESH_OPTIONS.map((option) => {
                const isSelected = refreshMs === option.value;
                return (
                  <button
                    key={option.value}
                    type="button"
                    onClick={() => setRefreshMs(option.value)}
                    style={{
                      background: isSelected ? 'rgba(57, 229, 105, 0.12)' : '#0d1710',
                      border: isSelected ? '1.5px solid #39e569' : '1px solid #1c3823',
                      borderRadius: 8,
                      padding: '12px 8px',
                      cursor: 'pointer',
                      textAlign: 'center',
                      transition: 'all 0.15s ease',
                      boxShadow: isSelected ? '0 0 10px rgba(57, 229, 105, 0.2)' : 'none',
                    }}
                  >
                    <div style={{ fontSize: 16, fontWeight: 800, color: isSelected ? '#39e569' : '#fff', marginBottom: 2 }}>
                      {option.label}
                    </div>
                    <div style={{ fontSize: 10.5, color: isSelected ? '#a3e635' : '#6a8a71', fontWeight: 600 }}>
                      {option.value === 0 ? 'Manual Only' : `${option.value / 1000}s Interval`}
                    </div>
                  </button>
                );
              })}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 14, borderTop: '1px solid #142e1a' }}>
              <span style={{ color: '#8aa690', fontSize: 12 }}>Force Immediate Synchronize:</span>
              <button
                className="btn primary sm"
                onClick={onRefresh}
                style={{ padding: '6px 14px', fontSize: 12, borderRadius: 6 }}
              >
                {refreshing ? 'Synchronizing…' : 'Sync Now'}
              </button>
            </div>
          </div>
        </Box>
      </div>

      {/* Box 3: Host Telemetry Sources Status */}
      <Box
        n={3}
        title="COLLECTOR STATUS & SOURCES"
        hot
        right={<span className="tone-dim">HOST AGENT SENSORS</span>}
      >
        <div style={{ padding: '6px 4px' }}>
          <p style={{ color: '#7a9680', fontSize: '12px', marginTop: 0, marginBottom: 12 }}>
            Status of telemetry categories actively collected by the PALANTIR host collector.
          </p>

          {data && data.errors && data.errors.status && <ErrorLine warn>collection-status: {data.errors.status}</ErrorLine>}

          {cats.length === 0 ? (
            <Empty>No collection status telemetry available yet.</Empty>
          ) : (
            <div className="box-scroll" style={{ overflowX: 'auto', marginBottom: 14 }}>
              <table className="tbl">
                <thead>
                  <tr>
                    <th />
                    {cats.map((c) => <th key={c.category}>{c.label || c.category}</th>)}
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="tone-dim" style={{ fontWeight: 700, color: '#a3c4aa' }}>collector</td>
                    {cats.map((c) => <td key={c.category}>{cell(c, AGENT)}</td>)}
                  </tr>
                </tbody>
              </table>
            </div>
          )}

          {node && (
            <div style={{ paddingTop: 10, borderTop: '1px solid #142e1a', color: '#728c78', fontSize: 11.5, fontFamily: 'JetBrains Mono, monospace' }}>
              <div>
                last contact: <span style={{ color: '#d8dee9' }}>{formatRelative(node.last_seen_at)}</span> • last collection: <span style={{ color: '#d8dee9' }}>{formatRelative(node.last_collection_at)}</span>
              </div>
              <div style={{ marginTop: 4 }}>
                collector endpoint: <span style={{ color: '#06b6d4' }}>{node.collector_url || 'not configured'}</span>
              </div>
            </div>
          )}
        </div>
      </Box>

      {/* Box 4: Background Workers & Operational Health */}
      {fleet?.data && (
        <Box
          n={4}
          title="BACKGROUND PIPELINE & OPERATIONAL HEALTH"
          hot
          right={<span className="tone-dim">STACK STATUS</span>}
        >
          <div style={{ padding: '6px 4px' }}>
            <p style={{ color: '#7a9680', fontSize: '12px', marginTop: 0, marginBottom: 14 }}>
              Status of backend core services, message brokers, and background worker task dispatchers.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10 }}>
              {/* Database */}
              <div style={{ background: '#0d1710', border: '1px solid #193822', borderRadius: 8, padding: '10px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0' }}>PostgreSQL</span>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#39e569', fontWeight: 800 }}>
                  <Dot tone={fleet.data.ops?.database?.status === 'healthy' ? 'green' : 'red'} />
                  {fleet.data.ops?.database?.status?.toUpperCase() || 'ONLINE'}
                </span>
              </div>

              {/* Redis Broker */}
              <div style={{ background: '#0d1710', border: '1px solid #193822', borderRadius: 8, padding: '10px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0' }}>Redis Cache/Queue</span>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#39e569', fontWeight: 800 }}>
                  <Dot tone={fleet.data.ops?.redis?.status === 'healthy' ? 'green' : 'red'} />
                  {fleet.data.ops?.redis?.status?.toUpperCase() || 'ONLINE'}
                </span>
              </div>

              {/* Celery Worker Pool */}
              <div style={{ background: '#0d1710', border: '1px solid #193822', borderRadius: 8, padding: '10px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0' }}>Celery Workers</span>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#39e569', fontWeight: 800 }}>
                  <Dot tone={fleet.data.ops?.celery?.workers?.status === 'healthy' ? 'green' : 'yellow'} />
                  {fleet.data.ops?.celery?.workers?.status?.toUpperCase() || 'RUNNING'}
                </span>
              </div>

              {/* Celery Beat Scheduler */}
              <div style={{ background: '#0d1710', border: '1px solid #193822', borderRadius: 8, padding: '10px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0' }}>Beat Scheduler</span>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#39e569', fontWeight: 800 }}>
                  <Dot tone={fleet.data.ops?.celery?.beat_dispatch?.status === 'healthy' ? 'green' : 'yellow'} />
                  {fleet.data.ops?.celery?.beat_dispatch?.status?.toUpperCase() || 'RUNNING'}
                </span>
              </div>
            </div>
          </div>
        </Box>
      )}
    </div>
  );
}
