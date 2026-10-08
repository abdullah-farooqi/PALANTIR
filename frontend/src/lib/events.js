// Helpers for alerts, anomalies, logs and investigations.

export function severityTone(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'red';
  if (s === 'WARNING') return 'yellow';
  if (s === 'CLEAR') return 'green';
  return 'dim';
}

export function logTone(sev) {
  const s = String(sev || '').toLowerCase();
  if (['emerg', 'emergency', 'alert', 'crit', 'critical', 'err', 'error', 'fatal'].includes(s)) return 'red';
  if (['warn', 'warning'].includes(s)) return 'yellow';
  if (['notice', 'info'].includes(s)) return 'cyan';
  return 'dim';
}

export function statusTone(status) {
  switch (status) {
    case 'complete':
    case 'available':
    case 'healthy':
    case 'reachable':
      return 'green';
    case 'running':
    case 'queued':
    case 'stale':
    case 'partial':
      return 'yellow';
    case 'failed':
    case 'collection_error':
    case 'unreachable':
    case 'unavailable':
    case 'degraded':
      return 'red';
    default:
      return 'dim';
  }
}

export function describeTrigger(inv) {
  if (inv.trigger_type === 'anomaly') return inv.trigger_id ? `anomaly #${inv.trigger_id}` : 'anomaly';
  if (inv.trigger_type === 'alert') return inv.trigger_id ? `alert #${inv.trigger_id}` : 'alert';
  return 'manual';
}
