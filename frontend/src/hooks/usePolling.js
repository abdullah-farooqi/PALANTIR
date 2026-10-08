import { useCallback, useEffect, useRef, useState } from 'react';

/**
 * Calls `fetcher()` immediately and then every `intervalMs` while `enabled`.
 * State is reset when `deps` change (e.g. another node was selected), and a slow
 * response from a previous selection is ignored.
 *
 * Returns { data, error, loading, refreshing, updatedAt, refresh }.
 */
export function usePolling(fetcher, deps, intervalMs, enabled = true) {
  const [state, setState] = useState({ data: null, error: '', loading: enabled, updatedAt: null });
  const [refreshing, setRefreshing] = useState(false);
  const fnRef = useRef(fetcher);
  fnRef.current = fetcher;
  const runId = useRef(0);

  const run = useCallback(async (initial) => {
    const id = (runId.current += 1);
    if (!initial) setRefreshing(true);
    try {
      const data = await fnRef.current();
      if (id !== runId.current) return;
      setState({ data, error: '', loading: false, updatedAt: Date.now() });
    } catch (err) {
      if (id !== runId.current) return;
      setState((s) => ({ ...s, error: (err && err.message) || String(err), loading: false }));
    } finally {
      if (id === runId.current) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (!enabled) {
      runId.current += 1;
      setState({ data: null, error: '', loading: false, updatedAt: null });
      return undefined;
    }
    setState({ data: null, error: '', loading: true, updatedAt: null });
    run(true);
    return () => {
      runId.current += 1;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, enabled]);

  useEffect(() => {
    if (!enabled || !intervalMs) return undefined;
    const id = setInterval(() => run(false), intervalMs);
    return () => clearInterval(id);
  }, [run, intervalMs, enabled]);

  const refresh = useCallback(() => run(false), [run]);
  return { ...state, refreshing, refresh };
}
