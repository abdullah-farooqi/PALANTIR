import { api } from '../api';
import { usePolling } from './usePolling';

/** Node list + fleet summary + pipeline health (top status bar and node tabs). */
export function useFleet(refreshMs) {
  return usePolling(
    async () => {
      const results = await Promise.allSettled([
        api.listNodes(),
        api.getFleetSummary(),
        api.getOpsHealth(),
      ]);
      if (results[0].status === 'rejected') throw results[0].reason;
      return {
        nodes: results[0].value,
        summary: results[1].status === 'fulfilled' ? results[1].value : null,
        ops: results[2].status === 'fulfilled' ? results[2].value : null,
      };
    },
    [],
    refreshMs,
    true
  );
}
