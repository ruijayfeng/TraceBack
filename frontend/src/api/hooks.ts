import {useCallback, useEffect, useRef, useState} from 'react';

export interface Resource<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  /** Refetch the current scope; previous data is kept while loading. */
  reload: () => void;
}

interface ResourceState<T> {
  scope: string;
  data: T | null;
  loading: boolean;
  error: string | null;
}

/**
 * Fetch a resource for a JSON-serialisable scope key.
 * - aborts the previous request when the scope changes;
 * - ignores late responses from an aborted scope;
 * - optionally keeps the previous data visible while the next page/filter loads
 *   (stale-while-revalidate) instead of blanking the panel.
 */
export function useResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  keys: unknown[],
  options: {keepPrevious?: boolean} = {},
): Resource<T> {
  const scope = JSON.stringify(keys);
  const keepPrevious = options.keepPrevious ?? false;
  const [nonce, setNonce] = useState(0);
  const lastData = useRef<T | null>(null);
  const [state, setState] = useState<ResourceState<T>>({scope, data: null, loading: true, error: null});

  useEffect(() => {
    const controller = new AbortController();
    const previous = keepPrevious ? lastData.current : null;
    setState({scope, data: previous, loading: true, error: null});
    load(controller.signal)
      .then(data => {
        if (controller.signal.aborted) return;
        lastData.current = data;
        setState({scope, data, loading: false, error: null});
      })
      .catch(e => {
        if (controller.signal.aborted) return;
        setState({scope, data: previous, loading: false, error: e instanceof Error ? e.message : 'request_failed'});
      });
    return () => controller.abort();
    // Callers provide every scope/filter dependency; stale results are aborted.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, nonce]);

  const reload = useCallback(() => setNonce(n => n + 1), []);
  const current = state.scope === scope
    ? state
    : {scope, data: keepPrevious ? lastData.current : null, loading: true, error: null};
  return {...current, reload};
}
