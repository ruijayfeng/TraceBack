import {useEffect, useState} from 'react';
export interface Resource<T> {data: T | null; loading: boolean; error: string | null}
export function useResource<T>(load: (signal: AbortSignal) => Promise<T>, keys: unknown[]): Resource<T> {
  const scope = JSON.stringify(keys);
  const [state, setState] = useState<Resource<T> & {scope: string}>({scope, data: null, loading: true, error: null});
  useEffect(() => {
    const controller = new AbortController();
    setState({scope, data: null, loading: true, error: null});
    load(controller.signal).then(data => {if (!controller.signal.aborted) setState({scope, data, loading: false, error: null});})
      .catch(e => {if (!controller.signal.aborted) setState({scope, data: null, loading: false, error: e instanceof Error ? e.message : 'request_failed'});});
    return () => controller.abort();
    // Callers provide every scope/filter dependency; stale results are aborted.
  }, keys);
  return state.scope === scope ? state : {data: null, loading: true, error: null};
}
