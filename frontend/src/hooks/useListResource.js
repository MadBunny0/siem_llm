// Хук загрузки списочного ресурса для вкладок (legacy-cleanup): state
// items/loading/error + load() — общий скелет, который раньше копировался
// в каждой вкладке (Analyses/Notifications/Audit/Rules/Playbooks/Responses).
// Опции: query — строка запроса (например '?limit=200'), pollMs — период
// опроса (пауза, когда вкладка браузера скрыта), requester — подмена
// fetch-обёртки (ResponsesView получает request пропсом, тесты — моком),
// onLoaded — колбэк после успешной загрузки.
import { useCallback, useEffect, useRef, useState } from 'react';

import { request } from '../api.js';

export function useListResource(path, { query = '', pollMs = 0, requester = request, onLoaded } = {}) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  // колбэк/запросчик — через ref: load остаётся стабильным между рендерами
  const onLoadedRef = useRef(onLoaded);
  const requesterRef = useRef(requester);
  useEffect(() => { onLoadedRef.current = onLoaded; });
  useEffect(() => { requesterRef.current = requester; });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setError('');
      const data = await requesterRef.current(path + query);
      setItems(data);
      if (onLoadedRef.current) onLoadedRef.current(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [path, query]);

  useEffect(() => {
    load();
    if (!pollMs) return undefined;
    const timer = setInterval(() => {
      // скрытая вкладка браузера — запросы не нужны, догоним при возврате
      if (document.visibilityState !== 'visible') return;
      load();
    }, pollMs);
    return () => clearInterval(timer);
  }, [load, pollMs]);

  return { items, setItems, loading, error, setError, load };
}
