// Вкладка «Аудит»: журнал действий системы (read-only).
// Вынесено из main.jsx (stage-19-legacy-cleanup); загрузка — общий хук
// useListResource (legacy-cleanup).

import React from 'react';
import { useListResource } from '../hooks/useListResource.js';
import { formatDate } from '../lib/helpers.js';

/* ==================== Вкладка «Аудит» ==================== */

export default function AuditView() {
  const { items, loading, error, load } = useListResource('/audit-logs', { query: '?limit=200' });

  return (
    <div className="panel tab-panel">
      <div className="panel-head">
        <div>
          <h2>Журнал аудита</h2>
          <p>Действия системы: корреляция, анализ, подтверждения и выполнение playbooks</p>
        </div>
        <button className="ghost" onClick={load} disabled={loading}>{loading ? <><span className="spinner spinner-dark"></span> Обновление...</> : '↻ Обновить'}</button>
      </div>
      {error && <div className="alert error">⚠ {error}</div>}
      {loading ? (
        <div className="empty">Загрузка данных...</div>
      ) : items.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">☰</div>
          <h3>Записей пока нет</h3>
          <p>Журнал заполняется по мере работы конвейера обработки.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th className="nowrap">Время</th>
                <th>Тип события</th>
                <th>Инцидент</th>
                <th>Детали</th>
              </tr>
            </thead>
            <tbody>
              {items.map(log => (
                <tr key={log.id}>
                  <td className="nowrap">{formatDate(log.timestamp)}</td>
                  <td><span className="badge badge-event">{log.event_type}</span></td>
                  <td>{log.incident_id !== null && log.incident_id !== undefined ? `#${log.incident_id}` : '—'}</td>
                  <td className="clamp">
                    {log.details === null || log.details === undefined || log.details === '' ? '—' : (
                      <details className="details-json">
                        <summary>Показать JSON</summary>
                        <pre>{typeof log.details === 'string' ? log.details : JSON.stringify(log.details, null, 2)}</pre>
                      </details>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
