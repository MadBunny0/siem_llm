// Вкладка «Уведомления»: отправленные оповещения (read-only).
// Вынесено из main.jsx (stage-19-legacy-cleanup).

import React, { useEffect, useState } from 'react';
import { request } from '../api.js';
import { formatDate } from '../lib/helpers.js';
import { NOTIFICATION_STATUS_CLASS } from '../constants.js';

/* ==================== Вкладка «Уведомления» ==================== */

export default function NotificationsView() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function load() {
    setLoading(true);
    try {
      setError('');
      setItems(await request('/notifications'));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  return (
    <div className="panel tab-panel">
      <div className="panel-head">
        <div>
          <h2>Уведомления</h2>
          <p>Сообщения, отправленные по инцидентам через каналы оповещения</p>
        </div>
        <button className="ghost" onClick={load} disabled={loading}>{loading ? <><span className="spinner spinner-dark"></span> Обновление...</> : '↻ Обновить'}</button>
      </div>
      {error && <div className="alert error">⚠ {error}</div>}
      {loading ? (
        <div className="empty">Загрузка данных...</div>
      ) : items.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">✉</div>
          <h3>Уведомлений пока нет</h3>
          <p>Уведомления появляются после анализа инцидентов и срабатывания playbooks.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Тип события</th>
                <th>Получатель</th>
                <th>Канал</th>
                <th>Статус</th>
                <th>Инцидент</th>
                <th className="nowrap">Дата</th>
              </tr>
            </thead>
            <tbody>
              {items.map(n => (
                <tr key={n.id}>
                  <td><span className="badge badge-event">{n.event_type}</span></td>
                  <td>{n.recipient || '—'}</td>
                  <td><span className="chip">{n.channel || '—'}</span></td>
                  <td>
                    <span className={`badge ${NOTIFICATION_STATUS_CLASS[n.status] || 'status-new'}`}>{n.status}</span>
                  </td>
                  <td>{n.incident_id !== null && n.incident_id !== undefined ? `#${n.incident_id}` : '—'}</td>
                  <td className="nowrap">{formatDate(n.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
