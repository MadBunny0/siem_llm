// Вкладка «Анализы»: история LLM-анализов (read-only).
// Вынесено из main.jsx (stage-19-legacy-cleanup).

import React, { useEffect, useState } from 'react';
import { request } from '../api.js';
import { confPct, formatDate } from '../lib/helpers.js';

/* ==================== Вкладка «Анализы» ==================== */

export default function AnalysesView({ onOpenIncident }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function load() {
    setLoading(true);
    try {
      setError('');
      setItems(await request('/analyses'));
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
          <h2>История LLM-анализов</h2>
          <p>Результаты работы модели по всем инцидентам</p>
        </div>
        <button className="ghost" onClick={load} disabled={loading}>{loading ? <><span className="spinner spinner-dark"></span> Обновление...</> : '↻ Обновить'}</button>
      </div>
      {error && <div className="alert error">⚠ {error}</div>}
      {loading ? (
        <div className="empty">Загрузка данных...</div>
      ) : items.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">✦</div>
          <h3>Анализов пока нет</h3>
          <p>Запустите интеллектуальный анализ на вкладке «Инциденты».</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Модель</th>
                <th>Инцидент</th>
                <th>Тип атаки</th>
                <th>Уверенность</th>
                <th>Действие</th>
                <th>Обоснование</th>
                <th className="nowrap">Дата</th>
              </tr>
            </thead>
            <tbody>
              {items.map(a => (
                <tr key={a.id}>
                  <td><span className="chip accent">{a.model || '—'}</span></td>
                  <td>
                    <button className="link-btn" onClick={() => onOpenIncident(a.incident_id)} title="Открыть инцидент">
                      #{a.incident_id}
                    </button>
                  </td>
                  <td>{a.attack_type || '—'}</td>
                  <td><span className="chip">{confPct(a.confidence)}</span></td>
                  <td>{a.recommended_action || '—'}</td>
                  <td className="clamp">{a.explanation || '—'}</td>
                  <td className="nowrap">{formatDate(a.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
