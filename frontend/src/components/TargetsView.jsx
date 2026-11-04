// Вкладка «Агенты (ВМ)» (stage-20): цели реального исполнения playbook —
// endpoint-агенты на виртуальных машинах наблюдаемых пользователей.
// Возможности: статусы целей (heartbeat), журнал действий агента (прокси SIEM),
// сброс состояния эмулируемой ВМ (повторяемость демонстрации) и запуск
// активности наблюдаемого пользователя/атакующего (алерты Wazuh → SIEM).
// Отдельный файл — интеграция с main.jsx минимальна: компонент получает
// request как prop (fetch-обёртка с JWT-сессией живёт в main.jsx).
// См. docs/REAL_EXECUTION.md.

import React, { useEffect, useState } from 'react';
import { formatDate } from '../lib/helpers.js';

// Режимы исполнения playbook-действий (stage-20): экспортируется в main.jsx
// для переключателя в карточке инцидента; simulation — dry run по §3.4 ВКР.
export const EXECUTION_MODES = [
  { id: 'simulation', label: 'Симуляция (dry run)', hint: 'Действие не меняет инфраструктуру — показывается, что БЫЛО бы выполнено' },
  { id: 'real', label: 'Реально на ВМ', hint: 'Действие исполняется агентом на виртуальной машине наблюдаемого пользователя' },
];

// Сценарии активности агента: подобраны под seed-правила корреляции SIEM
// (docs/REAL_EXECUTION.md, таблица демонстрации) — каждый порождает
// инцидент соответствующего класса атаки.
export const SIMULATE_SCENARIOS = [
  { id: 'normal_activity', label: 'Фоновая активность пользователей' },
  { id: 'brute_force', label: 'Подбор пароля (T1110)' },
  { id: 'password_spraying', label: 'Распыление паролей (T1110.003)' },
  { id: 'repeated_scan', label: 'Сетевое сканирование (T1046)' },
  { id: 'web_attack', label: 'Веб-атака / SQL-инъекция (T1190)' },
  { id: 'malware', label: 'Вредоносное ПО (T1204)' },
  { id: 'privilege_escalation', label: 'Повышение привилегий (T1068)' },
  { id: 'data_exfiltration', label: 'Эксфильтрация данных (T1048)' },
];

const TARGET_STATUS_CLASS = {
  online: 'badge-status-sent',
  offline: 'badge-status-failed',
  unknown: 'badge-status-pending',
};

const TARGET_STATUS_RU = {
  online: 'онлайн',
  offline: 'недоступен',
  unknown: 'не проверялся',
};

function TargetsView({ request }) {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busyTarget, setBusyTarget] = useState(null);
  // журнал и активность — по выбранной цели
  const [journalTarget, setJournalTarget] = useState(null);
  const [journal, setJournal] = useState([]);
  const [activity, setActivity] = useState([]);
  // симуляция активности
  const [scenario, setScenario] = useState('brute_force');
  const [simCount, setSimCount] = useState(4);

  async function load() {
    setLoading(true);
    try {
      setError('');
      setTargets(await request('/execution-targets'));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function checkTarget(t) {
    setBusyTarget(t.id);
    try {
      await request(`/execution-targets/${t.id}/check`, { method: 'POST' });
      await load();
    } catch (e) {
      setError(e.message);
      await load();
    } finally {
      setBusyTarget(null);
    }
  }

  async function resetTarget(t) {
    if (!window.confirm(`Сбросить состояние ВМ «${t.name}» к исходному?`)) return;
    setBusyTarget(t.id);
    try {
      await request(`/execution-targets/${t.id}/reset`, { method: 'POST' });
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyTarget(null);
    }
  }

  async function showJournal(t) {
    setBusyTarget(t.id);
    try {
      const [j, a] = await Promise.all([
        request(`/execution-targets/${t.id}/journal?limit=30`),
        request(`/execution-targets/${t.id}/activity?limit=30`),
      ]);
      setJournalTarget(t);
      setJournal(j);
      setActivity(a);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyTarget(null);
    }
  }

  async function simulate(t) {
    setBusyTarget(t.id);
    try {
      const result = await request(`/execution-targets/${t.id}/simulate`, {
        method: 'POST',
        body: JSON.stringify({ scenario, count: simCount }),
      });
      const incidents = (result.results || [])
        .map(r => r.siem_response?.incident_id)
        .filter(id => id !== null && id !== undefined);
      if (incidents.length) {
        window.alert(`Сценарий «${scenario}» на ${t.name}: отправлено ${result.sent}, ошибок ${result.failed}.\nСозданы/обновлены инциденты: #${[...new Set(incidents)].join(', #')}`);
      } else {
        window.alert(`Сценарий «${scenario}» на ${t.name}: отправлено ${result.sent}, ошибок ${result.failed}.\nИнциденты не созданы (правила корреляции не сработали — см. ответ SIEM в журнале активности).`);
      }
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyTarget(null);
    }
  }

  return (
    <div className="panel tab-panel">
      <div className="panel-head">
        <div>
          <h2>Агенты (ВМ наблюдаемых пользователей)</h2>
          <p>Реальное исполнение playbook на виртуальных машинах (stage-20) — статусы, журналы, активность</p>
        </div>
        <button className="ghost" onClick={load} disabled={loading}>{loading ? <><span className="spinner spinner-dark"></span> Обновление...</> : '↻ Обновить'}</button>
      </div>
      {error && <div className="alert error">⚠ {error}</div>}
      {loading ? (
        <div className="empty">Загрузка данных...</div>
      ) : targets.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">⬡</div>
          <h3>Цели исполнения не зарегистрированы</h3>
          <p>Реестр наполняется из переменной EXECUTION_TARGETS (см. docs/REAL_EXECUTION.md). В compose по умолчанию — три агента-«ВМ».</p>
        </div>
      ) : (
        <>
          <div className="targets-grid">
            {targets.map(t => (
              <div key={t.id} className="target-card">
                <div className="target-head">
                  <b>{t.name}</b>
                  <span className={`badge ${TARGET_STATUS_CLASS[t.status] || 'status-new'}`}>{TARGET_STATUS_RU[t.status] || t.status}</span>
                </div>
                <div className="target-meta">
                  <span className="chip">{t.platform}</span>
                  <span className="chip">adapter: {t.adapter}</span>
                  {t.asset_id != null && <span className="chip">актив #{t.asset_id}</span>}
                </div>
                <small className="target-url">{t.base_url}</small>
                <small className="target-seen">
                  {t.last_seen ? `Ответ был: ${formatDate(t.last_seen)}` : 'Проверок не было'}
                </small>
                <div className="target-actions">
                  <button className="ghost" onClick={() => checkTarget(t)} disabled={!!busyTarget}>Проверить</button>
                  <button className="ghost" onClick={() => showJournal(t)} disabled={!!busyTarget}>Журнал</button>
                  <button className="ghost" onClick={() => resetTarget(t)} disabled={!!busyTarget} title="Сброс состояния эмулируемой ВМ — для повторного показа демо">Сбросить ВМ</button>
                </div>
                <div className="target-simulate">
                  <select value={scenario} onChange={e => setScenario(e.target.value)} aria-label="Сценарий активности">
                    {SIMULATE_SCENARIOS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
                  </select>
                  <input
                    type="number" min="1" max="50" value={simCount}
                    onChange={e => setSimCount(Number(e.target.value) || 1)}
                    aria-label="Количество событий активности"
                  />
                  <button className="ghost" onClick={() => simulate(t)} disabled={!!busyTarget} title="ВМ генерирует активность → алерты Wazuh → SIEM">
                    {busyTarget === t.id ? <><span className="spinner spinner-dark"></span> ...</> : 'Проиграть активность'}
                  </button>
                </div>
              </div>
            ))}
          </div>

          {journalTarget && (
            <div className="target-details">
              <div className="panel-head">
                <h3>Журнал ВМ «{journalTarget.name}»</h3>
                <button className="ghost" onClick={() => setJournalTarget(null)}>✕ Закрыть</button>
              </div>
              <div className="target-details-cols">
                <div>
                  <b>Действия SIEM (реагирование)</b>
                  {journal.length === 0 ? (
                    <div className="empty">Действий ещё не было — выполните действие playbook в режиме «Реально на ВМ»</div>
                  ) : (
                    <table className="table">
                      <thead>
                        <tr><th>Когда</th><th>Действие</th><th>Кто</th><th>Инцидент</th><th>Результат</th></tr>
                      </thead>
                      <tbody>
                        {journal.map((j, i) => (
                          <tr key={i}>
                            <td className="nowrap">{formatDate(j.at)}</td>
                            <td><span className="badge badge-event">{j.action}</span></td>
                            <td>{j.requested_by || '—'}</td>
                            <td>{j.incident_id != null ? `#${j.incident_id}` : '—'}</td>
                            <td>{j.detail || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
                <div>
                  <b>Активность узла (наблюдаемый пользователь / атакующий)</b>
                  {activity.length === 0 ? (
                    <div className="empty">Активности ещё не было — проиграйте сценарий на карточке агента</div>
                  ) : (
                    <table className="table">
                      <thead>
                        <tr><th>Когда</th><th>Активность</th><th>Алерт</th></tr>
                      </thead>
                      <tbody>
                        {activity.map((a, i) => (
                          <tr key={i}>
                            <td className="nowrap">{formatDate(a.at)}</td>
                            <td>{a.description}</td>
                            <td>{a.alert_sent ? '✓ отправлен' : '✕ ошибка'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default TargetsView;
