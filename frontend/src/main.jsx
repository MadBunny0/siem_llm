import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const API = '/api/v1';
const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };

const TABS = [
  { id: 'incidents', icon: '◈', label: 'Инциденты' },
  { id: 'analyses', icon: '✦', label: 'Анализы' },
  { id: 'notifications', icon: '✉', label: 'Уведомления' },
  { id: 'audit', icon: '☰', label: 'Аудит' },
  { id: 'rules', icon: '⚡', label: 'Правила корреляции' },
  { id: 'playbooks', icon: '▶', label: 'Playbooks' },
];

const TAB_META = {
  incidents: { eyebrow: 'ЦЕНТР МОНИТОРИНГА', title: 'Инциденты информационной безопасности' },
  analyses: { eyebrow: 'LLM-АНАЛИТИКА', title: 'История анализов' },
  notifications: { eyebrow: 'КАНАЛЫ ОПОВЕЩЕНИЙ', title: 'Уведомления' },
  audit: { eyebrow: 'ЖУРНАЛ ДЕЙСТВИЙ', title: 'Аудит' },
  rules: { eyebrow: 'КОРРЕЛЯЦИЯ СОБЫТИЙ', title: 'Правила корреляции' },
  playbooks: { eyebrow: 'АВТОМАТИЗАЦИЯ РЕАГИРОВАНИЯ', title: 'Playbooks' },
};

const STATUS_LABELS = { new: 'Новый', in_progress: 'В работе', closed: 'Закрыт' };
const CONDITION_OPERATORS = ['eq', 'neq', 'in', 'like'];
const PRIORITIES = [1, 2, 3, 4];
const PRIORITY_LABELS = { 1: 'низкий', 2: 'средний', 3: 'высокий', 4: 'критический' };

function priorityLabel(priority) {
  if (priority === null || priority === undefined || priority === '') return '—';
  return PRIORITY_LABELS[priority] ? `${priority} · ${PRIORITY_LABELS[priority]}` : String(priority);
}
const PLAYBOOK_ACTIONS = ['monitor', 'collect_evidence', 'isolate_host', 'block_ip', 'disable_account'];
const NOTIFICATION_STATUS_CLASS = {
  sent: 'badge-status-sent',
  pending: 'badge-status-pending',
  failed: 'badge-status-failed',
};

/* ==================== Авторизация (JWT) ==================== */

const TOKEN_KEY = 'siem_token';
const USER_KEY = 'siem_user';
const AUTH_EXPIRED_EVENT = 'siem-auth-expired';

// Зеркало токена на уровне модуля: request() вызывается из всех вкладок без
// пропсов, поэтому токен хранится здесь, а состояние React (AuthGate)
// синхронизирует эту переменную при входе, выходе и истечении сессии.
let authToken = readStoredToken();

function readStoredToken() {
  try {
    return window.localStorage.getItem(TOKEN_KEY) || '';
  } catch (e) {
    return '';
  }
}

function setStoredToken(token) {
  authToken = token || '';
  try {
    if (authToken) window.localStorage.setItem(TOKEN_KEY, authToken);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch (e) {
    /* localStorage может быть недоступен — сессия просто не переживёт перезагрузку */
  }
}

function setStoredUser(user) {
  try {
    if (user) window.localStorage.setItem(USER_KEY, JSON.stringify(user));
    else window.localStorage.removeItem(USER_KEY);
  } catch (e) {
    /* ignore */
  }
}

function clearSession() {
  setStoredToken('');
  setStoredUser(null);
}

function detailToMessage(detail, fallback) {
  if (typeof detail === 'string' && detail) return detail;
  if (detail !== undefined && detail !== null) {
    try {
      const text = JSON.stringify(detail);
      if (text && text !== '{}') return text;
    } catch (e) {
      /* fallthrough */
    }
  }
  return fallback;
}

async function request(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  const response = await fetch(`${API}${path}`, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    // 401 — токен отсутствует/просрочен: сбрасываем сессию, AuthGate покажет экран входа.
    // 403 (недостаточно прав) пробрасывается дальше как обычная ошибка (alert/тост).
    if (response.status === 401) {
      clearSession();
      try {
        window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
      } catch (e) {
        /* ignore */
      }
    }
    throw new Error(detailToMessage(data && data.detail, `HTTP ${response.status}`));
  }
  return data;
}

async function loginRequest(username, password) {
  const data = await request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  if (!data || !data.access_token) {
    throw new Error('Сервер не вернул токен доступа');
  }
  setStoredToken(data.access_token);
  try {
    const me = await request('/auth/me');
    setStoredUser(me);
    return me;
  } catch (e) {
    clearSession();
    throw e;
  }
}

function formatDate(value) {
  if (!value) return '—';
  return new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value));
}

function confPct(value) {
  if (value === null || value === undefined || value === '') return '—';
  const num = Number(value);
  if (Number.isNaN(num)) return '—';
  return `${Math.round(num <= 1 ? num * 100 : num)}%`;
}

function Severity({ value }) {
  return <span className={`badge severity-${value || 'low'}`}>{value || 'low'}</span>;
}
function Status({ value }) {
  return <span className={`badge status-${value || 'new'}`}>{value || 'new'}</span>;
}

/* ==================== Stage 11: результаты по каждому действию ==================== */

// Нормализованный список результатов: новый формат (analysis.results — по одному
// на каждое действие из перечня LLM) с fallback на старый одиночный формат
// (validation/execution верхнего уровня).
function analysisResults(analysis) {
  if (!analysis) return [];
  if (Array.isArray(analysis.results) && analysis.results.length) return analysis.results;
  if (analysis.validation || analysis.execution) {
    return [{
      action: analysis.recommendation?.action ||
              analysis.recommendation?.recommended_action ||
              analysis.execution?.action,
      validation: analysis.validation,
      execution: analysis.execution,
    }];
  }
  return [];
}

// Действие требует ручного подтверждения администратора?
function resultNeedsConfirmation(result) {
  return result?.validation?.requires_confirmation === true ||
    result?.execution?.mode === 'pending_confirmation';
}

function resultsNeedConfirmation(results) {
  return (results || []).some(resultNeedsConfirmation);
}

// Причина из первого результата, ожидающего подтверждения (для плашки).
function pendingReasonText(freshAnalysis, storedAnalysis) {
  const sources = [freshAnalysis, storedAnalysis?.response_raw, storedAnalysis];
  for (const source of sources) {
    const pending = analysisResults(source).find(resultNeedsConfirmation);
    if (pending) {
      return pending.validation?.reason || pending.execution?.reason || '';
    }
  }
  return '';
}

// Бейдж решения DVE по одному результату.
function resultValidationBadge(result) {
  if (resultNeedsConfirmation(result)) return { cls: 'badge-pending', text: 'ОЖИДАЕТ ПОДТВЕРЖДЕНИЯ' };
  return result?.validation?.approved
    ? { cls: 'approved-text', text: 'РАЗРЕШЕНО' }
    : { cls: 'blocked-text', text: 'ЗАБЛОКИРОВАНО' };
}

// Бейдж режима исполнения по одному результату.
function resultExecutionBadge(result) {
  if (result?.execution?.executed) return { cls: 'executed-text', text: 'ВЫПОЛНЕНО' };
  if (resultNeedsConfirmation(result)) return { cls: 'badge-pending', text: 'ОЖИДАЕТ' };
  return { cls: 'simulated-text', text: 'СИМУЛЯЦИЯ' };
}

// [6] Бейдж источника анализа: поле initiated_by в Analysis.response_raw
// («auto_analysis» — автоанализ при создании critical-инцидента, «manual» — запуск вручную).
const INITIATED_BY_META = {
  auto_analysis: {
    cls: 'auto',
    text: 'авто (critical)',
    title: 'Автоматический анализ при создании critical-инцидента; LLM недетерминирована — повторный анализ может дать другой результат',
  },
  manual: {
    cls: 'manual',
    text: 'вручную',
    title: 'Анализ запущен вручную кнопкой «Запустить интеллектуальный анализ»',
  },
};

function initiatedByBadge(analysis) {
  let raw = analysis?.response_raw ?? analysis;
  if (typeof raw === 'string') {
    try {
      raw = JSON.parse(raw);
    } catch (e) {
      return null;
    }
  }
  return INITIATED_BY_META[raw?.initiated_by] || null;
}

// «1 критерий» / «3 критерия» / «5 критериев» — счётчик в таблице playbooks.
function criteriaCountLabel(count) {
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 === 1 && mod100 !== 11) return `${count} критерий`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return `${count} критерия`;
  return `${count} критериев`;
}

function PipelineStatus({ analysis, analysesLength, pendingConfirmation }) {
  const stages = [
    { id: 'wazuh', label: 'Wazuh' },
    { id: 'normalize', label: 'Normalize' },
    { id: 'correlate', label: 'Correlate' },
    { id: 'risk', label: 'Risk' },
    { id: 'qwen', label: 'Qwen' },
    { id: 'validate', label: 'Validate' },
    { id: 'playbook', label: 'Playbook' },
  ];

  // [8]+[9] Конвейер строится только по фактическим данным:
  //  - инцидент уже создан → Wazuh/Normalize/Correlate/Risk завершены всегда;
  //  - Qwen/Validate/Playbook завершены, только если есть хотя бы один анализ
  //    (свежий или в истории детали); иначе — pending независимо от статуса closed;
  //  - есть ожидающий подтверждения результат → Playbook в состоянии active с подписью;
  //  - статус closed на конвейер не влияет — он показан бейджем в шапке инцидента.
  const hasAnalysis = (analysesLength || 0) > 0 || !!analysis;

  return (
    <div className="pipeline-container">
      <div className="pipeline-title">КОНВЕЙЕР ОБРАБОТКИ</div>
      <div className="pipeline-steps">
        {stages.map((stage, index) => {
          const isLlmStage = stage.id === 'qwen' || stage.id === 'validate' || stage.id === 'playbook';
          const playbookAwaiting = stage.id === 'playbook' && pendingConfirmation;
          let status = 'completed';
          if (isLlmStage && !hasAnalysis) status = 'pending';
          if (playbookAwaiting) status = 'active';

          return (
            <React.Fragment key={stage.id}>
              <div className={`pipeline-stage ${status}`}>
                <div className="stage-label">{stage.label}</div>
                <div className="stage-status">
                  {status === 'completed' && '✓'}
                  {status === 'active' && '●'}
                  {status === 'pending' && '○'}
                </div>
                {playbookAwaiting && <div className="stage-note">ожидает подтверждения</div>}
              </div>
              {index < stages.length - 1 && (
                <div className={`pipeline-arrow ${status === 'completed' ? 'completed' : ''}`}>→</div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

/* ==================== Вкладка «Анализы» ==================== */

function AnalysesView({ onOpenIncident }) {
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

/* ==================== Вкладка «Уведомления» ==================== */

function NotificationsView() {
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

/* ==================== Вкладка «Аудит» ==================== */

function AuditView() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function load() {
    setLoading(true);
    try {
      setError('');
      setItems(await request('/audit-logs?limit=200'));
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

/* ==================== Вкладка «Правила корреляции» ==================== */

function RulesView({ notify, toastError, isAdmin }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [busyId, setBusyId] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(() => emptyRuleForm());

  function emptyRuleForm() {
    return {
      name: '',
      description: '',
      time_window_minutes: '10',
      min_events: '2',
      priority: 2,
      is_active: true,
      conditions: [{ field: '', operator: 'eq', value: '' }],
    };
  }

  async function load() {
    setLoading(true);
    try {
      setError('');
      setItems(await request('/correlation-rules'));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  function openCreate() {
    setEditing(null);
    setForm(emptyRuleForm());
    setShowForm(true);
  }

  function openEdit(rule) {
    const conditions = Array.isArray(rule.conditions) ? rule.conditions : [];
    setEditing(rule);
    setForm({
      name: rule.name || '',
      description: rule.description || '',
      time_window_minutes: String(rule.time_window_minutes ?? 10),
      min_events: String(rule.min_events ?? 2),
      priority: rule.priority === null || rule.priority === undefined ? 2 : Number(rule.priority),
      is_active: rule.is_active !== false,
      conditions: conditions.length
        ? conditions.map(c => ({
            field: c.field || '',
            operator: CONDITION_OPERATORS.includes(c.operator) ? c.operator : 'eq',
            value: Array.isArray(c.value)
              ? c.value.join(', ')
              : (c.value === null || c.value === undefined ? '' : String(c.value)),
          }))
        : [{ field: '', operator: 'eq', value: '' }],
    });
    setShowForm(true);
  }

  function updateCondition(index, patch) {
    setForm(f => ({ ...f, conditions: f.conditions.map((c, i) => (i === index ? { ...c, ...patch } : c)) }));
  }

  function addCondition() {
    setForm(f => ({ ...f, conditions: [...f.conditions, { field: '', operator: 'eq', value: '' }] }));
  }

  function removeCondition(index) {
    setForm(f => ({ ...f, conditions: f.conditions.length > 1 ? f.conditions.filter((_, i) => i !== index) : f.conditions }));
  }

  function buildPayload() {
    const conditions = form.conditions
      .filter(c => c.field.trim())
      .map(c => ({
        field: c.field.trim(),
        operator: c.operator,
        value: c.operator === 'in'
          ? c.value.split(',').map(v => v.trim()).filter(Boolean)
          : c.value,
      }));
    const priorityNumber = Number(form.priority);
    return {
      name: form.name.trim(),
      description: form.description.trim(),
      conditions,
      time_window_minutes: parseInt(form.time_window_minutes, 10) || 0,
      min_events: parseInt(form.min_events, 10) || 1,
      priority: Number.isFinite(priorityNumber) ? priorityNumber : 1,
      is_active: form.is_active,
    };
  }

  async function saveRule() {
    if (!form.name.trim()) {
      toastError('Укажите название правила корреляции');
      return;
    }
    if (!buildPayload().conditions.length) {
      toastError('Добавьте хотя бы одно условие с заполненным полем');
      return;
    }
    setBusy(true);
    try {
      const payload = buildPayload();
      if (editing) {
        await request(`/correlation-rules/${editing.id}`, { method: 'PUT', body: JSON.stringify(payload) });
        notify('Правило корреляции обновлено');
      } else {
        await request('/correlation-rules', { method: 'POST', body: JSON.stringify(payload) });
        notify('Правило корреляции создано');
      }
      setShowForm(false);
      setEditing(null);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function toggleActive(rule) {
    setBusyId(rule.id);
    try {
      const updated = await request(`/correlation-rules/${rule.id}`, {
        method: 'PUT',
        body: JSON.stringify({ ...rule, is_active: !rule.is_active }),
      });
      setItems(prev => prev.map(r => (r.id === rule.id ? { ...r, ...updated } : r)));
      notify(`Правило «${rule.name}» ${rule.is_active ? 'деактивировано' : 'активировано'}`);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  async function deleteRule(rule) {
    if (!window.confirm(`Удалить правило корреляции «${rule.name}»?`)) return;
    setBusyId(rule.id);
    try {
      await request(`/correlation-rules/${rule.id}`, { method: 'DELETE' });
      notify(`Правило «${rule.name}» удалено`);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  function conditionSummary(rule) {
    const list = Array.isArray(rule.conditions) ? rule.conditions : [];
    if (!list.length) return '—';
    return list
      .map(c => `${c.field || '?'} ${c.operator || 'eq'} ${Array.isArray(c.value) ? `[${c.value.join(', ')}]` : (c.value === null || c.value === undefined ? '—' : c.value)}`)
      .join('  AND  ');
  }

  const priorityOptions = PRIORITIES.includes(form.priority)
    ? PRIORITIES
    : [...PRIORITIES, form.priority].sort((a, b) => a - b);

  return (
    <div className="panel tab-panel">
      <div className="panel-head">
        <div>
          <h2>Правила корреляции</h2>
          <p>Правила объединения сырых событий в инциденты</p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="ghost" onClick={load} disabled={loading}>{loading ? <><span className="spinner spinner-dark"></span> Обновление...</> : '↻ Обновить'}</button>
          {isAdmin && <button className="primary" onClick={openCreate} disabled={busy}>＋ Новое правило</button>}
        </div>
      </div>
      {error && <div className="alert error">⚠ {error}</div>}
      {loading ? (
        <div className="empty">Загрузка данных...</div>
      ) : items.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">⚡</div>
          <h3>Правил пока нет</h3>
          <p>Создайте первое правило, чтобы события начали объединяться в инциденты.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Название</th>
                <th>Условия</th>
                <th>Окно</th>
                <th>События</th>
                <th>Приоритет</th>
                <th>Активно</th>
                {isAdmin && <th>Действия</th>}
              </tr>
            </thead>
            <tbody>
              {items.map(rule => (
                <tr key={rule.id}>
                  <td>
                    <strong>{rule.name}</strong>
                    {rule.description && <div className="rule-desc">{rule.description}</div>}
                  </td>
                  <td className="clamp">{conditionSummary(rule)}</td>
                  <td className="nowrap">{rule.time_window_minutes} мин</td>
                  <td>{rule.min_events}</td>
                  <td>{rule.priority ? <span className="chip">{priorityLabel(rule.priority)}</span> : '—'}</td>
                  <td>
                    {isAdmin ? (
                      <button
                        className={`toggle ${rule.is_active ? 'on' : ''}`}
                        onClick={() => toggleActive(rule)}
                        disabled={busyId === rule.id}
                        title={rule.is_active ? 'Деактивировать' : 'Активировать'}
                      >
                        <i></i>
                      </button>
                    ) : (
                      <span className="active-flag">{rule.is_active ? 'да' : 'нет'}</span>
                    )}
                  </td>
                  {isAdmin && (
                    <td>
                      <div className="row-actions">
                        <button className="ghost small" onClick={() => openEdit(rule)} disabled={busyId === rule.id}>Редактировать</button>
                        <button className="icon-btn" onClick={() => deleteRule(rule)} disabled={busyId === rule.id} title="Удалить правило">✕</button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showForm && isAdmin && (
        <div className="modal-overlay" onClick={() => setShowForm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <h3>{editing ? `Редактирование правила #${editing.id}` : 'Новое правило корреляции'}</h3>
            <p className="modal-subtitle">События, совпавшие по условиям в пределах временного окна, объединяются в инцидент</p>

            <div className="form-group">
              <label>Название *</label>
              <input
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder="Например: Brute force SSH"
              />
            </div>

            <div className="form-group">
              <label>Описание</label>
              <input
                value={form.description}
                onChange={e => setForm({ ...form, description: e.target.value })}
                placeholder="Что обнаруживает правило"
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
              <div className="form-group">
                <label>Окно, минут</label>
                <input
                  type="number"
                  min="1"
                  value={form.time_window_minutes}
                  onChange={e => setForm({ ...form, time_window_minutes: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label>Минимум событий</label>
                <input
                  type="number"
                  min="1"
                  value={form.min_events}
                  onChange={e => setForm({ ...form, min_events: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label>Приоритет</label>
                <select value={form.priority} onChange={e => setForm({ ...form, priority: Number(e.target.value) })}>
                  {priorityOptions.map(p => <option key={p} value={p}>{priorityLabel(p)}</option>)}
                </select>
              </div>
            </div>

            <div className="form-group">
              <label>Условия: поле / оператор / значение</label>
              {form.conditions.map((cond, index) => (
                <div className="condition-row" key={index}>
                  <input
                    placeholder="rule.id"
                    value={cond.field}
                    onChange={e => updateCondition(index, { field: e.target.value })}
                  />
                  <select value={cond.operator} onChange={e => updateCondition(index, { operator: e.target.value })}>
                    {CONDITION_OPERATORS.map(op => <option key={op} value={op}>{op}</option>)}
                  </select>
                  <input
                    placeholder={cond.operator === 'in' ? 'значение1, значение2' : 'значение'}
                    value={cond.value}
                    onChange={e => updateCondition(index, { value: e.target.value })}
                  />
                  <button
                    className="icon-btn"
                    onClick={() => removeCondition(index)}
                    disabled={form.conditions.length <= 1}
                    title="Удалить условие"
                  >
                    ✕
                  </button>
                </div>
              ))}
              <button className="ghost small" onClick={addCondition}>＋ Добавить условие</button>
            </div>

            <label className="checkbox-item standalone">
              <input
                type="checkbox"
                checked={form.is_active}
                onChange={e => setForm({ ...form, is_active: e.target.checked })}
              />
              <span>Правило активно</span>
            </label>

            <div className="form-actions">
              <button className="ghost" onClick={() => setShowForm(false)}>Отмена</button>
              <button className="primary" onClick={saveRule} disabled={busy}>
                {busy ? 'Сохранение...' : 'Сохранить правило'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ==================== Вкладка «Playbooks» ==================== */

function PlaybooksView({ notify, toastError, isAdmin }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [busyId, setBusyId] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(() => emptyPlaybookForm());

  function emptyPlaybookForm() {
    return {
      name: '',
      description: '',
      priority: 2,
      is_active: true,
      allowed_actions: ['monitor'],
      steps: '',
      success_criteria: '',
    };
  }

  async function load() {
    setLoading(true);
    try {
      setError('');
      setItems(await request('/playbooks'));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  function openCreate() {
    setEditing(null);
    setForm(emptyPlaybookForm());
    setShowForm(true);
  }

  function openEdit(rule) {
    setEditing(rule);
    setForm({
      name: rule.name || '',
      description: rule.description || '',
      priority: rule.priority === null || rule.priority === undefined ? 2 : Number(rule.priority),
      is_active: rule.is_active !== false,
      allowed_actions: Array.isArray(rule.allowed_actions)
        ? rule.allowed_actions.filter(a => PLAYBOOK_ACTIONS.includes(a))
        : [],
      steps: rule.steps === null || rule.steps === undefined ? '' : JSON.stringify(rule.steps, null, 2),
      // Stage 11: массив критериев сериализуется в строки — по одному на строку
      success_criteria: Array.isArray(rule.success_criteria) ? rule.success_criteria.join('\n') : '',
    });
    setShowForm(true);
  }

  function toggleAction(action, checked) {
    setForm(f => ({
      ...f,
      allowed_actions: checked
        ? [...f.allowed_actions, action]
        : f.allowed_actions.filter(a => a !== action),
    }));
  }

  async function savePlaybook() {
    if (!form.name.trim()) {
      toastError('Укажите название playbook');
      return;
    }
    if (!form.allowed_actions.length) {
      toastError('Выберите хотя бы одно разрешённое действие');
      return;
    }
    let steps = [];
    if (form.steps.trim()) {
      try {
        steps = JSON.parse(form.steps);
      } catch (e) {
        toastError(`Некорректный JSON в поле «Шаги»: ${e.message}`);
        return;
      }
      if (!Array.isArray(steps)) {
        toastError('Поле «Шаги» должно быть JSON-массивом, например [{"action": "isolate_host"}]');
        return;
      }
      if (!steps.every(item => item !== null && typeof item === 'object' && !Array.isArray(item))) {
        toastError('Каждый элемент «Шагов» должен быть JSON-объектом');
        return;
      }
    }
    const priorityNumber = Number(form.priority);
    // Stage 11: критерии успешного завершения — по одному на строку, пустые отбрасываем
    const successCriteria = form.success_criteria
      .split('\n')
      .map(line => line.trim())
      .filter(Boolean);
    const payload = {
      name: form.name.trim(),
      description: form.description.trim(),
      allowed_actions: form.allowed_actions,
      steps,
      success_criteria: successCriteria.length ? successCriteria : null,
      priority: Number.isFinite(priorityNumber) ? priorityNumber : 1,
      is_active: form.is_active,
    };
    if (editing) payload.trigger_conditions = editing.trigger_conditions ?? {};
    setBusy(true);
    try {
      if (editing) {
        await request(`/playbooks/${editing.id}`, { method: 'PUT', body: JSON.stringify(payload) });
        notify('Playbook обновлён');
      } else {
        await request('/playbooks', { method: 'POST', body: JSON.stringify(payload) });
        notify('Playbook создан');
      }
      setShowForm(false);
      setEditing(null);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function toggleActive(rule) {
    setBusyId(rule.id);
    try {
      const updated = await request(`/playbooks/${rule.id}`, {
        method: 'PUT',
        body: JSON.stringify({ ...rule, is_active: !rule.is_active }),
      });
      setItems(prev => prev.map(r => (r.id === rule.id ? { ...r, ...updated } : r)));
      notify(`Playbook «${rule.name}» ${rule.is_active ? 'деактивирован' : 'активирован'}`);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  async function deletePlaybook(rule) {
    if (!window.confirm(`Удалить playbook «${rule.name}»?`)) return;
    setBusyId(rule.id);
    try {
      await request(`/playbooks/${rule.id}`, { method: 'DELETE' });
      notify(`Playbook «${rule.name}» удалён`);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  const priorityOptions = PRIORITIES.includes(form.priority)
    ? PRIORITIES
    : [...PRIORITIES, form.priority].sort((a, b) => a - b);

  return (
    <div className="panel tab-panel">
      <div className="panel-head">
        <div>
          <h2>Playbooks реагирования</h2>
          <p>Сценарии автоматических действий по инцидентам</p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="ghost" onClick={load} disabled={loading}>{loading ? <><span className="spinner spinner-dark"></span> Обновление...</> : '↻ Обновить'}</button>
          {isAdmin && <button className="primary" onClick={openCreate} disabled={busy}>＋ Новый playbook</button>}
        </div>
      </div>
      {error && <div className="alert error">⚠ {error}</div>}
      {loading ? (
        <div className="empty">Загрузка данных...</div>
      ) : items.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">▶</div>
          <h3>Playbooks пока нет</h3>
          <p>Создайте сценарий, чтобы модуль Playbook Execution мог выполнять действия по инцидентам.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Название</th>
                <th>Разрешённые действия</th>
                <th>Шаги</th>
                <th>Приоритет</th>
                <th>Активен</th>
                {isAdmin && <th>Действия</th>}
              </tr>
            </thead>
            <tbody>
              {items.map(rule => (
                <tr key={rule.id}>
                  <td>
                    <strong>{rule.name}</strong>
                    {rule.description && <div className="rule-desc">{rule.description}</div>}
                  </td>
                  <td>
                    {(rule.allowed_actions || []).length
                      ? <div className="stack">{(rule.allowed_actions || []).map(a => <span key={a}>{a}</span>)}</div>
                      : '—'}
                  </td>
                  <td>
                    {Array.isArray(rule.steps) ? rule.steps.length : '—'}
                    {Array.isArray(rule.success_criteria) && rule.success_criteria.length > 0 && (
                      <span
                        className="chip accent criteria-chip"
                        title={rule.success_criteria.map((c, i) => `${i + 1}. ${c}`).join('\n')}
                      >
                        {criteriaCountLabel(rule.success_criteria.length)}
                      </span>
                    )}
                  </td>
                  <td>{rule.priority ? <span className="chip">{priorityLabel(rule.priority)}</span> : '—'}</td>
                  <td>
                    {isAdmin ? (
                      <button
                        className={`toggle ${rule.is_active ? 'on' : ''}`}
                        onClick={() => toggleActive(rule)}
                        disabled={busyId === rule.id}
                        title={rule.is_active ? 'Деактивировать' : 'Активировать'}
                      >
                        <i></i>
                      </button>
                    ) : (
                      <span className="active-flag">{rule.is_active ? 'да' : 'нет'}</span>
                    )}
                  </td>
                  {isAdmin && (
                    <td>
                      <div className="row-actions">
                        <button className="ghost small" onClick={() => openEdit(rule)} disabled={busyId === rule.id}>Редактировать</button>
                        <button className="icon-btn" onClick={() => deletePlaybook(rule)} disabled={busyId === rule.id} title="Удалить playbook">✕</button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showForm && isAdmin && (
        <div className="modal-overlay" onClick={() => setShowForm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <h3>{editing ? `Редактирование playbook #${editing.id}` : 'Новый playbook'}</h3>
            <p className="modal-subtitle">Определяет, какие действия разрешено выполнять автоматически по инциденту</p>

            <div className="form-group">
              <label>Название *</label>
              <input
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder="Например: Изоляция хоста при успешном брутфорсе"
              />
            </div>

            <div className="form-group">
              <label>Описание</label>
              <input
                value={form.description}
                onChange={e => setForm({ ...form, description: e.target.value })}
                placeholder="Когда и зачем применяется сценарий"
              />
            </div>

            <div className="form-group">
              <label>Разрешённые действия *</label>
              <div className="checkbox-row">
                {PLAYBOOK_ACTIONS.map(action => (
                  <label className="checkbox-item" key={action}>
                    <input
                      type="checkbox"
                      checked={form.allowed_actions.includes(action)}
                      onChange={e => toggleAction(action, e.target.checked)}
                    />
                    <span>{action}</span>
                  </label>
                ))}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div className="form-group">
                <label>Приоритет</label>
                <select value={form.priority} onChange={e => setForm({ ...form, priority: Number(e.target.value) })}>
                  {priorityOptions.map(p => <option key={p} value={p}>{priorityLabel(p)}</option>)}
                </select>
              </div>
              <div className="form-group">
                <label>Состояние</label>
                <label className="checkbox-item standalone" style={{ marginTop: '2px' }}>
                  <input
                    type="checkbox"
                    checked={form.is_active}
                    onChange={e => setForm({ ...form, is_active: e.target.checked })}
                  />
                  <span>Playbook активен</span>
                </label>
              </div>
            </div>

            <div className="form-group">
              <label>Шаги (JSON-массив)</label>
              <textarea
                className="mono"
                rows="6"
                value={form.steps}
                onChange={e => setForm({ ...form, steps: e.target.value })}
                placeholder={'[\n  { "order": 1, "action": "isolate_host", "description": "Изолировать скомпрометированный хост" }\n]'}
              />
            </div>

            <div className="form-group">
              <label>Критерии успешного завершения</label>
              <textarea
                rows="3"
                value={form.success_criteria}
                onChange={e => setForm({ ...form, success_criteria: e.target.value })}
                placeholder={'Необязательно, по одному критерию на строку, например:\nХост изолирован от корпоративной сети\nВредоносный IP-адрес добавлен в блок-лист'}
              />
            </div>

            <div className="form-actions">
              <button className="ghost" onClick={() => setShowForm(false)}>Отмена</button>
              <button className="primary" onClick={savePlaybook} disabled={busy}>
                {busy ? 'Сохранение...' : 'Сохранить playbook'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ==================== Экран входа ==================== */

function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    if (busy) return;
    if (!username.trim() || !password) {
      setError('Введите имя пользователя и пароль');
      return;
    }
    setBusy(true);
    setError('');
    try {
      await onLogin(username.trim(), password);
    } catch (err) {
      setError(err.message || 'Не удалось выполнить вход');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={submit}>
        <div className="brand-mark">S</div>
        <h1 className="login-title">SIEM Intelligence — вход</h1>
        <p className="login-subtitle">Введите учётные данные центра мониторинга</p>

        <div className="form-group">
          <label>Логин</label>
          <input
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="analyst1"
            autoComplete="username"
            autoFocus
          />
        </div>

        <div className="form-group">
          <label>Пароль</label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="••••••••"
            autoComplete="current-password"
          />
        </div>

        {error && <div className="login-error">⚠ {error}</div>}

        <button className="primary login-submit" type="submit" disabled={busy}>
          {busy ? '◌ Проверка учётных данных...' : 'Войти'}
        </button>

        <p className="login-hint">
          Демо-доступ: <b>analyst1 / analyst123</b> — аналитик · <b>soc_lead / soclead123</b> — администратор
        </p>
      </form>
    </div>
  );
}

/* ==================== Авторизация: корневой компонент ==================== */

function AuthGate() {
  const [user, setUser] = useState(null);
  const [booting, setBooting] = useState(() => !!readStoredToken());

  // Стартовая проверка сессии: если в localStorage есть siem_token —
  // запрашиваем GET /auth/me; при 401 request() уже очистил хранилище.
  useEffect(() => {
    let cancelled = false;
    async function bootstrap() {
      if (!authToken) {
        setBooting(false);
        return;
      }
      try {
        const me = await request('/auth/me');
        if (!cancelled) setUser(me);
      } catch (e) {
        if (!cancelled) clearSession();
      } finally {
        if (!cancelled) setBooting(false);
      }
    }
    bootstrap();
    return () => { cancelled = true; };
  }, []);

  // Истечение токена во время работы: request() отправляет событие —
  // сбрасываем user, интерфейс возвращается на экран входа.
  useEffect(() => {
    function handleExpired() { setUser(null); }
    window.addEventListener(AUTH_EXPIRED_EVENT, handleExpired);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, handleExpired);
  }, []);

  async function handleLogin(username, password) {
    const me = await loginRequest(username, password);
    setUser(me);
  }

  function handleLogout() {
    clearSession();
    setUser(null);
  }

  if (booting) {
    return (
      <div className="login-screen">
        <div className="login-card">
          <div className="brand-mark">S</div>
          <h1 className="login-title">SIEM Intelligence</h1>
          <p className="login-subtitle">Проверка сохранённой сессии...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return <App user={user} onLogout={handleLogout} />;
}

/* ==================== Приложение ==================== */

function App({ user, onLogout }) {
  const isAdmin = user?.role === 'admin';
  const [incidents, setIncidents] = useState([]);
  const [health, setHealth] = useState(null);
  const [selected, setSelected] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  // [5] Отдельные busy-флаги: спиннер показывается только на «своей» кнопке,
  // остальные на время любого запроса просто блокируются (anyBusy).
  const [analyzing, setAnalyzing] = useState(false);
  const [demoBusy, setDemoBusy] = useState(false);
  const [formBusy, setFormBusy] = useState(false);
  const [populateBusy, setPopulateBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [executeBusy, setExecuteBusy] = useState(null);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [toast, setToast] = useState('');
  const [errorToast, setErrorToast] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [activeTab, setActiveTab] = useState('incidents');

  const [incidentDetail, setIncidentDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [statusBusy, setStatusBusy] = useState(false);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [confirmedAction, setConfirmedAction] = useState(false);

  const [formData, setFormData] = useState({
    timestamp: new Date().toISOString().replace('Z', ''),
    rule_id: '5710',
    rule_level: '10',
    rule_description: 'sshd: Multiple authentication failures',
    rule_groups: 'authentication_failed,sshd',
    agent_id: '001',
    agent_name: 'test-linux',
    srcip: '192.0.2.10',
    dstuser: 'root',
    full_log: 'Failed password for root from 192.0.2.10 port 22 ssh2'
  });

  // Хотя бы один запрос в полёте — блокируем связанные кнопки, чтобы не плодить дубли.
  const anyBusy = analyzing || demoBusy || formBusy || populateBusy;

  function showToast(message) {
    setToast(message);
    setTimeout(() => setToast(''), 3500);
  }

  function showErrorToast(message) {
    setErrorToast(message);
    setTimeout(() => setErrorToast(''), 4500);
  }

  async function loadIncidentDetail(id) {
    // [5г] спиннер загрузки detail в карточке инцидента
    setDetailLoading(true);
    try {
      const detail = await request(`/incidents/${id}`);
      setIncidentDetail(detail);
    } catch (e) {
      setError(e.message);
    } finally {
      setDetailLoading(false);
    }
  }

  useEffect(() => {
    setIncidentDetail(null);
    setConfirmedAction(false);
    if (selected?.id) loadIncidentDetail(selected.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id]);

  async function load() {
    try {
      setError('');
      const [items, state] = await Promise.all([request('/incidents'), request('/health')]);
      setIncidents(items);
      setHealth(state);
      if (selected) {
        const fresh = items.find(x => x.id === selected.id);
        if (fresh) setSelected(fresh);
      }
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); const timer = setInterval(load, 10000); return () => clearInterval(timer); }, []);

  // [5в] Ручное обновление — спиннер на кнопке «Обновить».
  // Автообновление раз в 10с идёт через load() без индикатора, чтобы кнопка не мигала.
  async function refreshAll() {
    if (refreshing) return;
    setRefreshing(true);
    try {
      await load();
    } finally {
      setRefreshing(false);
    }
  }

  const filtered = useMemo(() => incidents
    .filter(i => filter === 'all' || i.severity === filter)
    .filter(i => !search || `${i.id} ${i.title} ${i.description}`.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => (severityOrder[b.severity] - severityOrder[a.severity]) || (new Date(b.created_at) - new Date(a.created_at))), [incidents, filter, search]);

  const stats = useMemo(() => ({
    total: incidents.length,
    critical: incidents.filter(i => i.severity === 'critical').length,
    high: incidents.filter(i => i.severity === 'high').length,
    active: incidents.filter(i => i.status !== 'closed').length,
  }), [incidents]);

  const lastDetailAnalysis = useMemo(() => {
    const list = incidentDetail?.analyses || [];
    if (!list.length) return null;
    return [...list].sort((a, b) =>
      (new Date(b.created_at) - new Date(a.created_at)) || ((b.id || 0) - (a.id || 0))
    )[0];
  }, [incidentDetail]);

  const pendingConfirmation = !!(
    !confirmedAction && (
      // свежий анализ: results по каждому действию (Stage 11) или validation/execution (старый формат)
      resultsNeedConfirmation(analysisResults(analysis)) ||
      // последний сохранённый анализ: бэкенд кладёт results в response_raw — плашка работает и после перезагрузки
      (lastDetailAnalysis && (
        resultsNeedConfirmation(analysisResults(lastDetailAnalysis.response_raw)) ||
        resultsNeedConfirmation(analysisResults(lastDetailAnalysis))
      ))
    )
  );

  const tabMeta = TAB_META[activeTab] || TAB_META.incidents;
  // [6] бейдж источника для свежего результата анализа
  const freshBadge = initiatedByBadge(analysis);

  async function runAnalysis() {
    if (!selected) return;
    // [5а] Предыдущий результат не сбрасываем: на время запроса он остаётся виден
    // затемнённым (.busy-dim), чтобы панель результата не «моргала».
    setAnalyzing(true); setError(''); setConfirmedAction(false);
    try {
      const result = await request(`/incidents/${selected.id}/analyze`, { method: 'POST' });
      setAnalysis(result);
      setToast('LLM-анализ завершён и рекомендация проверена');
      await load();
      await loadIncidentDetail(selected.id);
    } catch (e) { setError(e.message); }
    finally { setAnalyzing(false); setTimeout(() => setToast(''), 3500); }
  }

  async function changeStatus(status) {
    if (!selected || status === selected.status) return;
    setStatusBusy(true);
    try {
      const updated = await request(`/incidents/${selected.id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      });
      setSelected(prev => (prev && prev.id === updated?.id ? { ...prev, ...updated } : prev));
      await loadIncidentDetail(selected.id);
      await load();
      showToast(`Статус инцидента #${selected.id}: ${STATUS_LABELS[status] || status}`);
    } catch (e) { setError(e.message); }
    finally { setStatusBusy(false); }
  }

  async function confirmPendingAction() {
    if (!selected) return;
    setConfirmBusy(true);
    try {
      const result = await request(`/incidents/${selected.id}/confirm-action`, { method: 'POST' });
      // Stage 11: новый формат ответа — results по каждому действию;
      // старый формат — validation/execution верхнего уровня.
      const confirmResults = analysisResults(result);
      setAnalysis(prev => (prev
        ? {
            ...prev,
            validation: result?.validation ?? prev.validation,
            execution: result?.execution ?? prev.execution,
            results: confirmResults.length ? confirmResults : prev.results,
          }
        : prev));
      setConfirmedAction(true);
      if (confirmResults.length) {
        const realCount = confirmResults.filter(r => r.execution?.executed).length;
        const actions = confirmResults.map(r => r.action || '—').join(', ');
        setToast(`Подтверждено: ${confirmResults.length} действий исполнено, из них реальных: ${realCount} (${actions})`);
      } else {
        setToast(result?.execution?.executed
          ? `Действие выполнено: ${result.execution.action || result.execution.mode || 'готово'}`
          : 'Действие подтверждено администратором');
      }
      setTimeout(() => setToast(''), 3500);
      await loadIncidentDetail(selected.id);
      await load();
    } catch (e) { setError(e.message); }
    finally { setConfirmBusy(false); }
  }

  // Ручной запуск playbook-действия администратором: POST /incidents/{id}/execute-action.
  // DVE повторно проверяет действие; при AUTO_RESPONSE=false — режим симуляции.
  async function executeAction(action) {
    if (!selected || !action || executeBusy) return;
    setExecuteBusy(action);
    setError('');
    try {
      const result = await request(`/incidents/${selected.id}/execute-action`, {
        method: 'POST',
        body: JSON.stringify({ action }),
      });
      if (result?.execution?.executed) {
        showToast(`Действие ${action} выполнено (режим: ${result.execution.mode || '—'})`);
      } else {
        const reason = result?.execution?.reason || result?.validation?.reason || 'действие не выполнено';
        showErrorToast(`Заблокировано: ${reason}`);
      }
      // Обновляем бейджи у соответствующего результата (validation/execution из ответа).
      setAnalysis(prev => {
        if (!prev) return prev;
        const patch = r => (r.action === action
          ? { ...r, validation: result?.validation ?? r.validation, execution: result?.execution ?? r.execution }
          : r);
        if (Array.isArray(prev.results) && prev.results.length) {
          return { ...prev, results: prev.results.map(patch) };
        }
        return {
          ...prev,
          validation: result?.validation ?? prev.validation,
          execution: result?.execution ?? prev.execution,
        };
      });
      await loadIncidentDetail(selected.id);
      await load();
    } catch (e) {
      showErrorToast(`Не удалось выполнить действие: ${e.message}`);
    } finally {
      setExecuteBusy(null);
    }
  }

  // [12б] Мок-сценарии: POST /demo/populate (только admin) —
  // генерирует 18 событий → ~7 инцидентов всех уровней.
  async function populateDemo() {
    if (populateBusy) return;
    setPopulateBusy(true);
    setError('');
    try {
      const result = await request('/demo/populate', { method: 'POST' });
      const created = Array.isArray(result?.incidents) ? result.incidents : [];
      const counts = {};
      for (const inc of created) {
        const sev = inc?.severity || 'unknown';
        counts[sev] = (counts[sev] || 0) + 1;
      }
      const order = ['critical', 'high', 'medium', 'low'];
      const parts = order.filter(sev => counts[sev]).map(sev => `${sev}: ${counts[sev]}`);
      if (counts.unknown) parts.push(`другие: ${counts.unknown}`);
      showToast(created.length
        ? `Создано ${created.length} инцидентов: ${parts.join(', ')}`
        : 'События созданы, корреляция не сформировала инцидентов');
      await load();
    } catch (e) {
      showErrorToast(e.message);
    } finally {
      setPopulateBusy(false);
    }
  }

  async function openIncidentFromTab(incidentId) {
    if (incidentId === null || incidentId === undefined) return;
    setActiveTab('incidents');
    try {
      const known = incidents.find(x => x.id === incidentId);
      const incident = known || await request(`/incidents/${incidentId}`);
      setSelected(incident);
      setAnalysis(null);
    } catch (e) { setError(e.message); }
  }

  async function createDemo() {
    if (demoBusy) return;
    setDemoBusy(true); setError('');
    const demo = {
      timestamp: new Date().toISOString(),
      rule: { id: '5710', level: 10, description: 'sshd: Multiple authentication failures' },
      // [11а] seed-актив: по имени агента проставляются Актив и Критичность
      agent: { id: '001', name: 'mail-prod-01' },
      data: { srcip: '192.0.2.10', dstuser: 'root', ssh: { auth: { failure: true } } },
      full_log: 'Failed password for root from 192.0.2.10 port 22 ssh2'
    };
    try {
      const result = await request('/ingest/wazuh', { method: 'POST', body: JSON.stringify(demo) });
      await load();
      setToast(result.incident_id
        ? `Событие принято: инцидент #${result.incident_id}`
        : 'Событие сохранено: правила корреляции не сработали');
    } catch (e) { setError(e.message); }
    finally { setDemoBusy(false); setTimeout(() => setToast(''), 3500); }
  }

  async function createCustomEvent() {
    setFormBusy(true);
    setError('');

    const event = {
      timestamp: new Date(formData.timestamp).toISOString(),
      rule: {
        id: formData.rule_id,
        level: parseInt(formData.rule_level) || 5,
        description: formData.rule_description,
        groups: formData.rule_groups.split(',').map(g => g.trim())
      },
      agent: {
        id: formData.agent_id,
        name: formData.agent_name
      },
      data: {
        srcip: formData.srcip,
        dstuser: formData.dstuser
      },
      full_log: formData.full_log
    };

    try {
      const result = await request('/ingest/wazuh', { method: 'POST', body: JSON.stringify(event) });
      await load();
      setToast(result.incident_id
        ? `Событие создано: инцидент #${result.incident_id}`
        : 'Событие сохранено: правила корреляции не сработали');
      setShowForm(false);
      setFormData({
        timestamp: new Date().toISOString().replace('Z', ''),
        rule_id: '5710',
        rule_level: '10',
        rule_description: 'sshd: Multiple authentication failures',
        rule_groups: 'authentication_failed,sshd',
        agent_id: '001',
        agent_name: 'test-linux',
        srcip: '192.0.2.10',
        dstuser: 'root',
        full_log: 'Failed password for root from 192.0.2.10 port 22 ssh2'
      });
    } catch (e) {
      setError(e.message);
    } finally {
      setFormBusy(false);
      setTimeout(() => setToast(''), 3500);
    }
  }

  const handleSelectIncident = (incident) => {
    setSelected(incident);
    setAnalysis(null);
  };

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">S</div><div><strong>SIEM Intelligence</strong><small>LLM Incident Center</small></div></div>
      <nav>
        {TABS.map(tab => (
          <button
            key={tab.id}
            className={`nav-item ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.icon} <span>{tab.label}</span>
          </button>
        ))}
        <button className="nav-item" onClick={() => window.open('/docs', '_blank')}>⌘ <span>API / Swagger</span></button>
      </nav>
      <div className="user-box">
        <div className="user-meta">
          <div className="user-name">{user?.username || '—'}</div>
          <span className={`badge-role ${isAdmin ? 'admin' : ''}`}>
            {isAdmin ? 'администратор' : 'аналитик'}
          </span>
        </div>
        <button className="btn-logout" onClick={onLogout}>Выйти</button>
      </div>
    </aside>
    <main className="main">
      <header className="topbar">
        <div><div className="eyebrow">{tabMeta.eyebrow}</div><h1>{tabMeta.title}</h1></div>
        <div className="top-actions">
          <div className={`system-status ${health?.status === 'ok' ? 'online' : ''}`}><i></i>{health?.status === 'ok' ? 'Система работает' : 'Проверка...'}</div>
          <button className="ghost" onClick={refreshAll} disabled={refreshing}>
            {refreshing ? <><span className="spinner spinner-dark"></span> Обновление...</> : '↻ Обновить'}
          </button>
        </div>
      </header>
      {error && <div className="alert error">⚠ {error}</div>}
      {toast && <div className="toast">✓ {toast}</div>}
      {errorToast && <div className="toast toast-error">⚠ {errorToast}</div>}

      {activeTab === 'incidents' ? <>
        <section className="stats">
          <div className="stat"><span>Всего инцидентов</span><b>{stats.total}</b><em>за всё время</em></div>
          <div className="stat critical"><span>Критические</span><b>{stats.critical}</b><em>требуют внимания</em></div>
          <div className="stat high"><span>Высокий риск</span><b>{stats.high}</b><em>приоритетный анализ</em></div>
          <div className="stat"><span>Активные</span><b>{stats.active}</b><em>не закрыты</em></div>
        </section>
        <section className="workspace">
          <div className="panel incidents-panel">
            <div className="panel-head">
              <div><h2>Лента инцидентов</h2><p>События, нормализованные и объединённые корреляцией</p></div>
              <div className="panel-head-actions">
                <button className="primary" onClick={() => setShowForm(true)} disabled={anyBusy}>＋ Добавить событие</button>
                <button className="primary" onClick={createDemo} disabled={anyBusy}>
                  {demoBusy ? <><span className="spinner"></span> Отправка...</> : '＋ Тестовое событие'}
                </button>
                {isAdmin && (
                  <button
                    className="primary"
                    onClick={populateDemo}
                    disabled={anyBusy}
                    title="Сгенерировать мок-сценарии: 18 событий → ~7 инцидентов всех уровней (только администратор)"
                  >
                    {populateBusy ? <><span className="spinner"></span> Генерация...</> : '🎬 Мок-сценарии'}
                  </button>
                )}
              </div>
            </div>
            <div className="filters"><div className="search">⌕<input placeholder="Поиск по инцидентам..." value={search} onChange={e => setSearch(e.target.value)} /></div><div className="filter-tabs">{['all','critical','high','medium','low'].map(x => <button key={x} className={filter === x ? 'selected' : ''} onClick={() => setFilter(x)}>{x === 'all' ? 'Все' : x}</button>)}</div></div>
            {loading ? <div className="empty">Загрузка данных...</div> : filtered.length === 0 ? <div className="empty"><div className="empty-icon">✓</div><h3>Инцидентов пока нет</h3><p>Нажмите «Тестовое событие», чтобы проверить весь конвейер.</p></div> : <div className="incident-list">{filtered.map(i => <button className={`incident-row ${selected?.id === i.id ? 'selected-row' : ''}`} key={i.id} onClick={() => handleSelectIncident(i)}><div className={`risk-dot ${i.severity}`}></div><div className="incident-main"><div className="incident-title"><strong>#{i.id} · {i.title}</strong><Severity value={i.severity}/></div><p>{i.description || 'Описание отсутствует'}{i.attack_type ? ` · ${i.attack_type}` : ''}</p><span>Риск: {i.risk_score}{i.asset?.criticality ? ` · ${i.asset.criticality}` : ''} · {formatDate(i.created_at)}</span></div><Status value={i.status}/><span className="chevron">›</span></button>)}</div>}
          </div>
          <div className="panel detail-panel">
            {!selected ? <div className="detail-empty"><div className="radar">◉</div><h2>Выберите инцидент</h2><p>Здесь появятся контекст события, результат оценки риска и интеллектуальная рекомендация Qwen2.5-3B.</p></div> : <>
              <div className="detail-head"><div><span className="muted">ИНЦИДЕНТ #{selected.id}</span><h2>{selected.title}</h2></div><Severity value={selected.severity}/></div>

              {/* [7] Краткая памятка по роли аналитика — сворачиваемая */}
              <details className="role-hint">
                <summary>Роль аналитика — как работать с инцидентом</summary>
                <ol>
                  <li>Запустите интеллектуальный анализ (кнопка ниже) — одобренные DVE действия система выполняет автоматически (сейчас — симуляция).</li>
                  <li>При критическом активе DVE откладывает опасное действие — его подтверждает АДМИНИСТРАТОР кнопкой «Подтвердить и выполнить».</li>
                  <li>Админ может вручную запустить действие кнопкой ▶ на строке результата.</li>
                  <li>Меняйте статус инцидента кнопками блока «Изменить статус».</li>
                </ol>
              </details>

              <div className="detail-grid"><div><label>Статус</label><Status value={selected.status}/></div><div><label>Создан</label><span>{formatDate(selected.created_at)}</span></div><div><label>Уровень риска</label><span>{selected.risk_score} / 100</span></div><div><label>Тип атаки</label><span>{selected.attack_type || '-'}</span></div><div><label>Актив</label><span>{selected.asset?.name || '-'}</span></div><div><label>Критичность актива</label><span>{selected.asset?.criticality || '-'}</span></div></div>

              <div className="status-controls">
                <label>Изменить статус</label>
                <div className="status-buttons">
                  {['new', 'in_progress', 'closed'].map(s => (
                    <button
                      key={s}
                      className={`status-btn ${selected.status === s ? 'current' : ''}`}
                      onClick={() => changeStatus(s)}
                      disabled={statusBusy || selected.status === s}
                    >
                      {STATUS_LABELS[s]}
                    </button>
                  ))}
                </div>
              </div>

              <div className="section"><label>Описание</label><div className="description">{selected.description || 'Описание отсутствует.'}</div></div>

              {detailLoading && <div className="detail-loading"><span className="spinner spinner-dark"></span> Загрузка событий и истории анализов...</div>}

              <PipelineStatus
                analysis={analysis}
                analysesLength={(incidentDetail?.analyses || []).length}
                pendingConfirmation={pendingConfirmation}
              />

              {pendingConfirmation && (
                <div className="pending-banner">
                  <div>
                    <strong>Требуется подтверждение администратора</strong>
                    <span>
                      {pendingReasonText(analysis, lastDetailAnalysis) ||
                       'Рекомендованное действие превышает уровень автономности и ожидает вашего одобрения.'}
                    </span>
                  </div>
                  {isAdmin ? (
                    <button className="primary" onClick={confirmPendingAction} disabled={confirmBusy}>
                      {confirmBusy ? '◌ Выполняется...' : '✓ Подтвердить и выполнить'}
                    </button>
                  ) : (
                    <span className="pending-waiting">Ожидает подтверждения администратора</span>
                  )}
                </div>
              )}

              <button className="analyze" onClick={runAnalysis} disabled={anyBusy || analysis}>
                {analyzing ? <><span className="spinner"></span> Выполняется анализ...</> :
                 analysis ? '✓ Анализ выполнен' :
                 '✦ Запустить интеллектуальный анализ'}
              </button>

              {analysis && (
                <div className={`analysis-result${analyzing ? ' busy-dim' : ''}`}>
                  <div className="result-head">
                    <h3>Результат анализа</h3>
                    <span className="result-head-right">
                      {freshBadge && (
                        <span className={`initiated-badge ${freshBadge.cls}`} title={freshBadge.title}>{freshBadge.text}</span>
                      )}
                      <span className="approved">✓ Проверено</span>
                    </span>
                  </div>
                  <div className="recommendation">
                    <div>
                      <label>Рекомендованное действие</label>
                      <strong>
                        {analysis.recommendation?.action ||
                         analysis.recommendation?.recommended_action ||
                         '—'}
                      </strong>
                    </div>
                    <div>
                      <label>Уверенность</label>
                      <strong>
                        {analysis.recommendation?.confidence != null ?
                          `${Math.round(analysis.recommendation.confidence * 100)}%` :
                          '—'}
                    </strong>
                    </div>
                  </div>
                  <p>
                    {analysis.recommendation?.reason ||
                     analysis.recommendation?.explanation ||
                     'Модель не вернула текстовое обоснование.'}
                  </p>
                  {/* Stage 11: по одному результату на каждое действие из перечня LLM
                      (fallback на старый одиночный формат — см. analysisResults) */}
                  {analysisResults(analysis).map((r, index) => {
                    const validationBadge = resultValidationBadge(r);
                    const executionBadge = resultExecutionBadge(r);
                    return (
                      <div className="result-item" key={`${r.action || 'result'}-${index}`}>
                        <div className="result-head-row">
                          <span className="result-action">{r.action || 'действие'}</span>
                          <b className={validationBadge.cls}>{validationBadge.text}</b>
                          <b className={executionBadge.cls}>{executionBadge.text}</b>
                          {/* Ручной запуск одобренного DVE действия — только администратор */}
                          {isAdmin && r.action && r.validation?.approved === true && (
                            <button
                              className="exec-btn"
                              onClick={() => executeAction(r.action)}
                              disabled={!!executeBusy}
                              title="Запустить действие playbook вручную (только администратор)"
                            >
                              {executeBusy === r.action
                                ? <><span className="spinner spinner-sm"></span> Выполняется...</>
                                : '▶ Выполнить'}
                            </button>
                          )}
                        </div>
                        {(r.validation?.reason || r.execution?.reason) && (
                          <small className="result-reason">{r.validation?.reason || r.execution?.reason}</small>
                        )}
                      </div>
                    );
                  })}
                  <pre>{JSON.stringify(analysis.results ?? analysis.execution, null, 2)}</pre>
                </div>
              )}

              <div className="section">
                <label>Хронология событий {(incidentDetail?.events || []).length}</label>
                {(incidentDetail?.events || []).length ? (
                  <div className="timeline">
                    {incidentDetail.events.map(ev => (
                      <div className="timeline-item" key={ev.id ?? `${ev.timestamp}-${ev.source}-${ev.event_type}`}>
                        <div className="timeline-time">{formatDate(ev.timestamp)}</div>
                        <div className="timeline-body">
                          <div className="timeline-row">
                            <strong>{ev.event_type || 'Событие'}</strong>
                            {ev.source && <span className="chip">{ev.source}</span>}
                          </div>
                          <div className="timeline-meta">
                            {ev.user && <span>Пользователь: <b>{ev.user}</b></span>}
                            {ev.src_ip && <span>IP: <b>{ev.src_ip}</b></span>}
                            {ev.criticality_level !== null && ev.criticality_level !== undefined && <span>Критичность: <b>{ev.criticality_level}</b></span>}
                          </div>
                          {ev.raw_message && (
                            <details>
                              <summary>Исходное сообщение</summary>
                              <pre>{ev.raw_message}</pre>
                            </details>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : !detailLoading ? <div className="detail-hint">События не найдены.</div> : null}
              </div>

              <div className="section">
                <label>История анализов {(incidentDetail?.analyses || []).length}</label>
                {(incidentDetail?.analyses || []).length ? (
                  <div className="history-list">
                    {incidentDetail.analyses.map(a => {
                      // [6] бейдж источника анализа: initiated_by из response_raw
                      const badge = initiatedByBadge(a);
                      return (
                        <div className="history-item" key={a.id}>
                          <div className="history-head"><strong>{a.model || 'LLM'}</strong><span>{formatDate(a.created_at)}</span></div>
                          <div className="history-meta">
                            {badge && <span className={`initiated-badge ${badge.cls}`} title={badge.title}>{badge.text}</span>}
                            {a.attack_type && <span className="chip accent">{a.attack_type}</span>}
                            {a.confidence != null && <span className="chip">Уверенность: {confPct(a.confidence)}</span>}
                          </div>
                          {a.recommended_action && <div className="history-action">Действие: {a.recommended_action}</div>}
                          {a.explanation && <p>{a.explanation}</p>}
                        </div>
                      );
                    })}
                  </div>
                ) : !detailLoading ? <div className="detail-hint">Анализов ещё не было — запустите интеллектуальный анализ.</div> : null}
              </div>
            </>}
          </div>
        </section>
      </> : <section className="tab-content">
        {activeTab === 'analyses' && <AnalysesView onOpenIncident={openIncidentFromTab} />}
        {activeTab === 'notifications' && <NotificationsView />}
        {activeTab === 'audit' && <AuditView />}
        {activeTab === 'rules' && <RulesView notify={showToast} toastError={showErrorToast} isAdmin={isAdmin} />}
        {activeTab === 'playbooks' && <PlaybooksView notify={showToast} toastError={showErrorToast} isAdmin={isAdmin} />}
      </section>}

      <footer><span>Intelligent Incident Processing System · Prototype 1.0</span><span>Qwen2.5-3B · Ollama · PostgreSQL</span></footer>
    </main>

    {showForm && (
      <div className="modal-overlay" onClick={() => setShowForm(false)}>
        <div className="modal" onClick={e => e.stopPropagation()}>
          <h3>Добавить событие Wazuh</h3>
          <p className="modal-subtitle">
            Заполните поля для создания нового инцидента
          </p>

          <div className="form-group">
            <label>Описание правила</label>
            <input
              value={formData.rule_description}
              onChange={e => setFormData({...formData, rule_description: e.target.value})}
              placeholder="Например: SSH authentication failure"
            />
          </div>

          <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px'}}>
            <div className="form-group">
              <label>ID правила</label>
              <input
                value={formData.rule_id}
                onChange={e => setFormData({...formData, rule_id: e.target.value})}
                placeholder="5710"
              />
            </div>
            <div className="form-group">
              <label>Уровень (1-15)</label>
              <input
                type="number"
                min="1"
                max="15"
                value={formData.rule_level}
                onChange={e => setFormData({...formData, rule_level: e.target.value})}
              />
            </div>
          </div>

          <div className="form-group">
            <label>Группы (через запятую)</label>
            <input
              value={formData.rule_groups}
              onChange={e => setFormData({...formData, rule_groups: e.target.value})}
              placeholder="authentication_failed,sshd"
            />
          </div>

          <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px'}}>
            <div className="form-group">
              <label>ID агента</label>
              <input
                value={formData.agent_id}
                onChange={e => setFormData({...formData, agent_id: e.target.value})}
                placeholder="001"
              />
            </div>
            <div className="form-group">
              <label>Имя агента</label>
              <input
                value={formData.agent_name}
                onChange={e => setFormData({...formData, agent_name: e.target.value})}
                placeholder="server-01"
              />
            </div>
          </div>

          <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px'}}>
            <div className="form-group">
              <label>Source IP</label>
              <input
                value={formData.srcip}
                onChange={e => setFormData({...formData, srcip: e.target.value})}
                placeholder="192.168.1.100"
              />
            </div>
            <div className="form-group">
              <label>Пользователь</label>
              <input
                value={formData.dstuser}
                onChange={e => setFormData({...formData, dstuser: e.target.value})}
                placeholder="root"
              />
            </div>
          </div>

          <div className="form-group">
            <label>Время (ISO)</label>
            <input
              type="datetime-local"
              value={formData.timestamp}
              onChange={e => setFormData({...formData, timestamp: e.target.value})}
            />
          </div>

          <div className="form-group">
            <label>Полный лог</label>
            <textarea
              value={formData.full_log}
              onChange={e => setFormData({...formData, full_log: e.target.value})}
              placeholder="Failed password for root from 192.0.2.10 port 22 ssh2"
              rows="3"
              style={{width: '100%', padding: '8px', background: '#080e19', border: '1px solid #1d293e', borderRadius: '6px', color: '#dbe1ec', fontSize: '12px', fontFamily: 'monospace'}}
            />
          </div>

          <div className="form-actions">
            <button className="ghost" onClick={() => setShowForm(false)}>Отмена</button>
            <button className="primary" onClick={createCustomEvent} disabled={formBusy}>
              {formBusy ? <><span className="spinner"></span> Отправка...</> : 'Создать инцидент'}
            </button>
          </div>
        </div>
      </div>
    )}
  </div>
}

createRoot(document.getElementById('root')).render(<AuthGate />);
