import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const API = '/api/v1';
const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
  return data;
}

function formatDate(value) {
  if (!value) return '—';
  return new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value));
}

function Severity({ value }) {
  return <span className={`badge severity-${value || 'low'}`}>{value || 'low'}</span>;
}
function Status({ value }) {
  return <span className={`badge status-${value || 'new'}`}>{value || 'new'}</span>;
}

function PipelineStatus({ incident, analysis }) {
  const stages = [
    { id: 'wazuh', label: 'Wazuh' },
    { id: 'normalize', label: 'Normalize' },
    { id: 'correlate', label: 'Correlate' },
    { id: 'risk', label: 'Risk' },
    { id: 'qwen', label: 'Qwen' },
    { id: 'validate', label: 'Validate' },
    { id: 'playbook', label: 'Playbook' },
  ];

  let currentStage = 'wazuh';
  if (incident) {
    if (incident.risk_score !== undefined) currentStage = 'risk';
    if (incident.analyzed) currentStage = 'qwen';
    if (analysis) {
      if (analysis.validation) currentStage = 'validate';
      if (analysis.execution) currentStage = 'playbook';
    }
    if (incident.status === 'closed') currentStage = 'playbook';
  }

  const isCompleted = analysis && analysis.execution;

  return (
    <div className="pipeline-container">
      <div className="pipeline-title">КОНВЕЙЕР ОБРАБОТКИ</div>
      <div className="pipeline-steps">
        {stages.map((stage, index) => {
          let status = 'pending';
          let isCurrent = false;

          if (isCompleted) {
            status = 'completed';
          } else if (incident) {
            const stageIndex = stages.findIndex(s => s.id === stage.id);
            const currentIndex = stages.findIndex(s => s.id === currentStage);

            if (stageIndex < currentIndex) {
              status = 'completed';
            } else if (stageIndex === currentIndex) {
              status = 'active';
              isCurrent = true;
            } else {
              status = 'pending';
            }
          }

          return (
            <React.Fragment key={stage.id}>
              <div className={`pipeline-stage ${status}`}>
                <div className="stage-label">{stage.label}</div>
                <div className="stage-status">
                  {status === 'completed' && '✓'}
                  {status === 'active' && '●'}
                  {status === 'pending' && '○'}
                </div>
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

function App() {
  const [incidents, setIncidents] = useState([]);
  const [health, setHealth] = useState(null);
  const [selected, setSelected] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [toast, setToast] = useState('');
  const [showForm, setShowForm] = useState(false);

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

  async function runAnalysis() {
    if (!selected) return;
    setBusy(true); setAnalysis(null); setError('');
    try {
      const result = await request(`/incidents/${selected.id}/analyze`, { method: 'POST' });
      setAnalysis(result);
      setToast('LLM-анализ завершён и рекомендация проверена');
      await load();
    } catch (e) { setError(e.message); }
    finally { setBusy(false); setTimeout(() => setToast(''), 3500); }
  }

  async function createDemo() {
    setBusy(true); setError('');
    const demo = {
      timestamp: new Date().toISOString(),
      rule: { id: '5710', level: 10, description: 'sshd: Multiple authentication failures' },
      agent: { id: '001', name: 'demo-linux' },
      data: { srcip: '192.0.2.10', dstuser: 'root', ssh: { auth: { failure: true } } },
      full_log: 'Failed password for root from 192.0.2.10 port 22 ssh2'
    };
    try {
      const result = await request('/ingest/wazuh', { method: 'POST', body: JSON.stringify(demo) });
      await load();
      setToast(`Событие принято: инцидент #${result.incident_id}`);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); setTimeout(() => setToast(''), 3500); }
  }

  async function createCustomEvent() {
    setBusy(true);
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
      setToast(`Событие создано: инцидент #${result.incident_id}`);
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
      setBusy(false);
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
      <nav><button className="nav-item active">◈ <span>Инциденты</span></button><button className="nav-item" onClick={() => window.open('/docs', '_blank')}>⌘ <span>API / Swagger</span></button></nav>
    </aside>
    <main className="main">
      <header className="topbar"><div><div className="eyebrow">ЦЕНТР МОНИТОРИНГА</div><h1>Инциденты информационной безопасности</h1></div><div className="top-actions"><div className={`system-status ${health?.status === 'ok' ? 'online' : ''}`}><i></i>{health?.status === 'ok' ? 'Система работает' : 'Проверка...'}</div><button className="ghost" onClick={load}>↻ Обновить</button></div></header>
      {error && <div className="alert error">⚠ {error}</div>}
      {toast && <div className="toast">✓ {toast}</div>}
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
            <div style={{display: 'flex', gap: '8px'}}>
              <button className="primary" onClick={() => setShowForm(true)} disabled={busy}>＋ Добавить событие</button>
              <button className="primary" onClick={createDemo} disabled={busy}>＋ Тестовое событие</button>
            </div>
          </div>
          <div className="filters"><div className="search">⌕<input placeholder="Поиск по инцидентам..." value={search} onChange={e => setSearch(e.target.value)} /></div><div className="filter-tabs">{['all','critical','high','medium','low'].map(x => <button key={x} className={filter === x ? 'selected' : ''} onClick={() => setFilter(x)}>{x === 'all' ? 'Все' : x}</button>)}</div></div>
          {loading ? <div className="empty">Загрузка данных...</div> : filtered.length === 0 ? <div className="empty"><div className="empty-icon">✓</div><h3>Инцидентов пока нет</h3><p>Нажмите «Тестовое событие», чтобы проверить весь конвейер.</p></div> : <div className="incident-list">{filtered.map(i => <button className={`incident-row ${selected?.id === i.id ? 'selected-row' : ''}`} key={i.id} onClick={() => handleSelectIncident(i)}><div className={`risk-dot ${i.severity}`}></div><div className="incident-main"><div className="incident-title"><strong>#{i.id} · {i.title}</strong><Severity value={i.severity}/></div><p>{i.description || 'Описание отсутствует'}</p><span>{formatDate(i.created_at)}</span></div><Status value={i.status}/><span className="chevron">›</span></button>)}</div>}
        </div>
        <div className="panel detail-panel">
          {!selected ? <div className="detail-empty"><div className="radar">◉</div><h2>Выберите инцидент</h2><p>Здесь появятся контекст события, результат оценки риска и интеллектуальная рекомендация Qwen2.5-3B.</p></div> : <>
            <div className="detail-head"><div><span className="muted">ИНЦИДЕНТ #{selected.id}</span><h2>{selected.title}</h2></div><Severity value={selected.severity}/></div>
            <div className="detail-grid"><div><label>Статус</label><Status value={selected.status}/></div><div><label>Создан</label><span>{formatDate(selected.created_at)}</span></div><div><label>Модель</label><span>{health?.llm_model || 'qwen2.5:3b'}</span></div><div><label>Автоответ</label><span>{health?.auto_response ? 'Включён' : 'Симуляция'}</span></div></div>
            <div className="section"><label>Описание</label><div className="description">{selected.description || 'Описание отсутствует.'}</div></div>

            <PipelineStatus incident={selected} analysis={analysis} />

            <button className="analyze" onClick={runAnalysis} disabled={busy || analysis}>
              {busy ? '◌ Выполняется анализ...' :
               analysis ? '✓ Анализ выполнен' :
               '✦ Запустить интеллектуальный анализ'}
            </button>

            {analysis && (
              <div className="analysis-result">
                <div className="result-head">
                  <h3>Результат анализа</h3>
                  <span className="approved">✓ Проверено</span>
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
                <div className="validation">
                  <span>Decision Validation Engine</span>
                  <b className={analysis.validation?.approved ? 'approved-text' : 'blocked-text'}>
                    {analysis.validation?.approved ? 'РАЗРЕШЕНО' : 'ЗАБЛОКИРОВАНО'}
                  </b>
                  <small>{analysis.validation?.reason || ''}</small>
                </div>
                <div className="execution-result">
                  <span>Playbook Execution</span>
                  <b className={analysis.execution?.executed ? 'executed-text' : 'simulated-text'}>
                    {analysis.execution?.executed ? 'ВЫПОЛНЕНО' : 'СИМУЛЯЦИЯ'}
                  </b>
                  <small>Action: {analysis.execution?.action || '—'} · Mode: {analysis.execution?.mode || '—'}</small>
                </div>
                <pre>{JSON.stringify(analysis.execution, null, 2)}</pre>
              </div>
            )}
          </>}
        </div>
      </section>
      <footer><span>Intelligent Incident Processing System · Prototype 1.0</span><span>Qwen2.5-3B · Ollama · PostgreSQL</span></footer>
    </main>

    {showForm && (
      <div className="modal-overlay" onClick={() => setShowForm(false)}>
        <div className="modal" onClick={e => e.stopPropagation()}>
          <h3>Добавить событие Wazuh</h3>
          <p style={{color: '#68758b', fontSize: '11px', marginBottom: '20px'}}>
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
            <button className="primary" onClick={createCustomEvent} disabled={busy}>
              {busy ? 'Отправка...' : 'Создать инцидент'}
            </button>
          </div>
        </div>
      </div>
    )}
  </div>
}

createRoot(document.getElementById('root')).render(<App />);