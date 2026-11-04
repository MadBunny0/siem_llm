// Приложение: лента инцидентов, панель деталей, вкладки и модалка «Добавить событие Wazuh».
// Вынесено из main.jsx (stage-19-legacy-cleanup).

import React, { useEffect, useMemo, useRef, useState } from 'react';

import { actionRuDescription, actionShortLabel, analysisFromHistory, analysisResults, applyIncidentFilters,
         canConfirmAction, canRunAction, confPct, executionModeRu, formatDate, formatPlaybookSteps,
         initiatedByBadge, pendingReasonText,
         PLAYBOOK_ACTIONS, recommendedActionCodes,
         resultExecutionBadge, resultNeedsConfirmation, resultValidationBadge,
         resultsAwaitManualRun, resultsNeedConfirmation, ruleTemplateLabel, SEVERITY_LABELS,
         STATUS_LABELS, structuredAnalysis, verdictBadge }
  from './lib/helpers.js';
import PipelineStatus from './components/PipelineStatus.jsx';
import { Severity, Status } from './components/Badges.jsx';
import AnalysesView from './components/AnalysesView.jsx';
import NotificationsView from './components/NotificationsView.jsx';
import AuditView from './components/AuditView.jsx';
import RulesView from './components/RulesView.jsx';
import PlaybooksView from './components/PlaybooksView.jsx';
import { request } from './api.js';
import { ANALYSIS_BLOCK_LABELS, TABS, TAB_META, applyRuleTemplate, emptyEventForm, latestAnalysis } from './constants.js';

/* ==================== Приложение ==================== */

export default function App({ user, onLogout }) {
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
  // [15] Мультиселект-фильтры ленты: пустой массив = показывать все значения
  // группы (семантика «Все» без отдельной кнопки); группы сочетаются через AND.
  const [statusFilter, setStatusFilter] = useState([]);
  const [severityFilter, setSeverityFilter] = useState([]);
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
  // Защита от гонки при быстрой смене инцидентов: устаревшие ответы detail игнорируются.
  const detailReqRef = useRef(0);
  // [18] Актуальный id выбранного инцидента в ref: поллинг фонового анализа
  // сверяется с ним на каждой итерации и прерывается при смене инцидента
  // (значение из замыкания устарело бы — ref всегда синхронен с selected).
  const selectedIdRef = useRef(null);
  useEffect(() => { selectedIdRef.current = selected?.id ?? null; }, [selected?.id]);

  const [formData, setFormData] = useState(() => emptyEventForm());

  // [15] Справочник подсказок формы «Добавить событие Wazuh» (GET /ingest/reference):
  // правила Wazuh, группы, агенты, активы инвентаря, пользователи, IP-адреса.
  const [reference, setReference] = useState(null);
  const [templateId, setTemplateId] = useState('');

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

  // [15] Клик по чипу мультиселект-фильтра: toggle значения; можно выбрано
  // несколько в каждой группе, пустой набор = показывать все значения группы.
  function toggleFilterValue(setter, value) {
    setter(prev => (prev.includes(value) ? prev.filter(v => v !== value) : [...prev, value]));
  }

  async function loadIncidentDetail(id) {
    // [5г] спиннер загрузки detail в карточке инцидента
    const reqId = ++detailReqRef.current;
    setDetailLoading(true);
    try {
      const detail = await request(`/incidents/${id}`);
      if (reqId !== detailReqRef.current) return; // ответ устарел — инцидент уже сменён
      setIncidentDetail(detail);
      // [2] Восстановление последней рекомендации: если свежего анализа нет,
      // панель результата собирается из последнего анализа истории.
      const last = latestAnalysis(detail?.analyses);
      if (last) setAnalysis(prev => prev || analysisFromHistory(last));
    } catch (e) {
      if (reqId === detailReqRef.current) setError(e.message);
    } finally {
      if (reqId === detailReqRef.current) setDetailLoading(false);
    }
  }

  useEffect(() => {
    setIncidentDetail(null);
    setConfirmedAction(false);
    // [2] при смене инцидента результат предыдущего сбрасывается, затем панель
    // восстанавливается из истории нового инцидента (в loadIncidentDetail)
    setAnalysis(null);
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

  // [15] Справочник подсказок грузим при каждом открытии модалки (данные должны
  // быть достаточно свежими); ошибка загрузки глотается — форма остаётся
  // полностью ручной, подсказки просто не появляются.
  useEffect(() => {
    if (!showForm) return;
    let cancelled = false;
    setTemplateId('');
    request('/ingest/reference')
      .then(data => { if (!cancelled) setReference(data || null); })
      .catch(() => { /* справочник не критичен для формы */ });
    return () => { cancelled = true; };
  }, [showForm]);

  // [15] Подсказка «Имя агента»: объединение имён активов инвентаря и агентов
  // Wazuh — известное имя привязывает событие к активу (влияет на оценку риска).
  const agentNameHints = useMemo(() => {
    const names = [];
    for (const a of reference?.assets || []) if (a?.name && !names.includes(a.name)) names.push(a.name);
    for (const a of reference?.agents || []) if (a?.name && !names.includes(a.name)) names.push(a.name);
    return names;
  }, [reference]);

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

  // [15] Фильтрация ленты вынесена в чистую функцию applyIncidentFilters (тестируется в vitest).
  const filtered = useMemo(() => applyIncidentFilters(incidents, {
    statuses: statusFilter,
    severities: severityFilter,
    search,
  }), [incidents, statusFilter, severityFilter, search]);

  // [16] Фильтры активны (выбран чип хотя бы в одной группе или непустой поиск) —
  // рядом с группами показываем счётчик «из N» и кнопку сброса.
  const filtersActive = statusFilter.length > 0 || severityFilter.length > 0 || search.trim() !== '';

  const stats = useMemo(() => ({
    total: incidents.length,
    critical: incidents.filter(i => i.severity === 'critical').length,
    high: incidents.filter(i => i.severity === 'high').length,
    active: incidents.filter(i => i.status !== 'closed').length,
  }), [incidents]);

  const lastDetailAnalysis = useMemo(() => latestAnalysis(incidentDetail?.analyses), [incidentDetail]);

  // [15] Инцидент закреплён за другим аналитиком: кнопки статуса неактивны
  // (бэкенд всё равно вернул бы 403 — stage-14), подсказка объясняет, кто владелец.
  const foreignOwner = !isAdmin &&
    !!incidentDetail?.analyst?.username &&
    incidentDetail.analyst.username !== user?.username;

  // [16] Инцидент закрыт: запрещены все манипуляции, кроме возврата в работу —
  // смена статуса, повторный анализ, запуск и подтверждение действий.
  const incidentClosed = selected?.status === 'closed';

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

  // [17] Ручной режим (medium/high/critical): есть действия, ожидающие запуска
  // оператором — конвейер показывает Playbook как активный этап
  const awaitingManualRun = resultsAwaitManualRun(analysisResults(analysis));

  // [18] Структурированные поля вердикта LLM: у свежего анализа — в recommendation,
  // у панели из истории — в response_raw.recommendation (см. structuredAnalysis).
  const structured = useMemo(() => structuredAnalysis(analysis), [analysis]);

  // [18] Результаты анализа по каждому действию — для бокса «Предложенные действия»
  const resultItems = analysisResults(analysis);

  // [18] Отметки «действие запускали вручную» — теперь СЕРВЕРНЫЕ: приходят в
  // Incident.manual_actions (GET /incidents/{id}) как
  // { [action]: { mode, at, by } } и видны всем операторам, а не только
  // в localStorage того, кто запускал.
  const manualRuns = incidentDetail?.manual_actions || {};

  const tabMeta = TAB_META[activeTab] || TAB_META.incidents;
  // [6] бейдж источника для свежего результата анализа
  const freshBadge = initiatedByBadge(analysis);
  // [2] панель, восстановленная из истории, не блокирует повторный запуск анализа
  const hasFreshAnalysis = !!analysis && !analysis.fromHistory;
  // [18] Статус «анализ выполнен» — серверный: инцидент с непустой историей
  // анализов считается проанализированным. Переживает смену таски и
  // перезагрузку, виден другим операторам; повторный запуск — ссылкой рядом.
  const analysisDone = hasFreshAnalysis || (incidentDetail?.analyses || []).length > 0;

  // [18] Фоновый анализ (фидбек: синхронный POST /analyze падал 504 на долгом
  // инференсе Ollama): POST мгновенно возвращает { analysis: { scheduled: true } },
  // сам инференс выполняется на бэкенде, а результат добираем опросом истории
  // анализов инцидента.
  async function runAnalysis() {
    if (!selected) return;
    // [5а] Предыдущий результат не сбрасываем: на время запроса он остаётся виден
    // затемнённым (.busy-dim), чтобы панель результата не «моргала».
    setAnalyzing(true); setError(''); setConfirmedAction(false);
    const polledId = selected.id;
    // [18] Отметка времени ДО POST: «свежим» считаем только анализ, созданный
    // после запуска, — прошлые записи и автоанализы не подхватываются.
    const startedAt = new Date();
    try {
      const result = await request(`/incidents/${polledId}/analyze`, { method: 'POST' });
      if (result?.analysis?.scheduled) {
        showToast('Анализ запущен — выполняется в фоне');
        // [18] Поллинг: до 120 итераций с паузой 2500мс (~5 минут). Разовый сбой
        // GET не рвёт ожидание; при смене инцидента (selectedIdRef) — выход,
        // analyzing сбрасывается в finally.
        for (let attempt = 0; attempt < 120; attempt += 1) {
          await new Promise(resolve => setTimeout(resolve, 2500));
          if (selectedIdRef.current !== polledId) return;
          let detail = null;
          try {
            detail = await request(`/incidents/${polledId}`);
          } catch (pollError) {
            continue; // разовый сбой сети/бэкенда — пробуем на следующей итерации
          }
          const found = latestAnalysis(
            (detail?.analyses || []).filter(a => new Date(a.created_at) > startedAt)
          );
          if (found) {
            // Панель из записи истории, но fromHistory: false — кнопка анализа
            // показывает «✓ Анализ выполнен», бейдж «вручную» придёт из response_raw.
            setAnalysis({ ...analysisFromHistory(found), fromHistory: false });
            await load();
            await loadIncidentDetail(polledId);
            return;
          }
        }
        showErrorToast('Анализ не завершился за отведённое время — проверьте историю анализов позже');
      }
    } catch (e) { setError(e.message); }
    finally { setAnalyzing(false); }
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
      // [16] Успех = симуляция (dry run при AUTO_RESPONSE=false) или реальное
      // исполнение; reason при симуляции — текст одобрения DVE, а не ошибка.
      const success = result?.execution?.mode === 'simulation' || result?.execution?.executed === true;
      if (success) {
        showToast(`Действие выполнено (${executionModeRu(result.execution.mode) || 'готово'}): ${actionRuDescription(action)}`);
      } else if (result?.execution?.mode === 'pending_confirmation') {
        showErrorToast(`Действие отложено: ${result?.execution?.reason || 'требуется подтверждение администратора'}`);
      } else {
        const reason = result?.execution?.reason || result?.validation?.reason || 'действие не выполнено';
        showErrorToast(`Не выполнено: ${reason}`);
      }
      // Обновляем бейджи у соответствующего результата (validation/execution из ответа).
      // [16] При успехе помечаем совпавший результат run_manually: кнопка «Выполнить»
      // сменяется отметкой «Выполнено». Только при успехе — при
      // pending_confirmation/blocked отметка не ставится.
      // [18] Дубль отметки ведёт сервер (Incident.manual_actions): она попадает
      // в состояние через loadIncidentDetail(selected.id) ниже и видна всем операторам.
      const executionPatch = success
        ? { ...result.execution, run_manually: true }
        : (result?.execution ?? null);
      setAnalysis(prev => {
        if (!prev) return prev;
        const patch = r => (r.action === action
          ? { ...r, validation: result?.validation ?? r.validation, execution: executionPatch ?? r.execution }
          : r);
        if (Array.isArray(prev.results) && prev.results.length) {
          return { ...prev, results: prev.results.map(patch) };
        }
        return {
          ...prev,
          validation: result?.validation ?? prev.validation,
          execution: executionPatch ?? prev.execution,
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

  // [18] Сброс серверных отметок «действие запускали вручную»: POST /reset-actions
  // очищает Incident.manual_actions (владелец/админ; чужой аналитик → 403,
  // закрытый инцидент → 409). Деталь перезагружаем — кнопки снова активны.
  async function resetActionMarks() {
    if (!selected) return;
    try {
      await request(`/incidents/${selected.id}/reset-actions`, { method: 'POST' });
      await loadIncidentDetail(selected.id);
      showToast('Отметки выполненных действий сброшены');
    } catch (e) {
      showErrorToast(e.message);
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
      // [17] populate запускает фоновый автоанализ (AUTO_ANALYSIS_LEVELS):
      // low пройдёт автоконвейер (анализ → исполнение → закрытие); остальные
      // уровни анализирует и запускает оператор
      const scheduled = Number(result?.auto_analysis_scheduled) || 0;
      showToast(created.length
        ? `Создано ${created.length} инцидентов: ${parts.join(', ')}${scheduled ? ` · автоанализ запущен: ${scheduled}` : ''}`
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
      // [2] повторное открытие того же инцидента панель результата не сбрасывает
      const sameId = selected?.id === incident.id;
      setSelected(incident);
      if (!sameId) setAnalysis(null);
    } catch (e) { setError(e.message); }
  }

  // [15] Тестовое событие: бэкенд сам генерирует сценарий (POST /demo/test-event)
  // и возвращает результат корреляции; тост называет сценарий и исход.
  async function createDemo() {
    if (demoBusy) return;
    setDemoBusy(true); setError('');
    try {
      const data = await request('/demo/test-event', { method: 'POST' });
      await load();
      const result = data?.result || {};
      const scenarioTitle = data?.scenario_title || data?.scenario || 'событие';
      setToast(result.correlated
        ? `🎲 Событие: ${scenarioTitle} → инцидент #${result.incident_id} (${result.severity})`
        : `🎲 Событие: ${scenarioTitle} → правила корреляции не сработали`);
    } catch (e) { showErrorToast(e.message); }
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
      setFormData(emptyEventForm());
      setTemplateId('');
    } catch (e) {
      setError(e.message);
    } finally {
      setFormBusy(false);
      setTimeout(() => setToast(''), 3500);
    }
  }

  const handleSelectIncident = (incident) => {
    // [2] клик по уже выбранному инциденту не сбрасывает панель результата
    const sameId = selected?.id === incident.id;
    setSelected(incident);
    if (!sameId) setAnalysis(null);
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
                <button
                  className="primary"
                  onClick={createDemo}
                  disabled={anyBusy}
                  title="Случайный мок-сценарий из набора событий: брутфорс, распыление паролей, сканирование, SQLi, вредоносное ПО и др."
                >
                  {demoBusy ? <><span className="spinner"></span> Отправка...</> : '🎲 Тестовое событие'}
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
            {/* [15] Мультиселект-фильтры: клик по чипу — toggle, можно несколько в группе;
                пустой выбор группы = показывать все значения (семантика «Все» без кнопки) */}
            <div className="filters"><div className="search">⌕<input placeholder="Поиск по инцидентам..." value={search} onChange={e => setSearch(e.target.value)} /></div><div className="filter-group"><span className="filter-group-label">Статус</span><div className="filter-tabs">{Object.entries(STATUS_LABELS).map(([value, label]) => <button key={value} className={statusFilter.includes(value) ? 'selected' : ''} onClick={() => toggleFilterValue(setStatusFilter, value)}>{label}</button>)}</div></div><div className="filter-group"><span className="filter-group-label">Критичность</span><div className="filter-tabs">{Object.entries(SEVERITY_LABELS).map(([value, label]) => <button key={value} className={severityFilter.includes(value) ? 'selected' : ''} onClick={() => toggleFilterValue(setSeverityFilter, value)}>{label}</button>)}</div></div>
              {/* [16] Счётчик и сброс — делают мультиселект-фильтры заметнее */}
              <span className="filter-count">Показано: {filtered.length}{filtersActive ? ` из ${incidents.length}` : ''}</span>
              {filtersActive && (
                <button className="filter-reset" title="Сбросить статус, критичность и поиск" onClick={() => { setStatusFilter([]); setSeverityFilter([]); setSearch(''); }}>✕ Сбросить</button>
              )}
            </div>
            {loading ? <div className="empty">Загрузка данных...</div> : filtered.length === 0 ? <div className="empty"><div className="empty-icon">✓</div><h3>Инцидентов пока нет</h3><p>Нажмите «Тестовое событие», чтобы проверить весь конвейер.</p></div> : <div className="incident-list">{filtered.map(i => <button className={`incident-row ${selected?.id === i.id ? 'selected-row' : ''}`} key={i.id} onClick={() => handleSelectIncident(i)}><div className={`risk-dot ${i.severity}`}></div><div className="incident-main"><div className="incident-title"><strong>#{i.id} · {i.title}</strong><Severity value={i.severity}/></div><p>{i.description || 'Описание отсутствует'}{i.attack_type ? ` · ${i.attack_type}` : ''}</p><span>Риск: {i.risk_score}{i.asset?.criticality ? ` · ${i.asset.criticality}` : ''} · {formatDate(i.created_at)}</span></div><Status value={i.status}/><span className="chevron">›</span></button>)}</div>}
          </div>
          <div className="panel detail-panel">
            {!selected ? <div className="detail-empty"><div className="radar">◉</div><h2>Выберите инцидент</h2><p>Здесь появятся контекст события, результат оценки риска и интеллектуальная рекомендация Qwen2.5-3B.</p></div> : <>
              <div className="detail-head"><div><span className="muted">ИНЦИДЕНТ #{selected.id}</span><h2>{selected.title}</h2></div><Severity value={selected.severity}/></div>

              {/* [7] Краткая памятка по роли аналитика — сворачиваемая */}
              <details className="role-hint">
                <summary>Роль аналитика — как работать с инцидентом</summary>
                <ol>
                  <li>Запустите интеллектуальный анализ (кнопка ниже) — анализ выполняется в фоне, результат появится в панели сам. Одобренные DVE действия low-инцидентов выполняются автоматически (сейчас — симуляция).</li>
                  <li>При критическом активе DVE откладывает опасное действие — его подтверждает АДМИНИСТРАТОР кнопкой «Подтвердить и выполнить».</li>
                  <li>Админ может вручную запустить действие кнопкой ▶ на строке результата.</li>
                  <li>Меняйте статус инцидента кнопками блока «Изменить статус».</li>
                </ol>
              </details>

              <div className="detail-grid"><div><label>Статус</label><Status value={selected.status}/></div><div><label>Создан</label><span>{formatDate(selected.created_at)}</span></div><div><label>Уровень риска</label><span>{selected.risk_score} / 100</span></div><div><label>Тип атаки</label><span>{selected.attack_type || '-'}</span></div><div><label>Актив</label><span>{selected.asset?.name || '-'}</span></div><div><label>Критичность актива</label><span>{selected.asset?.criticality || '-'}</span></div><div><label>Назначен</label><span className="assignee-cell">{incidentDetail?.analyst?.username ? (<><span className="assignee-badge" title={incidentDetail.analyst.role ? `Роль: ${incidentDetail.analyst.role}` : 'Закреплённый аналитик'}>{incidentDetail.analyst.username}</span>{incidentDetail.analyst.username === user?.username && <span className="assignee-badge mine" title="Инцидент закреплён за вами">твой</span>}</>) : <span className="assignee-badge none" title="Инцидент ещё не закреплён — закрепляется при первом анализе или смене статуса">не закреплён</span>}</span></div></div>

              <div className="status-controls">
                <label>Изменить статус</label>
                <div className="status-buttons">
                  {['new', 'in_progress', 'closed'].map(s => (
                    <button
                      key={s}
                      className={`status-btn ${selected.status === s ? 'current' : ''}`}
                      onClick={() => changeStatus(s)}
                      // [16] из closed доступен только возврат в работу
                      disabled={statusBusy || selected.status === s || foreignOwner || (incidentClosed && s !== 'in_progress')}
                    >
                      {STATUS_LABELS[s]}
                    </button>
                  ))}
                </div>
                {foreignOwner && (
                  <small className="status-hint">
                    Инцидент закреплён за {incidentDetail.analyst.username} — статус
                    может менять владелец или администратор.
                  </small>
                )}
                {incidentClosed && (
                  <small className="status-hint">
                    Инцидент закрыт — доступен возврат в работу.
                  </small>
                )}
              </div>

              <div className="section"><label>Описание</label><div className="description">{selected.description || 'Описание отсутствует.'}</div></div>

              {detailLoading && <div className="detail-loading"><span className="spinner spinner-dark"></span> Загрузка событий и истории анализов...</div>}

              <PipelineStatus
                analysis={analysis}
                analysesLength={(incidentDetail?.analyses || []).length}
                pendingConfirmation={pendingConfirmation}
                awaitingManualRun={awaitingManualRun}
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
                    <button className="primary" onClick={confirmPendingAction} disabled={confirmBusy || incidentClosed}>
                      {confirmBusy ? '◌ Выполняется...' : '✓ Подтвердить и выполнить'}
                    </button>
                  ) : (
                    <span className="pending-waiting">Ожидает подтверждения администратора</span>
                  )}
                </div>
              )}

              {/* [2]/[18] Статус кнопки анализа — СЕРВЕРНЫЙ (история анализов инцидента):
                  «✓ Анализ выполнен» не сбрасывается при смене таски и перезагрузке и
                  виден другим операторам; повторный запуск — ссылкой «↻ Повторить анализ»
                  (LLM недетерминирована, повторный анализ — нормальное действие оператора);
                  [16] на закрытом инциденте анализ недоступен до возврата в работу */}
              <div className="analyze-row">
                <button className="analyze" onClick={runAnalysis} disabled={anyBusy || analysisDone || incidentClosed}>
                  {analyzing ? <><span className="spinner"></span> Выполняется анализ...</> :
                   incidentClosed ? 'Инцидент закрыт — верните в работу' :
                   analysisDone ? '✓ Анализ выполнен' :
                   '✦ Запустить интеллектуальный анализ'}
                </button>
                {analysisDone && !analyzing && !incidentClosed && (
                  <button
                    className="link-btn analyze-rerun"
                    onClick={runAnalysis}
                    disabled={anyBusy}
                    title="Запустить повторный LLM-анализ — модель недетерминирована, результат может отличаться"
                  >
                    ↻ Повторить анализ
                  </button>
                )}
              </div>

              {analysis && (
                <div className={`analysis-result${analyzing ? ' busy-dim' : ''}`}>
                  <div className="result-head">
                    <h3>Результат анализа</h3>
                    <span className="result-head-right">
                      {freshBadge && (
                        <span className={`initiated-badge ${freshBadge.cls}`} title={freshBadge.title}>{freshBadge.text}</span>
                      )}
                      {/* [2] отдельный признак «откуда показаны данные» — не путать с авто/вручную */}
                      {analysis?.fromHistory && (
                        <span className="initiated-badge history" title="Показан результат последнего анализа; запусти анализ заново для свежего">из истории</span>
                      )}
                      <span className="approved">✓ Проверено</span>
                    </span>
                  </div>
                  {/* [18] Строка вердикта LLM; у старых анализов вердикта нет — бейдж не показываем */}
                  <div className="verdict-row">
                    {structured.verdict && (
                      <span
                        className={`badge ${verdictBadge(structured.verdict).cls}`}
                        title={verdictBadge(structured.verdict).title}
                      >
                        {verdictBadge(structured.verdict).text}
                      </span>
                    )}
                    <span className="verdict-confidence">Уверенность: <b>{confPct(analysis.recommendation?.confidence)}</b></span>
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
                  </div>
                  {/* [18] Резюме анализа; у старых анализов summary нет — прежний текст обоснования */}
                  {structured.summary ? (
                    <div className="analysis-block">
                      <label>Резюме</label>
                      <p>{structured.summary}</p>
                    </div>
                  ) : (
                    <p>
                      {analysis.recommendation?.reason ||
                       analysis.recommendation?.explanation ||
                       'Модель не вернула текстовое обоснование.'}
                    </p>
                  )}
                  {/* [18] Структурированные блоки анализа — рендерим только непустые списки */}
                  {ANALYSIS_BLOCK_LABELS.filter(([field]) => structured[field].length > 0).map(([field, label]) => (
                    <div className="analysis-block" key={field}>
                      <label>{label}</label>
                      <ul>
                        {structured[field].map((line, i) => <li key={i}>{line}</li>)}
                      </ul>
                    </div>
                  ))}
                  {structured.process_tree.length > 0 && (
                    <div className="analysis-block">
                      <label>Дерево процессов</label>
                      <pre className="process-tree">{structured.process_tree.join('\n')}</pre>
                    </div>
                  )}
                  {/* [18] Предложенные действия — отдельные боксы (result-item) внутри общего бокса;
                      Stage 11: по одному результату на каждое действие из перечня LLM
                      (fallback на старый одиночный формат — см. analysisResults) */}
                  <div className="proposed-actions">
                    <span className="box-label">Предложенные действия (проверка DVE)</span>
                    {resultItems.length === 0 ? (
                      <div className="proposed-empty">Действий не предложено</div>
                    ) : resultItems.map((r, index) => {
                    const validationBadge = resultValidationBadge(r);
                    const executionBadge = resultExecutionBadge(r);
                    // [1] Одна главная кнопка по состоянию результата: ожидает подтверждения →
                    // «Подтвердить и выполнить», одобрено → «Выполнить: <русское описание>»,
                    // заблокировано → кнопки нет (виден reason).
                    const needsConfirm = resultNeedsConfirmation(r);
                    // [15] Подтверждение отложенного — только админ; ручной запуск
                    // одобренного — админ или владелец инцидента (незакреплённый
                    // закрепляется при запуске). DVE-политика всё равно проверяется
                    // на бэкенде, при AUTO_RESPONSE=false исполнение — dry run.
                    // [16] На закрытом инциденте обе кнопки недоступны.
                    const canConfirm = canConfirmAction(r, isAdmin, incidentClosed);
                    const canExecute = canRunAction(r, {
                      isAdmin,
                      username: user?.username || null,
                      ownerUsername: incidentDetail?.analyst?.username || null,
                      incidentClosed,
                    });
                    // [18] «Выполнено»: run_manually из React-состояния или серверная
                    // отметка manual_actions (видна всем операторам)
                    const isDone = r.execution?.run_manually === true || !!manualRuns[r.action];
                    return (
                      <div className="result-item" key={`${r.action || 'result'}-${index}`}>
                        <div className="result-head-row">
                          <span className="result-action">{r.action || 'действие'}</span>
                          <b className={validationBadge.cls}>{validationBadge.text}</b>
                          <b className={executionBadge.cls}>{executionBadge.text}</b>
                          {canConfirm && (
                            <button
                              className="exec-btn exec-confirm"
                              onClick={confirmPendingAction}
                              disabled={confirmBusy}
                              title="Действие ожидает подтверждения администратора"
                            >
                              {confirmBusy
                                ? <><span className="spinner spinner-sm"></span> Выполняется...</>
                                : '✓ Подтвердить и выполнить'}
                            </button>
                          )}
                          {/* [16]/[18] Действие уже запускали вручную: кнопка сменяется
                              отметкой «Выполнено» (для симуляции — dry run) */}
                          {isDone ? (
                            <button
                              className="exec-btn exec-run"
                              disabled
                              title="Действие уже запускали вручную; повторный запуск — после нового анализа (сухой run повторяем)"
                            >
                              ✓ Выполнено{((r.execution?.mode ?? manualRuns[r.action]?.mode) === 'simulation') ? ' (dry run)' : ''}
                            </button>
                          ) : canExecute && (
                            /* Ручной запуск одобренного DVE действия — владелец инцидента или администратор;
                               [18] на кнопке только короткая подпись — полное описание строкой ниже и в tooltip */
                            <button
                              className="exec-btn exec-run"
                              onClick={() => executeAction(r.action)}
                              disabled={!!executeBusy}
                              title={`Запустить действие playbook вручную (при симуляции — dry run): ${actionRuDescription(r.action)}`}
                            >
                              {executeBusy === r.action
                                ? <><span className="spinner spinner-sm"></span> Выполняется...</>
                                : <>▶ {actionShortLabel(r.action)}</>}
                            </button>
                          )}
                        </div>
                        {/* [3] Русская расшифровка кода действия */}
                        <div className="result-action-ru">{actionRuDescription(r.action)}</div>
                        {/* [1] Описание сценария из БД (playbook_description, stage-14) */}
                        {r.execution?.playbook_description && (
                          <small className="playbook-desc">Сценарий: {r.execution.playbook_description}</small>
                        )}
                        {/* [15] Шаги сценария — «команды» действия: при симуляции показываем,
                            что БЫЛО БЫ выполнено, при реальном исполнении — что выполнено;
                            [17] manual_run — шаги запустит оператор кнопкой «▶ Выполнить» */}
                        {formatPlaybookSteps(r.execution?.playbook_steps).length > 0 && (
                          <div className="result-steps">
                            <label>
                              {r.execution?.mode === 'simulation'
                                ? 'Что было бы выполнено (симуляция):'
                                : r.execution?.mode === 'controlled'
                                  ? 'Шаги сценария (выполнено):'
                                  : r.execution?.mode === 'manual_run'
                                    ? 'Шаги сценария (запустит оператор):'
                                    : 'Шаги сценария:'}
                            </label>
                            <ol>
                              {formatPlaybookSteps(r.execution.playbook_steps).map((line, i) => (
                                <li key={i}>{line}</li>
                              ))}
                            </ol>
                          </div>
                        )}
                        {(r.validation?.reason || r.execution?.reason) && (
                          <small className="result-reason">{r.validation?.reason || r.execution?.reason}</small>
                        )}
                      </div>
                    );
                  })}
                  </div>
                  {/* [18] Все действия playbook — отдельный бокс рядом с предложенными
                      действиями: пользователю доступны все кнопки плейбука; отметки
                      «Выполнено» серверные (Incident.manual_actions) — видны всем операторам */}
                  <div className="playbook-actions-box">
                    <div className="box-label-row">
                      <span className="box-label">Все действия playbook</span>
                      {Object.keys(manualRuns).length > 0 && (
                        <button
                          className="link-btn"
                          onClick={resetActionMarks}
                          title="Сбросить серверные отметки «Выполнено» у кнопок playbook этого инцидента"
                        >
                          Сбросить отметки
                        </button>
                      )}
                    </div>
                    <div className="playbook-actions-grid">
                      {PLAYBOOK_ACTIONS.map(a => {
                        const runDone = !!manualRuns[a];
                        const mode = manualRuns[a]?.mode;
                        return (
                          <button
                            key={a}
                            className={`pb-action-btn${runDone ? ' done' : ''}`}
                            onClick={() => executeAction(a)}
                            disabled={runDone || !!executeBusy || incidentClosed || foreignOwner}
                            title={runDone
                              ? `Действие выполнил: ${manualRuns[a].by || '—'} · ${formatDate(manualRuns[a].at)}${mode === 'simulation' ? ' · dry run' : ''}`
                              : actionRuDescription(a)}
                          >
                            {runDone ? '✓ Выполнено' : actionShortLabel(a)}
                          </button>
                        );
                      })}
                    </div>
                    {/* [18] Сводка «кто что запустил» прямо в карточке — серверные
                        отметки, видны всем операторам */}
                    {Object.keys(manualRuns).length > 0 && (
                      <div className="playbook-actions-done">
                        {Object.entries(manualRuns).map(([action, info]) => (
                          <span key={action} className="chip">
                            {actionShortLabel(action)} — {info?.by || '—'}{info?.mode === 'simulation' ? ' (dry run)' : ''}
                          </span>
                        ))}
                      </div>
                    )}
                    <small className="playbook-actions-hint">
                      Запуск проверяется DVE; при выключенном AUTO_RESPONSE — симуляция (dry run). Свободный инцидент закрепляется за вами.
                    </small>
                  </div>
                  {/* [15] Сырой JSON убран под сворачиваемый блок: технические данные
                      не должны сбивать с толку — человекочитаемая часть (бейджи DVE,
                      русские описания, reason) остаётся сверху */}
                  <details className="result-raw">
                    <summary>Технические данные (JSON)</summary>
                    <pre>{JSON.stringify(analysis.results ?? analysis.execution, null, 2)}</pre>
                  </details>
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
                      // [3] русские расшифровки действий из recommended_action («block_ip, isolate_host»)
                      const actionCodes = recommendedActionCodes(a.recommended_action);
                      // [18] вердикт LLM из структурированного ответа (response_raw.recommendation,
                      // у записей истории может быть строкой JSON — structuredAnalysis распарсит)
                      const verdict = structuredAnalysis({ response_raw: a.response_raw }).verdict;
                      return (
                        <div className="history-item" key={a.id}>
                          <div className="history-head"><strong>{a.model || 'LLM'}</strong><span>{formatDate(a.created_at)}</span></div>
                          <div className="history-meta">
                            {badge && <span className={`initiated-badge ${badge.cls}`} title={badge.title}>{badge.text}</span>}
                            {verdict && <span className="chip">{verdict}</span>}
                            {a.attack_type && <span className="chip accent">{a.attack_type}</span>}
                            {a.confidence != null && <span className="chip">Уверенность: {confPct(a.confidence)}</span>}
                          </div>
                          {a.recommended_action && (
                            <div className="history-action">
                              Действие: {a.recommended_action}
                              {actionCodes.length > 0 && (
                                <div className="history-action-ru">
                                  {actionCodes.map((code, i) => <div key={`${code}-${i}`}>{actionRuDescription(code)}</div>)}
                                </div>
                              )}
                            </div>
                          )}
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
            Выбери шаблон атаки — технические поля заполнятся автоматически. От критичности
            актива зависит оценка риска и требования подтверждения (DVE)
          </p>

          {/* [15] Шаблон события — варианты из справочника /ingest/reference (правила Wazuh);
              выбор заполняет поля правила, но не блокирует дальнейшую правку */}
          <div className="form-group">
            <label>Шаблон события</label>
            <select
              value={templateId}
              onChange={e => {
                const id = e.target.value;
                setTemplateId(id);
                const rule = (reference?.rules || []).find(r => String(r.id) === id) || null;
                setFormData(f => applyRuleTemplate(rule, f));
              }}
            >
              <option value="">— заполнить вручную —</option>
              {(reference?.rules || []).map(r => <option key={r.id} value={String(r.id)}>{ruleTemplateLabel(r)}</option>)}
            </select>
          </div>

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
              <label>ID правила Wazuh</label>
              <input
                value={formData.rule_id}
                onChange={e => setFormData({...formData, rule_id: e.target.value})}
                placeholder="5710"
                list="ref-rule-ids"
              />
            </div>
            <div className="form-group">
              <label>Уровень правила (1–15)</label>
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
            <label>Группы события (через запятую)</label>
            <input
              value={formData.rule_groups}
              onChange={e => setFormData({...formData, rule_groups: e.target.value})}
              placeholder="authentication_failed,sshd"
              list="ref-groups"
            />
            <small className="form-hint">По группам правила корреляции распознают тип атаки — значения можно выбрать из списка</small>
          </div>

          <div className="form-group">
            <label>Имя агента</label>
            <small className="form-hint">Известное имя агента привязывает событие к активу из инвентаря — критичность актива влияет на оценку риска</small>
            <input
              value={formData.agent_name}
              onChange={e => setFormData({...formData, agent_name: e.target.value})}
              placeholder="mail-prod-01"
              list="ref-agent-names"
              title="Известное имя агента привязывает событие к активу из инвентаря (влияет на оценку риска)"
            />
          </div>

          <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px'}}>
            <div className="form-group">
              <label>ID агента Wazuh</label>
              <input
                value={formData.agent_id}
                onChange={e => setFormData({...formData, agent_id: e.target.value})}
                placeholder="001"
                list="ref-agent-ids"
              />
            </div>
            <div className="form-group">
              <label>Время (ISO)</label>
              <input
                type="datetime-local"
                value={formData.timestamp}
                onChange={e => setFormData({...formData, timestamp: e.target.value})}
              />
            </div>
          </div>

          <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px'}}>
            <div className="form-group">
              <label>Source IP (источник)</label>
              <input
                value={formData.srcip}
                onChange={e => setFormData({...formData, srcip: e.target.value})}
                placeholder="198.51.100.7"
                list="ref-src-ips"
              />
            </div>
            <div className="form-group">
              <label>Пользователь</label>
              <input
                value={formData.dstuser}
                onChange={e => setFormData({...formData, dstuser: e.target.value})}
                placeholder="root"
                list="ref-users"
              />
            </div>
          </div>

          {/* [15] Справочные подсказки (datalist не ограничивает свободный ввод);
              id уникальны, источники — справочник /ingest/reference */}
          <datalist id="ref-rule-ids">
            {(reference?.rules || []).map(r => <option key={r.id} value={String(r.id)} />)}
          </datalist>
          <datalist id="ref-groups">
            {(reference?.groups || []).map(g => <option key={g} value={g} />)}
          </datalist>
          <datalist id="ref-agent-names">
            {agentNameHints.map(name => <option key={name} value={name} />)}
          </datalist>
          <datalist id="ref-agent-ids">
            {(reference?.agents || []).map(a => <option key={a.id} value={String(a.id)} />)}
          </datalist>
          <datalist id="ref-users">
            {(reference?.users || []).map(u => <option key={u} value={u} />)}
          </datalist>
          <datalist id="ref-src-ips">
            {(reference?.src_ips || []).map(ip => <option key={ip} value={ip} />)}
          </datalist>

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
              {formBusy ? <><span className="spinner"></span> Отправка...</> : 'Отправить событие'}
            </button>
          </div>
        </div>
      </div>
    )}
  </div>
}
