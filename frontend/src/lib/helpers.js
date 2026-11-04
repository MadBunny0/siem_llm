// Чистые хелперы UI (stage-13) — вынесены из main.jsx для тестируемости.
// Никакого React и обращений к DOM/localStorage — только функции над данными.

export const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };

export const STATUS_LABELS = { new: 'Новый', in_progress: 'В работе', closed: 'Закрыт' };

export const PRIORITY_LABELS = { 1: 'низкий', 2: 'средний', 3: 'высокий', 4: 'критический' };

export const PLAYBOOK_ACTIONS = ['monitor', 'collect_evidence', 'isolate_host', 'block_ip', 'disable_account'];

export function priorityLabel(priority) {
  if (priority === null || priority === undefined || priority === '') return '—';
  return PRIORITY_LABELS[priority] ? `${priority} · ${PRIORITY_LABELS[priority]}` : String(priority);
}

export function formatDate(value) {
  if (!value) return '—';
  return new Intl.DateTimeFormat('ru-RU', { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value));
}

export function confPct(value) {
  if (value === null || value === undefined || value === '') return '—';
  const num = Number(value);
  if (Number.isNaN(num)) return '—';
  return `${Math.round(num <= 1 ? num * 100 : num)}%`;
}

/* ==================== Результаты анализа по каждому действию (stage-11/12) ==================== */

// Нормализованный список результатов: новый формат (analysis.results — по одному
// на каждое действие из перечня LLM) с fallback на старый одиночный формат
// (validation/execution верхнего уровня).
export function analysisResults(analysis) {
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
export function resultNeedsConfirmation(result) {
  return result?.validation?.requires_confirmation === true ||
    result?.execution?.mode === 'pending_confirmation';
}

export function resultsNeedConfirmation(results) {
  return (results || []).some(resultNeedsConfirmation);
}

// Причина из первого результата, ожидающего подтверждения (для плашки).
export function pendingReasonText(freshAnalysis, storedAnalysis) {
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
export function resultValidationBadge(result) {
  if (resultNeedsConfirmation(result)) return { cls: 'badge-pending', text: 'ОЖИДАЕТ ПОДТВЕРЖДЕНИЯ' };
  return result?.validation?.approved
    ? { cls: 'approved-text', text: 'РАЗРЕШЕНО' }
    : { cls: 'blocked-text', text: 'ЗАБЛОКИРОВАНО' };
}

// Бейдж режима исполнения по одному результату.
export function resultExecutionBadge(result) {
  if (result?.execution?.executed) return { cls: 'executed-text', text: 'ВЫПОЛНЕНО' };
  if (resultNeedsConfirmation(result)) return { cls: 'badge-pending', text: 'ОЖИДАЕТ' };
  if (result?.execution?.mode === 'manual_run') {
    // [17] ручной режим: playbook выполнит оператор кнопкой «▶ Выполнить»
    return { cls: 'badge-pending', text: 'ОЖИДАЕТ ЗАПУСКА' };
  }
  return { cls: 'simulated-text', text: 'СИМУЛЯЦИЯ' };
}

// Бейдж источника анализа: поле initiated_by в Analysis.response_raw
// («auto_analysis» — автоанализ при создании инцидента уровней из
// AUTO_ANALYSIS_LEVELS (critical, low), «manual» — запуск вручную).
export const INITIATED_BY_META = {
  auto_analysis: {
    cls: 'auto',
    text: 'авто (LLM)',
    title: 'Автоматический анализ при создании инцидента уровней из AUTO_ANALYSIS_LEVELS (critical, low); LLM недетерминирована — повторный анализ может дать другой результат',
  },
  manual: {
    cls: 'manual',
    text: 'вручную',
    title: 'Анализ запущен вручную кнопкой «Запустить интеллектуальный анализ»',
  },
};

export function initiatedByBadge(analysis) {
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

/* ==================== Stage 14: русские описания действий, восстановление из истории ==================== */

// Русские описания действий реагирования — для кнопок, списков и подсказок.
export const ACTION_RU = {
  block_ip: 'Блокировка IP-адреса источника атаки на межсетевом экране',
  disable_account: 'Временная блокировка учётной записи в IdM',
  isolate_host: 'Изоляция узла от сети — карантин EDR',
  collect_evidence: 'Сбор и сохранение доказательств по инциденту',
  monitor: 'Наблюдение за инцидентом без активного вмешательства',
};

export function actionRuDescription(action) {
  return ACTION_RU[action] || 'Действие по сценарию реагирования';
}

// «block_ip, isolate_host» → ['block_ip', 'isolate_host']; не-строка/пусто → [].
export function recommendedActionCodes(value) {
  if (typeof value !== 'string' || !value.trim()) return [];
  return value.split(',').map(part => part.trim()).filter(Boolean);
}

// response_raw анализа (строка JSON или уже объект) → объект; при ошибке — null.
function parseResponseRaw(analysis) {
  let raw = analysis?.response_raw ?? null;
  if (typeof raw === 'string') {
    try {
      raw = JSON.parse(raw);
    } catch (e) {
      return null;
    }
  }
  return raw && typeof raw === 'object' ? raw : null;
}

// [2] Панель результата из последней записи истории анализов: результаты — из
// response_raw (новый формат) с fallback на саму запись, рекомендация — из полей
// записи БД. fromHistory — признак «данные показаны из истории» (бейдж в шапке).
export function analysisFromHistory(last) {
  if (!last) return null;
  const raw = parseResponseRaw(last) || {};
  let results = analysisResults(raw);
  if (!results.length && (raw.validation || raw.execution || last.recommended_action)) {
    // старые записи без results: единственный результат из полей записи;
    // recommended_action приоритетнее execution.action (stage-14)
    results = [{
      action: last.recommended_action || raw.execution?.action,
      validation: raw.validation,
      execution: raw.execution,
    }];
  }
  if (!results.length) results = analysisResults(last);
  return {
    results,
    recommendation: {
      description: last.description || '',
      attack_type: last.attack_type || '',
      confidence: last.confidence ?? null,
      explanation: last.explanation || '',
      recommended_action: last.recommended_action || '',
    },
    validation: raw.validation,
    execution: raw.execution,
    // response_raw сохраняем, чтобы бейдж авто/вручную (initiatedByBadge) работал
    // и для восстановленной панели.
    response_raw: raw,
    fromHistory: true,
  };
}

// «1 критерий» / «3 критерия» / «5 критериев» — счётчик в таблице playbooks.
export function criteriaCountLabel(count) {
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 === 1 && mod100 !== 11) return `${count} критерий`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return `${count} критерия`;
  return `${count} критериев`;
}

/* ==================== Stage 15: ручной запуск действий, шаги playbook ==================== */

// Режимы исполнения (execution.mode) — русские подписи для тостов и бейджей.
export const EXECUTION_MODE_RU = {
  simulation: 'dry run — симуляция, инфраструктура не изменялась',
  controlled: 'реальное выполнение',
  pending_confirmation: 'ожидает подтверждения администратора',
  blocked: 'заблокировано политикой DVE',
  // [17] ручной режим: medium/high/critical — playbook запускает оператор
  manual_run: 'ожидает запуска оператором — playbook ещё не выполнялся',
};

export function executionModeRu(mode) {
  return EXECUTION_MODE_RU[mode] || mode || '';
}

// [17] Есть ли среди результатов действия, ожидающие ручного запуска
// оператором (medium/high/critical — playbook не исполнялся автоматически).
export function resultsAwaitManualRun(results) {
  return (results || []).some(r => r?.execution?.mode === 'manual_run');
}

// Может ли текущий пользователь вручную запустить одобренное DVE действие:
// админ — на любом инциденте; аналитик — владелец инцидента (незакреплённый
// инцидент закрепляется при запуске, поэтому доступен любому аналитику).
// Отложенное (pending) и заблокированное действие запустить нельзя.
// [16] Действие, уже запущенное вручную (run_manually), повторно не запускается,
// на закрытом инциденте (incidentClosed) запуск запрещён целиком.
export function canRunAction(result, { isAdmin = false, username = null, ownerUsername = null, incidentClosed = false } = {}) {
  if (!result?.action) return false;
  if (result?.execution?.run_manually === true) return false;
  if (incidentClosed) return false;
  if (resultNeedsConfirmation(result)) return false;
  if (result?.validation?.approved !== true) return false;
  if (isAdmin) return true;
  if (!username) return false;
  return !ownerUsername || username === ownerUsername;
}

// Может ли подтвердить отложенное действие — только администратор (§3.4, p:102).
// [16] На закрытом инциденте подтверждение недоступно — только возврат в работу.
export function canConfirmAction(result, isAdmin, incidentClosed = false) {
  return !!isAdmin && !incidentClosed && resultNeedsConfirmation(result);
}

// Русские подписи плейсхолдеров playbook-шагов ({{src_ip}} и т.п.).
const STEP_PLACEHOLDER_RU = {
  src_ip: 'IP-адрес источника',
  user: 'учётная запись нарушителя',
  asset: 'скомпрометированный актив',
  incident: 'инцидент',
};

function stepPlaceholderRu(raw) {
  const key = String(raw).replace(/[{}]/g, '').trim();
  return STEP_PLACEHOLDER_RU[key] || key;
}

// Один шаг playbook → строка на русском: приоритет — description из БД,
// иначе русское описание действия + цель и инструмент.
export function formatPlaybookStep(step) {
  if (!step || typeof step !== 'object') return '';
  if (step.description) return String(step.description);
  const parts = [];
  parts.push(step.action ? actionRuDescription(step.action) : 'Шаг сценария');
  if (step.target) parts.push(`цель: ${stepPlaceholderRu(step.target)}`);
  if (step.tool && step.tool !== 'none') parts.push(`инструмент: ${step.tool}`);
  return parts.join(' — ');
}

// Шаги playbook → список строк (не-массивы и пустые шаги отбрасываются).
export function formatPlaybookSteps(steps) {
  if (!Array.isArray(steps)) return [];
  return steps.map(formatPlaybookStep).filter(Boolean);
}

// Строковое представление detail из ответа FastAPI (422 отдаёт detail массивом).
export function detailToMessage(detail, fallback) {
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

/* ==================== Stage 15: мультиселект-фильтры, шаблоны из справочника ==================== */

// Русские подписи критичности — для чипов мультиселект-фильтра инцидентов.
export const SEVERITY_LABELS = { critical: 'Критический', high: 'Высокий', medium: 'Средний', low: 'Низкий' };

// Мультиселект-фильтр ленты инцидентов. statuses/severities — массивы выбранных
// чипов (пустой массив = показывать все значения этой группы); группы сочетаются
// через AND. Поиск — подстрока по id/title/description без учёта регистра.
// Сортировка прежняя: severityOrder по убыванию, затем created_at по убыванию.
export function applyIncidentFilters(incidents, { statuses, severities, search } = {}) {
  const statusSet = new Set(statuses || []);
  const severitySet = new Set(severities || []);
  const needle = (search || '').toLowerCase();
  return (Array.isArray(incidents) ? incidents : [])
    .filter(incident => !statusSet.size || statusSet.has(incident.status))
    .filter(incident => !severitySet.size || severitySet.has(incident.severity))
    .filter(incident => !needle || `${incident.id} ${incident.title} ${incident.description}`.toLowerCase().includes(needle))
    .sort((a, b) => (severityOrder[b.severity] - severityOrder[a.severity]) ||
      (new Date(b.created_at) - new Date(a.created_at)));
}

// «5710 — sshd: Multiple authentication failures» — подпись варианта шаблона
// события в select и datalist формы (справочник GET /ingest/reference).
export function ruleTemplateLabel(rule) {
  if (!rule) return '';
  return `${rule.id} — ${rule.description}`;
}

/* ==================== Stage 17: тактики MITRE ATT&CK (матрица критичности) ==================== */

// [17] Тактики MITRE ATT&CK (матрица критичности, docs/CRITICALITY_MATRIX.md) —
// русские подписи для формы и таблицы правил корреляции.
export const MITRE_TACTIC_RU = {
  reconnaissance: 'Reconnaissance — разведка',
  resource_development: 'Resource Development — подготовка ресурсов',
  initial_access: 'Initial Access — начальный доступ',
  discovery: 'Discovery — изучение среды',
  privilege_escalation: 'Privilege Escalation — повышение привилегий',
  credential_access: 'Credential Access — доступ к учётным данным',
  execution: 'Execution — выполнение',
  persistence: 'Persistence — закрепление',
  defense_evasion: 'Defense Evasion — обход защиты',
  lateral_movement: 'Lateral Movement — боковое перемещение',
  collection: 'Collection — сбор данных',
  command_and_control: 'Command and Control — управление (C2)',
  exfiltration: 'Exfiltration — кража данных',
  impact: 'Impact — воздействие',
};
