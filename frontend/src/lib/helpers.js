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
  return { cls: 'simulated-text', text: 'СИМУЛЯЦИЯ' };
}

// Бейдж источника анализа: поле initiated_by в Analysis.response_raw
// («auto_analysis» — автоанализ при создании critical-инцидента, «manual» — запуск вручную).
export const INITIATED_BY_META = {
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

// «1 критерий» / «3 критерия» / «5 критериев» — счётчик в таблице playbooks.
export function criteriaCountLabel(count) {
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 === 1 && mod100 !== 11) return `${count} критерий`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return `${count} критерия`;
  return `${count} критериев`;
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
