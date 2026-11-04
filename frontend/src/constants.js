// Общие константы интерфейса и чистые хелперы форм и истории анализов.
// Вынесено из main.jsx (stage-19-legacy-cleanup).

export const TABS = [
  { id: 'incidents', icon: '◈', label: 'Инциденты' },
  { id: 'analyses', icon: '✦', label: 'Анализы' },
  { id: 'notifications', icon: '✉', label: 'Уведомления' },
  { id: 'audit', icon: '☰', label: 'Аудит' },
  { id: 'rules', icon: '⚡', label: 'Правила корреляции' },
  { id: 'playbooks', icon: '▶', label: 'Playbooks' },
  // [20] реальное исполнение playbook: агенты на ВМ наблюдаемых пользователей
  { id: 'targets', icon: '⬡', label: 'Агенты (ВМ)' },
];

export const TAB_META = {
  incidents: { eyebrow: 'ЦЕНТР МОНИТОРИНГА', title: 'Инциденты информационной безопасности' },
  analyses: { eyebrow: 'LLM-АНАЛИТИКА', title: 'История анализов' },
  notifications: { eyebrow: 'КАНАЛЫ ОПОВЕЩЕНИЙ', title: 'Уведомления' },
  audit: { eyebrow: 'ЖУРНАЛ ДЕЙСТВИЙ', title: 'Аудит' },
  rules: { eyebrow: 'КОРРЕЛЯЦИЯ СОБЫТИЙ', title: 'Правила корреляции' },
  playbooks: { eyebrow: 'АВТОМАТИЗАЦИЯ РЕАГИРОВАНИЯ', title: 'Playbooks' },
  targets: { eyebrow: 'РЕАЛЬНОЕ ИСПОЛНЕНИЕ (STAGE-20)', title: 'Агенты на ВМ наблюдаемых пользователей' },
};

export const CONDITION_OPERATORS = ['eq', 'neq', 'in', 'like'];
export const PRIORITIES = [1, 2, 3, 4];
export const NOTIFICATION_STATUS_CLASS = {
  sent: 'badge-status-sent',
  pending: 'badge-status-pending',
  failed: 'badge-status-failed',
};

// [18] Подписи структурированных блоков анализа в панели «Результат анализа»;
// process_tree рисуется деревом через <pre>, поэтому в этом списке его нет.
export const ANALYSIS_BLOCK_LABELS = [
  ['command_explanation', 'Разбор команд и событий'],
  ['suspicious_fragments', 'Подозрительные фрагменты'],
  ['possible_legitimate_indicators', 'Возможные легитимные объяснения'],
  ['affected_entities', 'Затронутые сущности'],
  ['missing_data', 'Недостающие данные'],
  ['recommendations', 'Рекомендации для дальнейших действий'],
];
// [15] Дефолты формы «Добавить событие Wazuh»: агент — seed-актив mail-prod-01,
// чтобы событие сразу привязывалось к активу (критичность влияет на риск/DVE).
export function emptyEventForm() {
  return {
    timestamp: new Date().toISOString().replace('Z', ''),
    rule_id: '5710',
    rule_level: '10',
    rule_description: 'sshd: Multiple authentication failures',
    rule_groups: 'authentication_failed,sshd',
    agent_id: '001',
    agent_name: 'mail-prod-01',
    srcip: '192.0.2.10',
    dstuser: 'root',
    full_log: 'Failed password for root from 192.0.2.10 port 22 ssh2',
  };
}

// [15] Выбор шаблона из справочника /ingest/reference: заполняет только поля
// правила (группы — через запятую без пробелов, как их парсит createCustomEvent);
// ввод пользователя (IP, агент, время) не перетирается. Пустой выбор
// («— заполнить вручную —») ничего не заполняет, поля остаются правиться свободно.
export function applyRuleTemplate(rule, formData) {
  if (!rule) return formData;
  return {
    ...formData,
    rule_id: String(rule.id),
    rule_level: rule.level === null || rule.level === undefined ? formData.rule_level : String(rule.level),
    rule_description: rule.description || formData.rule_description,
    rule_groups: (rule.groups || []).join(','),
  };
}

// Последняя запись истории анализов: по created_at, при равенстве — по большему id.
export function latestAnalysis(list) {
  const arr = Array.isArray(list) ? list : [];
  if (!arr.length) return null;
  return [...arr].sort((a, b) =>
    (new Date(b.created_at) - new Date(a.created_at)) || ((b.id || 0) - (a.id || 0))
  )[0];
}
