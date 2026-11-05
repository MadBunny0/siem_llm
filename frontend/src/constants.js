// Общие константы интерфейса и чистые хелперы истории анализов.
// Вынесено из main.jsx (stage-19-legacy-cleanup). stage-23: генераторы
// демо-данных и режимы симуляции удалены — события приходят только с
// wazuh-агентов ВМ, реакции всегда реальные (Wazuh active response).

export const TABS = [
  { id: 'incidents', icon: '◈', label: 'Инциденты' },
  { id: 'analyses', icon: '✦', label: 'Анализы' },
  { id: 'notifications', icon: '✉', label: 'Уведомления' },
  { id: 'audit', icon: '☰', label: 'Аудит' },
  { id: 'rules', icon: '⚡', label: 'Правила корреляции' },
  { id: 'playbooks', icon: '▶', label: 'Playbooks' },
  // [23] реальные реакции playbook на ВМ актива через Wazuh active response
  { id: 'responses', icon: '⬡', label: 'Реакции (ВМ)' },
];

export const TAB_META = {
  incidents: { eyebrow: 'ЦЕНТР МОНИТОРИНГА', title: 'Инциденты информационной безопасности' },
  analyses: { eyebrow: 'LLM-АНАЛИТИКА', title: 'История анализов' },
  notifications: { eyebrow: 'КАНАЛЫ ОПОВЕЩЕНИЙ', title: 'Уведомления' },
  audit: { eyebrow: 'ЖУРНАЛ ДЕЙСТВИЙ', title: 'Аудит' },
  rules: { eyebrow: 'КОРРЕЛЯЦИЯ СОБЫТИЙ', title: 'Правила корреляции' },
  playbooks: { eyebrow: 'АВТОМАТИЗАЦИЯ РЕАГИРОВАНИЯ', title: 'Playbooks' },
  responses: { eyebrow: 'РЕАКЦИИ PLAYBOOK (WAZUH AR)', title: 'Реальные реакции на виртуальных машинах' },
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

// Последняя запись истории анализов: по created_at, при равенстве — по большему id.
export function latestAnalysis(list) {
  const arr = Array.isArray(list) ? list : [];
  if (!arr.length) return null;
  return [...arr].sort((a, b) =>
    (new Date(b.created_at) - new Date(a.created_at)) || ((b.id || 0) - (a.id || 0))
  )[0];
}
