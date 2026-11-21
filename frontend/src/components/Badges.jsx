// Бейджи инцидента: критичность (Severity) и статус (Status).
// Вынесено из main.jsx (stage-19-legacy-cleanup).

import React from 'react';

// Названия статусов таски — единый словарь с lib/helpers.js (фидбек
// заказчика 2026-11-18): бейджи ленты/карточки показывают те же
// OPEN / IN PROGRESS / CLOSED, что и фильтры; CSS-класс не менялся
const STATUS_BADGE_LABELS = { new: 'OPEN', in_progress: 'IN PROGRESS', closed: 'CLOSED' };

export function Severity({ value }) {
  return <span className={`badge severity-${value || 'low'}`}>{value || 'low'}</span>;
}
export function Status({ value }) {
  const v = value || 'new';
  return <span className={`badge status-${v}`}>{STATUS_BADGE_LABELS[v] || v}</span>;
}
