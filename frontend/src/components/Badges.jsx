// Бейджи инцидента: критичность (Severity) и статус (Status).
// Вынесено из main.jsx (stage-19-legacy-cleanup).

import React from 'react';

export function Severity({ value }) {
  return <span className={`badge severity-${value || 'low'}`}>{value || 'low'}</span>;
}
export function Status({ value }) {
  return <span className={`badge status-${value || 'new'}`}>{value || 'new'}</span>;
}
