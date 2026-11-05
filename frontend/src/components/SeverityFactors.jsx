// Блок «Оценка критичности» в карточке инцидента (stage-22).
// Показывает, ИЗ КАКИХ ФАКТОРОВ получился уровень критичности — с числами
// и объяснениями: база по матрице MITRE (тактика правила) + повышения по
// процедуре SOC, плюс числовая модель риска §3.3.3 (слагаемые базы, бонус
// за серию, вероятность реализации, достоверность корреляции, пороги).
// Данные — Incident.severity_factors с бэкенда (заполняется при ingest).

import React from 'react';

import { MITRE_TACTIC_RU, SEVERITY_LABELS } from '../lib/helpers.js';
import { Severity } from './Badges.jsx';

// Подпись основания оценки: матрица MITRE (stage-17, процедура SOC v3.1)
// или fallback на числовую модель риска (правило без тактики)
const BASIS_LABELS = {
  mitre_matrix: 'Матрица MITRE — процедура SOC v3.1',
  risk_score: 'Числовая модель риска (§3.3.3) — тактика не задана',
};

// Слагаемые базы числовой модели — русские подписи видов факторов
const RISK_FACTOR_LABELS = {
  rule_level: 'Уровень правила Wazuh',
  asset_criticality: 'Критичность актива',
  attack_danger: 'Опасность типа атаки',
};

function pct(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return String(value);
  return `${Math.round(n * 100)}%`;
}

function MatrixPart({ mitre, severity }) {
  const tacticRu = MITRE_TACTIC_RU[mitre.tactic] || mitre.tactic;
  const baseRu = SEVERITY_LABELS[mitre.base_severity] || mitre.base_severity;
  const escalations = Array.isArray(mitre.escalations) ? mitre.escalations : [];
  return (
    <div className="sf-part sf-mitre" data-testid="sf-mitre">
      <div className="sf-line">
        <strong>База по матрице:</strong> тактика «{tacticRu}»{mitre.technique ? ` (${mitre.technique})` : ''} → базовый уровень «{baseRu}»
      </div>
      <div className="sf-line">
        <strong>Повышение критичности</strong> (при выполнении хотя бы одного условия — на один уровень, суммарно максимум +1):
        {escalations.length ? (
          <ul className="sf-escalations">
            {escalations.map(item => (
              <li key={item.category}>
                <strong>{item.title}</strong> — {item.explanation}
              </li>
            ))}
          </ul>
        ) : (
          <span className="sf-muted"> условий не выполнено — итог равен базовому уровню</span>
        )}
      </div>
      <div className="sf-line sf-result">
        Итог по матрице: <Severity value={severity} />
        {escalations.length > 0 && <span> («{baseRu}» + 1 уровень)</span>}
      </div>
    </div>
  );
}

function RiskPart({ risk }) {
  const factors = Array.isArray(risk.factors) ? risk.factors : [];
  const thresholds = risk.thresholds || {};
  const severityRu = SEVERITY_LABELS[risk.severity] || risk.severity;
  return (
    <div className="sf-part sf-risk" data-testid="sf-risk">
      <div className="sf-line">
        <strong>Числовая модель риска:</strong> база = максимум слагаемых{risk.base_from ? ` — ${RISK_FACTOR_LABELS[risk.base_from] || risk.base_from}` : ''} = <strong>{risk.base}</strong>:
        {factors.length ? (
          <ul className="sf-factors">
            {factors.map(f => (
              <li key={f.kind} className={f.kind === risk.base_from ? 'sf-base-factor' : ''}>
                <strong>{RISK_FACTOR_LABELS[f.kind] || f.kind}: {f.value}</strong> — {f.detail}
                {f.kind === risk.base_from && <span className="sf-muted"> ← база</span>}
              </li>
            ))}
          </ul>
        ) : (
          <span className="sf-muted"> слагаемых нет — база 0</span>
        )}
      </div>
      <div className="sf-line">
        <strong>Бонус за серию событий (корреляция):</strong> +{risk.series_bonus} × вероятность реализации {pct(risk.p_implement)} × достоверность корреляции {pct(risk.correlation_confidence)} = <strong>+{risk.adjusted_bonus}</strong>
      </div>
      <div className="sf-line sf-result">
        Итог: <strong>{risk.score}/100</strong> → «{severityRu}»
        {thresholds.critical != null && (
          <span className="sf-muted"> (пороги: критический ≥ {thresholds.critical}, высокий ≥ {thresholds.high}, средний ≥ {thresholds.medium}, ниже — низкий)</span>
        )}
      </div>
    </div>
  );
}

export default function SeverityFactors({ factors }) {
  if (!factors || typeof factors !== 'object') {
    return (
      <section className="severity-factors" data-testid="severity-factors-empty">
        <label>Оценка критичности</label>
        <div className="sf-empty">
          Разбор оценки недоступен: инцидент создан до появления этого блока.
          Добавьте событие в инцидент или пересоздайте демо-сценарий — разбор
          рассчитается при поступлении события.
        </div>
      </section>
    );
  }

  const basisLabel = BASIS_LABELS[factors.basis] || factors.basis;
  return (
    <section className="severity-factors" data-testid="severity-factors">
      <label>Оценка критичности</label>
      <div className="severity-factors-body">
        <div className="sf-head">
          <Severity value={factors.severity} />
          <span className="sf-basis" title="Основание оценки: матрица MITRE по тактике правила либо числовая модель риска, если тактика у правила не задана">{basisLabel}</span>
        </div>
        {factors.mitre && <MatrixPart mitre={factors.mitre} severity={factors.severity} />}
        {factors.risk && <RiskPart risk={factors.risk} />}
      </div>
    </section>
  );
}
