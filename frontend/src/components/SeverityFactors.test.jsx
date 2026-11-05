// Тесты блока «Оценка критичности» в карточке инцидента (stage-22).
// Компонент чистый (данные пропсом, без сети): проверяем, что факторы
// критичности показываются с числами и объяснениями — база по матрице MITRE,
// повышения по процедуре SOC, числа числовой модели риска, пороги, а также
// фолбэк для инцидентов без разбора (созданы до stage-22).

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import SeverityFactors from './SeverityFactors.jsx';

afterEach(cleanup);

// Фикстура — ровно тот формат, что бэкенд кладёт в Incident.severity_factors
const MITRE_FACTORS = {
  basis: 'mitre_matrix',
  severity: 'critical',
  computed_at: '2026-11-05T10:00:00+00:00',
  mitre: {
    tactic: 'credential_access',
    technique: 'T1110',
    base_severity: 'high',
    escalations: [
      {
        category: 'critical_asset',
        title: 'Критичный бизнес-актив',
        explanation: 'Актив «db-primary-01» имеет критичность critical',
      },
    ],
  },
  risk: {
    score: 100,
    severity: 'critical',
    base: 100,
    base_from: 'asset_criticality',
    factors: [
      { kind: 'rule_level', value: 70, detail: 'Уровень правила Wazuh: 10 → 70/100' },
      { kind: 'asset_criticality', value: 100, detail: 'Критичность актива: critical → 100/100' },
      { kind: 'attack_danger', value: 85, detail: 'Опасность типа атаки (маркер «credential») → 85/100' },
    ],
    series_bonus: 10,
    p_implement: 0.667,
    correlation_confidence: 0.667,
    adjusted_bonus: 4.4,
    thresholds: { critical: 85, high: 65, medium: 40 },
  },
};

const FALLBACK_FACTORS = {
  basis: 'risk_score',
  severity: 'high',
  computed_at: '2026-11-05T10:00:00+00:00',
  mitre: null,
  risk: {
    score: 74,
    severity: 'high',
    base: 70,
    base_from: 'rule_level',
    factors: [
      { kind: 'rule_level', value: 70, detail: 'Уровень правила Wazuh: 10 → 70/100' },
    ],
    series_bonus: 10,
    p_implement: 0.667,
    correlation_confidence: 0.334,
    adjusted_bonus: 4.4,
    thresholds: { critical: 85, high: 65, medium: 40 },
  },
};

describe('SeverityFactors', () => {
  it('показывает базу по матрице MITRE и повышение с объяснением', () => {
    render(<SeverityFactors factors={MITRE_FACTORS} />);
    // база: тактика + техника + базовый уровень
    expect(screen.getByText(/База по матрице:/)).toBeTruthy();
    expect(screen.getByText(/Credential Access — доступ к учётным данным/)).toBeTruthy();
    expect(screen.getByText(/\(T1110\)/)).toBeTruthy();
    expect(screen.getByText(/базовый уровень «Высокий»/)).toBeTruthy();
    // повышение: название категории + объяснение с именем актива
    expect(screen.getByText(/Критичный бизнес-актив/)).toBeTruthy();
    expect(screen.getByText(/Актив «db-primary-01» имеет критичность critical/)).toBeTruthy();
    // итог +1 уровень от базы
    expect(screen.getByText(/«Высокий» \+ 1 уровень/)).toBeTruthy();
  });

  it('показывает числа числовой модели: слагаемые, бонус серии, пороги', () => {
    const { getByTestId } = render(<SeverityFactors factors={MITRE_FACTORS} />);
    // слагаемые базы с цифрами и пометкой базы
    expect(screen.getByText(/Уровень правила Wazuh: 10 → 70\/100/)).toBeTruthy();
    expect(screen.getByText(/Критичность актива: critical → 100\/100/)).toBeTruthy();
    expect(screen.getByText(/Опасность типа атаки \(маркер «credential»\) → 85\/100/)).toBeTruthy();
    expect(screen.getByText(/← база/)).toBeTruthy();
    // смешанные строки (текст разбит по <strong>) — по textContent секции:
    // бонус серии с числами и процентами вероятностей + итог с порогами
    const text = getByTestId('severity-factors').textContent;
    expect(text).toContain('Бонус за серию событий (корреляция): +10 × вероятность реализации 67% × достоверность корреляции 67% = +4.4');
    expect(text).toContain('Итог: 100/100 → «Критический»');
    expect(text).toContain('пороги: критический ≥ 85, высокий ≥ 65, средний ≥ 40, ниже — низкий');
  });

  it('fallback basis=risk_score: блока матрицы нет, подпись основания другая', () => {
    render(<SeverityFactors factors={FALLBACK_FACTORS} />);
    expect(screen.queryByTestId('sf-mitre')).toBeNull();
    expect(screen.getByText(/Числовая модель риска \(§3\.3\.3\) — тактика не задана/)).toBeTruthy();
    expect(screen.getByText(/74\/100/)).toBeTruthy();
    expect(screen.getByTestId('sf-risk')).toBeTruthy();
  });

  it('без повышений: «условий не выполнено», без «+1 уровень»', () => {
    const factors = {
      ...MITRE_FACTORS,
      mitre: { ...MITRE_FACTORS.mitre, escalations: [] },
    };
    render(<SeverityFactors factors={factors} />);
    expect(screen.getByText(/условий не выполнено — итог равен базовому уровню/)).toBeTruthy();
    expect(screen.queryByText(/\+ 1 уровень/)).toBeNull();
  });

  it('нет разбора (инцидент до stage-22): пояснение вместо блока', () => {
    render(<SeverityFactors factors={null} />);
    expect(screen.getByTestId('severity-factors-empty')).toBeTruthy();
    expect(screen.getByText(/Разбор оценки недоступен/)).toBeTruthy();
    expect(screen.queryByTestId('sf-risk')).toBeNull();
  });
});
