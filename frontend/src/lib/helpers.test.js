import { describe, expect, it } from 'vitest';

import {
  actionRuDescription,
  analysisFromHistory,
  analysisResults,
  confPct,
  criteriaCountLabel,
  detailToMessage,
  initiatedByBadge,
  pendingReasonText,
  priorityLabel,
  recommendedActionCodes,
  resultExecutionBadge,
  resultNeedsConfirmation,
  resultValidationBadge,
  resultsNeedConfirmation,
} from './helpers.js';

describe('analysisResults — нормализация форматов ответа анализа', () => {
  it('null/undefined → пустой список', () => {
    expect(analysisResults(null)).toEqual([]);
    expect(analysisResults(undefined)).toEqual([]);
  });

  it('новый формат: results передаётся как есть', () => {
    const results = [
      { action: 'monitor', validation: { approved: true }, execution: { mode: 'simulation' } },
      { action: 'block_ip', validation: { approved: false }, execution: { mode: 'pending_confirmation' } },
    ];
    expect(analysisResults({ results })).toBe(results);
  });

  it('пустой results → fallback на одиночный формат', () => {
    const single = {
      recommendation: { action: 'monitor' },
      validation: { approved: true },
      execution: { mode: 'simulation' },
    };
    expect(analysisResults({ results: [], ...single })).toHaveLength(1);
  });

  it('старый формат (validation/execution верхнего уровня) → список из одного', () => {
    const legacy = {
      recommendation: { recommended_action: 'block_ip' },
      validation: { approved: true, action: 'block_ip' },
      execution: { executed: false, mode: 'simulation', action: 'block_ip' },
    };
    const [result] = analysisResults(legacy);
    expect(result.action).toBe('block_ip');
    expect(result.execution.mode).toBe('simulation');
  });

  it('ничего полезного → пустой список', () => {
    expect(analysisResults({ recommendation: {} })).toEqual([]);
  });
});

describe('resultNeedsConfirmation / resultsNeedConfirmation', () => {
  it('requires_confirmation из validation', () => {
    expect(resultNeedsConfirmation({ validation: { requires_confirmation: true } })).toBe(true);
  });

  it('mode pending_confirmation из execution', () => {
    expect(resultNeedsConfirmation({ execution: { mode: 'pending_confirmation' } })).toBe(true);
  });

  it('обычный одобренный результат не требует подтверждения', () => {
    expect(resultNeedsConfirmation({ validation: { approved: true } })).toBe(false);
    expect(resultNeedsConfirmation(null)).toBe(false);
  });

  it('resultsNeedConfirmation: хоть один ожидающий → true', () => {
    const results = [
      { validation: { approved: true } },
      { execution: { mode: 'pending_confirmation' } },
    ];
    expect(resultsNeedConfirmation(results)).toBe(true);
    expect(resultsNeedConfirmation([{ validation: { approved: true } }])).toBe(false);
    expect(resultsNeedConfirmation(undefined)).toBe(false);
  });
});

describe('pendingReasonText — причина из первого ожидающего результата', () => {
  it('берёт reason из свежего анализа', () => {
    const fresh = { results: [{ action: 'block_ip', validation: { requires_confirmation: true, reason: 'критический актив' } }] };
    expect(pendingReasonText(fresh, null)).toBe('критический актив');
  });

  it('ищет в response_raw сохранённого анализа, если свежего нет', () => {
    const stored = {
      response_raw: { results: [{ execution: { mode: 'pending_confirmation', reason: 'ожидает' } }] },
    };
    expect(pendingReasonText(null, stored)).toBe('ожидает');
  });

  it('нет ожидающих → пустая строка', () => {
    expect(pendingReasonText({ validation: { approved: true } }, null)).toBe('');
  });
});

describe('бейджи DVE и исполнения', () => {
  it('одобрено → РАЗРЕШЕНО', () => {
    expect(resultValidationBadge({ validation: { approved: true } })).toEqual({ cls: 'approved-text', text: 'РАЗРЕШЕНО' });
  });

  it('заблокировано → ЗАБЛОКИРОВАНО', () => {
    expect(resultValidationBadge({ validation: { approved: false } })).toEqual({ cls: 'blocked-text', text: 'ЗАБЛОКИРОВАНО' });
  });

  it('ожидание подтверждения → бейдж pending', () => {
    expect(resultValidationBadge({ execution: { mode: 'pending_confirmation' } }).text).toBe('ОЖИДАЕТ ПОДТВЕРЖДЕНИЯ');
    expect(resultExecutionBadge({ execution: { mode: 'pending_confirmation' } }).text).toBe('ОЖИДАЕТ');
  });

  it('исполнение: выполнено → ВЫПОЛНЕНО, иначе СИМУЛЯЦИЯ', () => {
    expect(resultExecutionBadge({ execution: { executed: true } }).text).toBe('ВЫПОЛНЕНО');
    expect(resultExecutionBadge({ execution: { executed: false, mode: 'simulation' } }).text).toBe('СИМУЛЯЦИЯ');
  });
});

describe('initiatedByBadge — источник анализа', () => {
  it('auto_analysis → бейдж «авто (critical)»', () => {
    const badge = initiatedByBadge({ response_raw: { initiated_by: 'auto_analysis' } });
    expect(badge.text).toBe('авто (critical)');
    expect(badge.cls).toBe('auto');
  });

  it('manual → «вручную»', () => {
    expect(initiatedByBadge({ response_raw: { initiated_by: 'manual' } }).text).toBe('вручную');
  });

  it('строка JSON парсится (детальный анализ из истории)', () => {
    const badge = initiatedByBadge({ response_raw: JSON.stringify({ initiated_by: 'manual' }) });
    expect(badge.text).toBe('вручную');
  });

  it('нет поля / битый JSON → null', () => {
    expect(initiatedByBadge({ response_raw: {} })).toBeNull();
    expect(initiatedByBadge({ response_raw: '{broken' })).toBeNull();
    expect(initiatedByBadge(null)).toBeNull();
  });
});

describe('criteriaCountLabel — русские склонения', () => {
  it.each([
    [1, '1 критерий'],
    [2, '2 критерия'],
    [3, '3 критерия'],
    [4, '4 критерия'],
    [5, '5 критериев'],
    [11, '11 критериев'],
    [12, '12 критериев'],
    [21, '21 критерий'],
    [22, '22 критерия'],
    [25, '25 критериев'],
    [101, '101 критерий'],
    [112, '112 критериев'],
  ])('%i → %s', (count, expected) => {
    expect(criteriaCountLabel(count)).toBe(expected);
  });
});

describe('confPct — уверенность в процентах', () => {
  it('0..1 → проценты', () => {
    expect(confPct(0.9)).toBe('90%');
    expect(confPct(0.05)).toBe('5%');
  });

  it('значения > 1 трактуются как проценты напрямую', () => {
    expect(confPct(90)).toBe('90%');
  });

  it('пустые/нечисловые → прочерк', () => {
    expect(confPct(null)).toBe('—');
    expect(confPct(undefined)).toBe('—');
    expect(confPct('')).toBe('—');
    expect(confPct('abc')).toBe('—');
  });
});

describe('priorityLabel — формат для селектов', () => {
  it('известный приоритет → «2 · средний»', () => {
    expect(priorityLabel(2)).toBe('2 · средний');
  });

  it('вне справочника → число как строка', () => {
    expect(priorityLabel(7)).toBe('7');
  });

  it('пусто → прочерк', () => {
    expect(priorityLabel(null)).toBe('—');
    expect(priorityLabel('')).toBe('—');
  });
});

describe('detailToMessage — detail из ответов FastAPI', () => {
  it('строка проходит как есть', () => {
    expect(detailToMessage('Ошибка X', 'fallback')).toBe('Ошибка X');
  });

  it('массив 422 сериализуется', () => {
    const detail = [{ msg: 'field required' }];
    expect(detailToMessage(detail, 'fallback')).toBe(JSON.stringify(detail));
  });

  it('undefined → fallback', () => {
    expect(detailToMessage(undefined, 'Неизвестная ошибка')).toBe('Неизвестная ошибка');
  });
});

describe('stage-14: actionRuDescription — русские расшифровки действий', () => {
  it('известные действия → русское описание', () => {
    expect(actionRuDescription('block_ip')).toBe('Блокировка IP-адреса источника атаки на межсетевом экране');
    expect(actionRuDescription('disable_account')).toBe('Временная блокировка учётной записи в IdM');
    expect(actionRuDescription('isolate_host')).toBe('Изоляция узла от сети — карантин EDR');
    expect(actionRuDescription('collect_evidence')).toBe('Сбор и сохранение доказательств по инциденту');
    expect(actionRuDescription('monitor')).toBe('Наблюдение за инцидентом без активного вмешательства');
  });

  it('неизвестное действие → общий текст-заглушка', () => {
    expect(actionRuDescription('unknown_action')).toBe('Действие по сценарию реагирования');
    expect(actionRuDescription(undefined)).toBe('Действие по сценарию реагирования');
  });
});

describe('stage-14: recommendedActionCodes — разбор перечня действий', () => {
  it('строка через запятую → массив кодов (trim + фильтр пустых)', () => {
    expect(recommendedActionCodes('block_ip, isolate_host')).toEqual(['block_ip', 'isolate_host']);
    expect(recommendedActionCodes('monitor')).toEqual(['monitor']);
  });

  it('лишние запятые/пробелы отбрасываются', () => {
    expect(recommendedActionCodes('monitor, , collect_evidence,')).toEqual(['monitor', 'collect_evidence']);
  });

  it('не-строка/пусто → пустой массив', () => {
    expect(recommendedActionCodes(null)).toEqual([]);
    expect(recommendedActionCodes('')).toEqual([]);
    expect(recommendedActionCodes(42)).toEqual([]);
  });
});

describe('stage-14: analysisFromHistory — восстановление панели из истории', () => {
  const stored = {
    id: 7,
    created_at: '2026-11-04T12:00:00Z',
    model: 'qwen2.5:3b',
    description: 'Описание из БД',
    attack_type: 'credential_attack',
    confidence: 0.9,
    explanation: 'Обоснование',
    recommended_action: 'block_ip',
    response_raw: {
      initiated_by: 'auto_analysis',
      results: [
        {
          action: 'block_ip',
          validation: { approved: false, action: 'block_ip', requires_confirmation: true, reason: 'критический актив' },
          execution: { executed: false, mode: 'pending_confirmation', action: 'block_ip' },
        },
      ],
      validation: { approved: false },
      execution: { mode: 'pending_confirmation' },
    },
  };

  it('собирает панель из последней записи: результаты из response_raw', () => {
    const panel = analysisFromHistory(stored);
    expect(panel.fromHistory).toBe(true);
    expect(panel.results).toHaveLength(1);
    expect(panel.results[0].action).toBe('block_ip');
    expect(resultNeedsConfirmation(panel.results[0])).toBe(true);
  });

  it('рекомендация — из полей записи БД', () => {
    const panel = analysisFromHistory(stored);
    expect(panel.recommendation.attack_type).toBe('credential_attack');
    expect(panel.recommendation.confidence).toBe(0.9);
    expect(panel.recommendation.recommended_action).toBe('block_ip');
  });

  it('response_raw сохраняется — бейдж авто/вручную продолжает работать', () => {
    const panel = analysisFromHistory(stored);
    expect(initiatedByBadge(panel).text).toBe('авто (critical)');
  });

  it('строка response_raw из API парсится', () => {
    const panel = analysisFromHistory({ ...stored, response_raw: JSON.stringify(stored.response_raw) });
    expect(panel.results).toHaveLength(1);
  });

  it('fallback на саму запись, если в response_raw нет results', () => {
    const legacy = { ...stored, response_raw: { initiated_by: 'manual' }, validation: { approved: true }, execution: { mode: 'simulation', action: 'monitor' } };
    const panel = analysisFromHistory(legacy);
    expect(panel.results).toHaveLength(1);
    expect(panel.results[0].action).toBe('block_ip');
  });

  it('null → null (нечего показывать)', () => {
    expect(analysisFromHistory(null)).toBeNull();
  });
});
