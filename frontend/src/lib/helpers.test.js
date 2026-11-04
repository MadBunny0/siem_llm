import { describe, expect, it } from 'vitest';

import {
  actionRuDescription,
  actionShortLabel,
  analysisFromHistory,
  analysisResults,
  applyIncidentFilters,
  canConfirmAction,
  canRunAction,
  confPct,
  criteriaCountLabel,
  detailToMessage,
  executionModeRu,
  formatPlaybookStep,
  formatPlaybookSteps,
  initiatedByBadge,
  MITRE_TACTIC_RU,
  pendingReasonText,
  priorityLabel,
  recommendedActionCodes,
  resultExecutionBadge,
  resultNeedsConfirmation,
  resultValidationBadge,
  resultsAwaitManualRun,
  resultsNeedConfirmation,
  ruleTemplateLabel,
  structuredAnalysis,
  verdictBadge,
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
  it('auto_analysis → бейдж «авто (LLM)»', () => {
    const badge = initiatedByBadge({ response_raw: { initiated_by: 'auto_analysis' } });
    expect(badge.text).toBe('авто (LLM)');
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
    expect(initiatedByBadge(panel).text).toBe('авто (LLM)');
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

/* ==================== Stage 15: запуск действий, шаги playbook ==================== */

describe('canRunAction — кому доступен ручной запуск действия', () => {
  const approved = { action: 'block_ip', validation: { approved: true }, execution: { mode: 'simulation' } };
  const pending = { action: 'block_ip', validation: { approved: false, requires_confirmation: true }, execution: { mode: 'pending_confirmation' } };
  const blocked = { action: 'monitor', validation: { approved: false }, execution: { mode: 'blocked' } };

  it('админ — на любом инциденте', () => {
    expect(canRunAction(approved, { isAdmin: true })).toBe(true);
    expect(canRunAction(approved, { isAdmin: true, username: 'soc_lead', ownerUsername: 'analyst1' })).toBe(true);
  });

  it('владелец инцидента — может запустить', () => {
    expect(canRunAction(approved, { isAdmin: false, username: 'analyst1', ownerUsername: 'analyst1' })).toBe(true);
  });

  it('чужой аналитик — не может', () => {
    expect(canRunAction(approved, { isAdmin: false, username: 'analyst2', ownerUsername: 'analyst1' })).toBe(false);
  });

  it('незакреплённый инцидент — доступен любому аналитику (закрепится при запуске)', () => {
    expect(canRunAction(approved, { isAdmin: false, username: 'analyst2', ownerUsername: null })).toBe(true);
  });

  it('отложенное (pending) и заблокированное действие запустить нельзя', () => {
    expect(canRunAction(pending, { isAdmin: true })).toBe(false);
    expect(canRunAction(blocked, { isAdmin: true })).toBe(false);
  });

  it('нет действия/нет пользователя — false', () => {
    expect(canRunAction(null, { isAdmin: true })).toBe(false);
    expect(canRunAction(approved, { isAdmin: false, username: null })).toBe(false);
  });
});

describe('canConfirmAction — подтверждение отложенного действия (только админ)', () => {
  const pending = { action: 'block_ip', validation: { requires_confirmation: true } };
  const approved = { action: 'monitor', validation: { approved: true } };

  it('админ подтверждает отложенное', () => {
    expect(canConfirmAction(pending, true)).toBe(true);
  });

  it('аналитик подтверждать не может (§3.4 p:102)', () => {
    expect(canConfirmAction(pending, false)).toBe(false);
  });

  it('одобренное действие подтверждения не требует', () => {
    expect(canConfirmAction(approved, true)).toBe(false);
  });
});

/* ==================== Stage 16: feedback fixes — run_manually, закрытый инцидент ==================== */

describe('canRunAction stage-16: run_manually и закрытый инцидент', () => {
  const approved = { action: 'block_ip', validation: { approved: true }, execution: { mode: 'simulation' } };
  const manual = { ...approved, execution: { mode: 'simulation', run_manually: true } };

  it('run_manually: true — кнопку больше не показываем (даже при approved и админе)', () => {
    expect(canRunAction(manual, { isAdmin: true })).toBe(false);
    expect(canRunAction(manual, { isAdmin: false, username: 'analyst1', ownerUsername: 'analyst1' })).toBe(false);
  });

  it('закрытый инцидент — запуск запрещён (даже админу)', () => {
    expect(canRunAction(approved, { isAdmin: true, incidentClosed: true })).toBe(false);
    expect(canRunAction(approved, { isAdmin: false, username: 'analyst1', ownerUsername: 'analyst1', incidentClosed: true })).toBe(false);
  });

  it('true-кейсы stage-15 не сломаны (метки нет, инцидент открыт)', () => {
    expect(canRunAction(approved, { isAdmin: true })).toBe(true);
    expect(canRunAction(approved, { isAdmin: false, username: 'analyst1', ownerUsername: 'analyst1' })).toBe(true);
    expect(canRunAction(approved, { isAdmin: true, incidentClosed: false })).toBe(true);
  });
});

describe('canConfirmAction stage-16: закрытый инцидент и обратная совместимость', () => {
  const pending = { action: 'block_ip', validation: { requires_confirmation: true } };

  it('закрытый инцидент — подтверждение недоступно (только возврат в работу)', () => {
    expect(canConfirmAction(pending, true, true)).toBe(false);
  });

  it('без третьего аргумента поведение прежнее (обратная совместимость)', () => {
    expect(canConfirmAction(pending, true)).toBe(true);
    expect(canConfirmAction(pending, false)).toBe(false);
  });
});

describe('executionModeRu — русские подписи режимов исполнения', () => {
  it('известные режимы', () => {
    expect(executionModeRu('simulation')).toContain('симуляция');
    expect(executionModeRu('controlled')).toContain('реальное');
    expect(executionModeRu('pending_confirmation')).toContain('подтверждения');
    expect(executionModeRu('blocked')).toContain('заблокировано');
  });

  it('неизвестный — как есть, пустой → пусто', () => {
    expect(executionModeRu('mystery')).toBe('mystery');
    expect(executionModeRu(undefined)).toBe('');
  });
});

describe('formatPlaybookSteps — «команды» действия на русском', () => {
  it('шаг из seed: русское описание + цель + инструмент', () => {
    const line = formatPlaybookStep({ action: 'block_ip', target: '{{src_ip}}', tool: 'firewall' });
    expect(line).toContain('Блокировка IP-адреса');
    expect(line).toContain('IP-адрес источника');
    expect(line).toContain('firewall');
  });

  it('description из БД приоритетнее', () => {
    const line = formatPlaybookStep({ action: 'block_ip', description: 'Кастомный шаг из playbook' });
    expect(line).toBe('Кастомный шаг из playbook');
  });

  it('плейсхолдеры расшифровываются по-русски, неизвестный — как есть', () => {
    expect(formatPlaybookStep({ action: 'isolate_host', target: '{{asset}}' })).toContain('скомпрометированный актив');
    expect(formatPlaybookStep({ action: 'monitor', target: '{{weird}}' })).toContain('weird');
  });

  it('tool=none не отображается', () => {
    expect(formatPlaybookStep({ action: 'monitor', target: '{{incident}}', tool: 'none' })).not.toContain('инструмент');
  });

  it('не-объект → пустая строка; не-массив → пустой список', () => {
    expect(formatPlaybookStep(null)).toBe('');
    expect(formatPlaybookSteps(undefined)).toEqual([]);
    expect(formatPlaybookSteps([{ action: 'block_ip' }, null, '']).length).toBe(1);
  });
});

describe('applyIncidentFilters — мультиселект-фильтры ленты инцидентов', () => {
  // 2 critical (разное время), 1 high, 1 medium — статусы new/new/in_progress/closed.
  const incidents = [
    { id: 1, title: 'Brute force SSH', description: 'Перебор пароля', severity: 'critical', status: 'new', created_at: '2026-11-04T10:00:00Z' },
    { id: 2, title: 'Malware on host', description: 'Вредоносный файл', severity: 'high', status: 'in_progress', created_at: '2026-11-04T11:00:00Z' },
    { id: 3, title: 'Port scan', description: 'Сканирование портов', severity: 'medium', status: 'closed', created_at: '2026-11-04T09:00:00Z' },
    { id: 4, title: 'Brute force RDP', description: 'Перебор пароля RDP', severity: 'critical', status: 'new', created_at: '2026-11-04T12:00:00Z' },
  ];
  const ids = list => list.map(i => i.id);

  it('обе группы пусты → видно всё, сортировка не сломана (severity desc, затем created_at desc)', () => {
    expect(ids(applyIncidentFilters(incidents, {}))).toEqual([4, 1, 2, 3]);
    expect(ids(applyIncidentFilters(incidents, { statuses: [], severities: [], search: '' }))).toEqual([4, 1, 2, 3]);
    // исходный массив не мутируется сортировкой
    expect(ids(incidents)).toEqual([1, 2, 3, 4]);
  });

  it('только статусы: несколько выбранных, критичность не фильтруется', () => {
    expect(ids(applyIncidentFilters(incidents, { statuses: ['new'] }))).toEqual([4, 1]);
    expect(ids(applyIncidentFilters(incidents, { statuses: ['new', 'closed'] }))).toEqual([4, 1, 3]);
  });

  it('только критичности: несколько выбранных, статус не фильтруется', () => {
    expect(ids(applyIncidentFilters(incidents, { severities: ['high', 'medium'] }))).toEqual([2, 3]);
  });

  it('обе группы вместе → пересечение (AND)', () => {
    expect(ids(applyIncidentFilters(incidents, { statuses: ['new'], severities: ['critical'] }))).toEqual([4, 1]);
    // пересечение пустое: in_progress есть только у high
    expect(applyIncidentFilters(incidents, { statuses: ['in_progress'], severities: ['critical'] })).toEqual([]);
  });

  it('поиск: подстрока по id/title/description без учёта регистра', () => {
    expect(ids(applyIncidentFilters(incidents, { search: 'brute' }))).toEqual([4, 1]);
    expect(ids(applyIncidentFilters(incidents, { search: 'ПЕРЕБОР' }))).toEqual([4, 1]);
    expect(ids(applyIncidentFilters(incidents, { search: '3' }))).toEqual([3]);
    expect(applyIncidentFilters(incidents, { search: 'нет такого' })).toEqual([]);
  });

  it('фильтры и поиск сочетаются', () => {
    expect(ids(applyIncidentFilters(incidents, { statuses: ['new'], severities: ['critical'], search: 'rdp' }))).toEqual([4]);
  });

  it('не-массив/undefined → пустой список', () => {
    expect(applyIncidentFilters(null, {})).toEqual([]);
    expect(applyIncidentFilters(undefined)).toEqual([]);
  });
});

describe('ruleTemplateLabel — подпись шаблона правила из справочника', () => {
  it('«id — описание» через длинное тире', () => {
    expect(ruleTemplateLabel({ id: '5710', level: 10, description: 'sshd: Multiple authentication failures' }))
      .toBe('5710 — sshd: Multiple authentication failures');
  });

  it('числовой id подставляется как есть', () => {
    expect(ruleTemplateLabel({ id: 31103, description: 'SQL injection attempt in query string' }))
      .toBe('31103 — SQL injection attempt in query string');
  });

  it('пустое правило → пустая строка', () => {
    expect(ruleTemplateLabel(null)).toBe('');
    expect(ruleTemplateLabel(undefined)).toBe('');
  });
});

/* ==================== Stage 17: тактики MITRE ATT&CK (матрица критичности) ==================== */

describe('MITRE_TACTIC_RU — справочник тактик для формы и таблицы правил', () => {
  it('14 тактик ATT&CK (матрица критичности)', () => {
    expect(Object.keys(MITRE_TACTIC_RU)).toHaveLength(14);
  });

  it('подпись credential_access содержит «Credential Access»', () => {
    expect(MITRE_TACTIC_RU.credential_access).toContain('Credential Access');
  });

  it('значения — «английское название — русский перевод»', () => {
    for (const label of Object.values(MITRE_TACTIC_RU)) {
      expect(label).toContain(' — ');
      expect(label.trim()).toBe(label);
    }
  });
});

describe('stage-17: ручной режим исполнения (manual_run)', () => {
  it('resultExecutionBadge: manual_run → «ОЖИДАЕТ ЗАПУСКА»', () => {
    const badge = resultExecutionBadge({ execution: { executed: false, mode: 'manual_run' } });
    expect(badge.text).toBe('ОЖИДАЕТ ЗАПУСКА');
  });

  it('resultExecutionBadge: simulation и pending не сломаны', () => {
    expect(resultExecutionBadge({ execution: { executed: false, mode: 'simulation' } }).text).toBe('СИМУЛЯЦИЯ');
    expect(resultExecutionBadge({ execution: { executed: false, mode: 'pending_confirmation' } }).text).toBe('ОЖИДАЕТ');
    expect(resultExecutionBadge({ execution: { executed: true, mode: 'controlled' } }).text).toBe('ВЫПОЛНЕНО');
  });

  it('executionModeRu: manual_run — «ожидает запуска оператором»', () => {
    expect(executionModeRu('manual_run')).toContain('ожидает запуска оператором');
  });

  it('resultsAwaitManualRun: true только при наличии manual_run', () => {
    expect(resultsAwaitManualRun([{ execution: { mode: 'manual_run' } }])).toBe(true);
    expect(resultsAwaitManualRun([{ execution: { mode: 'simulation' } }])).toBe(false);
    expect(resultsAwaitManualRun([])).toBe(false);
    expect(resultsAwaitManualRun(null)).toBe(false);
  });

  it('manual_run не считается ни pending, ни выполненным', () => {
    const result = {
      action: 'monitor',
      validation: { approved: true },
      execution: { executed: false, mode: 'manual_run' },
    };
    expect(resultNeedsConfirmation(result)).toBe(false);
    // одобренное DVE действие доступно для ручного запуска оператором
    expect(canRunAction(result, { isAdmin: true })).toBe(true);
    expect(resultExecutionBadge(result).text).toBe('ОЖИДАЕТ ЗАПУСКА');
  });
});

/* ==================== Stage 18: вердикт LLM, краткие подписи, структурированный анализ ==================== */

describe('verdictBadge — бейдж вердикта LLM', () => {
  it('канонические значения → свои бейджи', () => {
    expect(verdictBadge('True Positive')).toEqual({
      cls: 'badge-verdict-tp',
      text: 'TRUE POSITIVE',
      title: 'Вердикт LLM: подтверждённая угроза',
    });
    expect(verdictBadge('False Positive')).toEqual({
      cls: 'badge-verdict-fp',
      text: 'FALSE POSITIVE',
      title: 'Вердикт LLM: ложное срабатывание',
    });
  });

  it('сокращения tp/fp и любой регистр распознаются', () => {
    expect(verdictBadge('tp').cls).toBe('badge-verdict-tp');
    expect(verdictBadge('TP').text).toBe('TRUE POSITIVE');
    expect(verdictBadge('fp').cls).toBe('badge-verdict-fp');
    expect(verdictBadge('false positive').text).toBe('FALSE POSITIVE');
  });

  it('неизвестное/пустое → PENDING', () => {
    expect(verdictBadge('что-то иное')).toEqual({
      cls: 'badge-verdict-pending',
      text: 'PENDING',
      title: 'Вердикт LLM: требуется дополнительный анализ',
    });
    expect(verdictBadge('').text).toBe('PENDING');
    expect(verdictBadge(null).text).toBe('PENDING');
    expect(verdictBadge(undefined).text).toBe('PENDING');
  });
});

describe('actionShortLabel — короткие подписи для кнопок', () => {
  it('все 5 действий playbook', () => {
    expect(actionShortLabel('monitor')).toBe('Мониторинг');
    expect(actionShortLabel('collect_evidence')).toBe('Сбор артефактов');
    expect(actionShortLabel('isolate_host')).toBe('Изолировать узел');
    expect(actionShortLabel('block_ip')).toBe('Блокировать IP');
    expect(actionShortLabel('disable_account')).toBe('Отключить учётную запись');
  });

  it('неизвестное действие → сам код', () => {
    expect(actionShortLabel('quarantine_vlan')).toBe('quarantine_vlan');
  });
});

describe('structuredAnalysis — структурированные поля вердикта LLM', () => {
  it('свежий анализ: поля лежат в recommendation', () => {
    const structured = structuredAnalysis({
      recommendation: {
        verdict: 'True Positive',
        summary: 'Брутфорс SSH с источника 192.0.2.10',
        command_explanation: ['ssh root@host — подбор пароля', ''],
        suspicious_fragments: ['Failed password for root'],
        possible_legitimate_indicators: [],
        affected_entities: ['mail-prod-01'],
        missing_data: [],
        process_tree: ['sshd (1234)', '  └─ bash (1300)'],
        recommendations: ['Блокировать IP источника'],
      },
    });
    expect(structured.verdict).toBe('True Positive');
    expect(structured.summary).toBe('Брутфорс SSH с источника 192.0.2.10');
    expect(structured.command_explanation).toEqual(['ssh root@host — подбор пароля']);
    expect(structured.suspicious_fragments).toEqual(['Failed password for root']);
    // отступы дерева процессов не трим — дерево рисуется строками
    expect(structured.process_tree).toEqual(['sshd (1234)', '  └─ bash (1300)']);
    expect(structured.recommendations).toEqual(['Блокировать IP источника']);
  });

  it('панель из истории: recommendation без вердикта → берём response_raw.recommendation (строка JSON)', () => {
    const structured = structuredAnalysis({
      recommendation: { description: 'Из колонок БД', confidence: 0.9 },
      response_raw: JSON.stringify({
        recommendation: {
          verdict: 'False Positive',
          summary: 'Легитимный скан инвентаря',
          missing_data: ['логи VPN за ночь'],
        },
      }),
    });
    expect(structured.verdict).toBe('False Positive');
    expect(structured.summary).toBe('Легитимный скан инвентаря');
    expect(structured.missing_data).toEqual(['логи VPN за ночь']);
  });

  it('списки чистятся: не-массивы → [], элементы к строке, пустые отбрасываются', () => {
    const structured = structuredAnalysis({
      recommendation: {
        verdict: 'tp',
        suspicious_fragments: 'не массив',
        affected_entities: [42, null, 'ok', '', '   '],
        recommendations: { a: 1 },
      },
    });
    expect(structured.suspicious_fragments).toEqual([]);
    expect(structured.affected_entities).toEqual(['42', 'ok']);
    expect(structured.recommendations).toEqual([]);
  });

  it('нет ничего → безопасные дефолты (verdict/summary пустые, списки [])', () => {
    expect(structuredAnalysis(null)).toEqual({
      verdict: '',
      summary: '',
      command_explanation: [],
      suspicious_fragments: [],
      possible_legitimate_indicators: [],
      affected_entities: [],
      missing_data: [],
      process_tree: [],
      recommendations: [],
    });
    expect(structuredAnalysis({}).verdict).toBe('');
    expect(structuredAnalysis({ recommendation: {} }).summary).toBe('');
  });

  it('битый JSON в response_raw не роняет функцию', () => {
    expect(structuredAnalysis({ response_raw: '{broken' }).verdict).toBe('');
    expect(structuredAnalysis({ response_raw: 42 }).summary).toBe('');
  });
});
