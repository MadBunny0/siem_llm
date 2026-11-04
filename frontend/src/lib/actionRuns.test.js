import { beforeEach, describe, expect, it } from 'vitest';

import { clearIncidentRuns, getIncidentRuns, isActionRun, markActionRun } from './actionRuns.js';

const STORAGE_KEY = 'siem_action_runs_v1';

// [18] Отметки «действие запускали вручную» живут в localStorage (ключ
// siem_action_runs_v1) и закреплены за инцидентом: между тестами хранилище чистится.
describe('actionRuns — отметки запуска действий по инцидентам', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('mark → isActionRun true, карта отметок содержит режим и время', () => {
    markActionRun(5, 'block_ip', 'simulation');
    expect(isActionRun(5, 'block_ip')).toBe(true);
    const runs = getIncidentRuns(5);
    expect(runs.block_ip.mode).toBe('simulation');
    expect(typeof runs.block_ip.at).toBe('string');
  });

  it('другой инцидент (или другое действие) отметок не видит — состояние закреплено на таске', () => {
    markActionRun(5, 'block_ip', 'controlled');
    expect(isActionRun(4, 'block_ip')).toBe(false);
    expect(isActionRun(5, 'monitor')).toBe(false);
    expect(getIncidentRuns(4)).toEqual({});
  });

  it('clear снимает отметки и возвращает «были ли они», повторный clear → false', () => {
    expect(clearIncidentRuns(5)).toBe(false);
    markActionRun(5, 'block_ip', 'simulation');
    expect(clearIncidentRuns(5)).toBe(true);
    expect(isActionRun(5, 'block_ip')).toBe(false);
    expect(getIncidentRuns(5)).toEqual({});
    expect(clearIncidentRuns(5)).toBe(false);
  });

  it('записи пишутся в window.localStorage под ключом siem_action_runs_v1', () => {
    markActionRun(12, 'isolate_host', 'controlled');
    const stored = JSON.parse(window.localStorage.getItem(STORAGE_KEY));
    expect(stored['12'].isolate_host.mode).toBe('controlled');
    // incidentId приводится к строке-ключу: числовой и строковый id — одно и то же
    expect(isActionRun('12', 'isolate_host')).toBe(true);
  });

  it('isActionRun читает предзаписанный localStorage (имитация перезагрузки страницы)', () => {
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ 7: { block_ip: { mode: 'simulation', at: '2026-11-04T10:00:00.000Z' } } })
    );
    expect(isActionRun(7, 'block_ip')).toBe(true);
    expect(getIncidentRuns(7).block_ip.at).toBe('2026-11-04T10:00:00.000Z');
  });

  it('порча JSON в localStorage → чтение не падает, mark восстанавливает работоспособность', () => {
    window.localStorage.setItem(STORAGE_KEY, '{broken json');
    expect(isActionRun(3, 'block_ip')).toBe(false);
    expect(getIncidentRuns(3)).toEqual({});
    markActionRun(3, 'block_ip', 'simulation');
    expect(isActionRun(3, 'block_ip')).toBe(true);
  });

  it('null/undefined в аргументах не создают мусорных ключей', () => {
    markActionRun(null, 'block_ip', 'simulation');
    expect(isActionRun(undefined, 'block_ip')).toBe(false);
    expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
    expect(getIncidentRuns(null)).toEqual({});
    expect(clearIncidentRuns(undefined)).toBe(false);
  });
});
