// Тесты вкладки «Агенты (ВМ)» (stage-20): рендер с целью, контракт констант
// (режимы исполнения, сценарии активности ↔ seed-правила).
// request передаётся пропсом (как в main.jsx) — в тестах это мок без сети.

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const mockRequest = vi.fn(async (path) => {
  if (path === '/execution-targets') {
    return [
      {
        id: 1,
        name: 'wks-finance-12',
        asset_id: 4,
        kind: 'agent',
        base_url: 'http://agent-wks:8100',
        platform: 'container',
        adapter: 'state',
        is_active: true,
        status: 'online',
        last_seen: '2026-11-05T10:00:00Z',
      },
    ];
  }
  if (path.startsWith('/execution-targets/1/journal')) {
    return [
      {
        at: '2026-11-05T10:05:00Z',
        action: 'block_ip',
        params: { ip: '203.0.113.66' },
        executed: true,
        requested_by: 'analyst1',
        incident_id: 5,
        detail: 'IP-адрес 203.0.113.66 заблокирован',
      },
    ];
  }
  if (path.startsWith('/execution-targets/1/activity')) {
    return [{ at: '2026-11-05T10:00:00Z', description: 'Вход пользователя alice', alert_sent: true, detail: null }];
  }
  return [];
});

import TargetsView, { EXECUTION_MODES, SIMULATE_SCENARIOS } from './TargetsView.jsx';

afterEach(cleanup);

describe('TargetsView — константы (контракт с бэкендом и агентом)', () => {
  it('режимы исполнения: simulation и real, без лишних', () => {
    expect(EXECUTION_MODES.map((m) => m.id)).toEqual(['simulation', 'real']);
    expect(EXECUTION_MODES.find((m) => m.id === 'simulation').label).toContain('Симуляция');
    expect(EXECUTION_MODES.find((m) => m.id === 'real').label).toContain('ВМ');
  });

  it('сценарии активности покрывают все 7 атакующих классов seed-правил', () => {
    const ids = SIMULATE_SCENARIOS.map((s) => s.id);
    for (const scenario of [
      'brute_force',
      'password_spraying',
      'repeated_scan',
      'web_attack',
      'malware',
      'privilege_escalation',
      'data_exfiltration',
    ]) {
      expect(ids).toContain(scenario);
    }
    expect(ids).toContain('normal_activity');
  });
});

describe('TargetsView — рендер', () => {
  it('показывает цель со статусом, кнопками и сценариями', async () => {
    render(<TargetsView request={mockRequest} />);
    // имя цели появляется после загрузки (mock request)
    expect(await screen.findByText('wks-finance-12')).toBeTruthy();
    expect(screen.getByText('онлайн')).toBeTruthy();
    expect(screen.getByText('Проверить')).toBeTruthy();
    expect(screen.getByText('Журнал')).toBeTruthy();
    expect(screen.getByText('Сбросить ВМ')).toBeTruthy();
    expect(screen.getByText('Проиграть активность')).toBeTruthy();
    // сценарий по умолчанию выбран в select
    const select = screen.getByLabelText('Сценарий активности');
    expect(select.value).toBe('brute_force');
  });
});
