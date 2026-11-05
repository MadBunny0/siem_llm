// Тесты вкладки «Реакции (ВМ)» (stage-23): рендер активных реакций, контракт
// констант (режимы исполнения переехали в constants.js после удаления вкладки
// «Агенты (ВМ)», подписи действий RESPONSE_ACTION_RU).
// request передаётся пропсом (как в App) — в тестах это мок без сети.

import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const mockRequest = vi.fn(async (path) => {
  if (path === '/responses/state') {
    return [
      {
        asset: 'mail-prod-01',
        incident_id: 7,
        actions: [
          {
            action: 'block_ip',
            target: '192.168.56.102',
            at: '2026-11-05T10:05:00Z',
            by: 'soc_lead',
            incident_id: 7,
          },
        ],
      },
      {
        asset: 'wks-finance-12',
        incident_id: 3,
        actions: [
          { action: 'monitor', target: null, at: '2026-11-05T09:00:00Z', by: 'analyst1', incident_id: 3 },
          { action: 'collect_evidence', target: null, at: '2026-11-05T09:01:00Z', by: 'analyst1', incident_id: 3 },
        ],
      },
    ];
  }
  return [];
});

import ResponsesView from './ResponsesView.jsx';
import { RESPONSE_ACTION_RU } from '../lib/helpers.js';

afterEach(cleanup);

describe('ResponsesView — константы (контракт с бэкендом и карточкой инцидента)', () => {
  it('подписи RESPONSE_ACTION_RU покрывают все действия playbook', () => {
    for (const action of ['block_ip', 'disable_account', 'isolate_host', 'monitor', 'collect_evidence']) {
      expect(RESPONSE_ACTION_RU[action]).toBeTruthy();
    }
  });
});

describe('ResponsesView — рендер', () => {
  it('показывает активы с инцидентами, бейджи реакций с целями и «кем/когда»', async () => {
    render(<ResponsesView request={mockRequest} />);
    expect(await screen.findByText('mail-prod-01')).toBeTruthy();
    expect(screen.getByText('инцидент #7')).toBeTruthy();
    // цель реакции (IP) — внутри строки бейджа (смешанный текст → textContent)
    const blockRow = screen.getByTestId('resp-block_ip-7');
    expect(blockRow.textContent).toContain('Блокировка IP');
    expect(blockRow.textContent).toContain('192.168.56.102');
    expect(blockRow.textContent).toContain('soc_lead');
    // пассивные отметки без цели — только подписи
    expect(screen.getByTestId('resp-monitor-3').textContent).toContain('Наблюдение');
    expect(screen.getByTestId('resp-collect_evidence-3').textContent).toContain('Сбор артефактов');
    expect(screen.getByText('инцидент #3')).toBeTruthy();
  });

  it('пустой ответ — подсказка, как реакция появляется', async () => {
    mockRequest.mockImplementationOnce(async () => []);
    render(<ResponsesView request={mockRequest} />);
    expect(await screen.findByText('Активных реакций нет')).toBeTruthy();
  });
});
