import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import PipelineStatus, { pipelineStageStatuses } from './PipelineStatus.jsx';

const STAGE_IDS = ['wazuh', 'normalize', 'correlate', 'risk', 'qwen', 'validate', 'playbook'];

afterEach(cleanup);

function statusesFromDom() {
  return [...document.querySelectorAll('.pipeline-stage')].map((el) => ({
    id: el.dataset.stage,
    status: [...el.classList].find((c) => ['completed', 'active', 'pending'].includes(c)),
    note: el.querySelector('.stage-note')?.textContent || null,
  }));
}

describe('pipelineStageStatuses — чистая логика этапов', () => {
  it('без анализа: LLM-этапы pending, первые четыре completed', () => {
    const stages = pipelineStageStatuses({ hasAnalysis: false });
    expect(stages.map((s) => s.id)).toEqual(STAGE_IDS);
    for (const stage of stages) {
      if (['qwen', 'validate', 'playbook'].includes(stage.id)) {
        expect(stage.status).toBe('pending');
      } else {
        expect(stage.status).toBe('completed');
      }
    }
  });

  it('есть анализ: все этапы completed', () => {
    const stages = pipelineStageStatuses({ hasAnalysis: true });
    expect(stages.every((s) => s.status === 'completed')).toBe(true);
  });

  it('pendingConfirmation: playbook active, остальные по данным', () => {
    const stages = pipelineStageStatuses({ hasAnalysis: false, pendingConfirmation: true });
    expect(stages.find((s) => s.id === 'playbook').status).toBe('active');
    expect(stages.find((s) => s.id === 'qwen').status).toBe('pending');
  });

  it('stage-17: awaitingManualRun — playbook active с подписью «ожидает запуска»', () => {
    const stages = pipelineStageStatuses({ hasAnalysis: true, awaitingManualRun: true });
    const playbook = stages.find((s) => s.id === 'playbook');
    expect(playbook.status).toBe('active');
    expect(playbook.note).toBe('ожидает запуска оператором');
    // qwen/validate выполнены — анализ уже был
    expect(stages.find((s) => s.id === 'qwen').status).toBe('completed');
  });

  it('stage-17: pendingConfirmation приоритетнее awaitingManualRun', () => {
    const stages = pipelineStageStatuses({
      hasAnalysis: true,
      pendingConfirmation: true,
      awaitingManualRun: true,
    });
    expect(stages.find((s) => s.id === 'playbook').note).toBe('ожидает подтверждения');
  });
});

describe('PipelineStatus — рендер', () => {
  it('закрытый без анализа: конвейер НЕ прыгает на Playbook (баг [9])', () => {
    render(<PipelineStatus analysis={null} analysesLength={0} pendingConfirmation={false} />);
    const statuses = statusesFromDom();
    // qwen/validate/playbook — pending, даже если инцидент closed
    expect(statuses.find((s) => s.id === 'qwen').status).toBe('pending');
    expect(statuses.find((s) => s.id === 'playbook').status).toBe('pending');
  });

  it('инцидент с анализом в истории: все этапы completed (баг [8] — возврат из closed не сбрасывает)', () => {
    render(<PipelineStatus analysis={null} analysesLength={2} pendingConfirmation={false} />);
    expect(statusesFromDom().every((s) => s.status === 'completed')).toBe(true);
  });

  it('ожидающий подтверждения результат: Playbook active с подписью', () => {
    render(<PipelineStatus analysis={null} analysesLength={1} pendingConfirmation={true} />);
    const statuses = statusesFromDom();
    expect(statuses[6].status).toBe('active');
    expect(statuses[6].note).toBe('ожидает подтверждения');
  });

  it('свежий результат анализа учитывается даже без истории', () => {
    render(
      <PipelineStatus
        analysis={{ results: [{ validation: { approved: true } }] }}
        analysesLength={0}
        pendingConfirmation={false}
      />,
    );
    expect(statusesFromDom().every((s) => s.status === 'completed')).toBe(true);
  });

  it('рендерит заголовок и 7 этапов со стрелками', () => {
    render(<PipelineStatus analysis={null} analysesLength={0} pendingConfirmation={false} />);
    expect(screen.getByText('КОНВЕЙЕР ОБРАБОТКИ')).toBeTruthy();
    expect(document.querySelectorAll('.pipeline-stage')).toHaveLength(7);
    expect(document.querySelectorAll('.pipeline-arrow')).toHaveLength(6);
  });
});
