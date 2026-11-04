// Конвейер обработки инцидента (§3.1, рис. 3.1) — вынесен из main.jsx (stage-13).
//
// [8]+[9] Этапы строятся только по фактическим данным:
//  - инцидент уже создан → Wazuh/Normalize/Correlate/Risk завершены всегда;
//  - Qwen/Validate/Playbook завершены, только если есть хотя бы один анализ
//    (свежий или в истории детали); иначе — pending независимо от статуса closed;
//  - есть ожидающий подтверждения результат → Playbook в состоянии active с подписью;
//  - статус closed на конвейер не влияет — он показан бейджем в шапке инцидента.

import React from 'react';

const STAGES = [
  { id: 'wazuh', label: 'Wazuh' },
  { id: 'normalize', label: 'Normalize' },
  { id: 'correlate', label: 'Correlate' },
  { id: 'risk', label: 'Risk' },
  { id: 'qwen', label: 'Qwen' },
  { id: 'validate', label: 'Validate' },
  { id: 'playbook', label: 'Playbook' },
];

export function pipelineStageStatuses({
  hasAnalysis = false,
  pendingConfirmation = false,
  awaitingManualRun = false,
} = {}) {
  return STAGES.map((stage) => {
    const isLlmStage = stage.id === 'qwen' || stage.id === 'validate' || stage.id === 'playbook';
    let status = 'completed';
    let note = null;
    if (isLlmStage && !hasAnalysis) status = 'pending';
    if (stage.id === 'playbook' && pendingConfirmation) {
      status = 'active';
      note = 'ожидает подтверждения';
    } else if (stage.id === 'playbook' && awaitingManualRun) {
      // [17] ручной режим: playbook не исполнялся — запустит оператор
      status = 'active';
      note = 'ожидает запуска оператором';
    }
    return { id: stage.id, label: stage.label, status, note };
  });
}

export default function PipelineStatus({ analysis, analysesLength, pendingConfirmation, awaitingManualRun }) {
  const hasAnalysis = (analysesLength || 0) > 0 || !!analysis;
  const stageStatuses = pipelineStageStatuses({ hasAnalysis, pendingConfirmation, awaitingManualRun });

  return (
    <div className="pipeline-container">
      <div className="pipeline-title">КОНВЕЙЕР ОБРАБОТКИ</div>
      <div className="pipeline-steps">
        {stageStatuses.map((stage, index) => (
          <React.Fragment key={stage.id}>
            <div className={`pipeline-stage ${stage.status}`} data-stage={stage.id}>
              <div className="stage-label">{stage.label}</div>
              <div className="stage-status">
                {stage.status === 'completed' && '✓'}
                {stage.status === 'active' && '●'}
                {stage.status === 'pending' && '○'}
              </div>
              {stage.status === 'active' && stage.id === 'playbook' &&
                <div className="stage-note">{stage.note}</div>}
            </div>
            {index < stageStatuses.length - 1 && (
              <div className={`pipeline-arrow ${stage.status === 'completed' ? 'completed' : ''}`}>→</div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}
