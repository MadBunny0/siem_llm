// Вкладка «Реакции (ВМ)» (stage-23): активные реальные реакции playbook —
// команды, принятые Wazuh Manager (active response) и ещё не отменённые
// («Сбросить реакции» в карточке инцидента выполняет обратные AR-команды,
// после чего записи исчезают отсюда). Источник — GET /responses/state:
// агрегат по всем инцидентам, группировка {актив, инцидент}. Обновление
// каждые 10 с + кнопка «Обновить» (пауза, когда вкладка браузера скрыта —
// legacy-cleanup). Отдельный файл — интеграция с App минимальна: компонент
// получает request как prop (fetch-обёртка с JWT живёт в api.js; тот же
// проп используют тесты — мок без сети). См. docs/E2E_STAND.md,
// docs/E2E_SCENARIOS.md.

import React, { useState } from 'react';
import { useListResource } from '../hooks/useListResource.js';
import { formatDate, RESPONSE_ACTION_RU } from '../lib/helpers.js';

const REFRESH_MS = 10000;

function ResponsesView({ request }) {
  const [updatedAt, setUpdatedAt] = useState(null);
  const { items, loading, error, load } = useListResource('/responses/state', {
    pollMs: REFRESH_MS,
    requester: request,
    onLoaded: () => setUpdatedAt(new Date()),
  });

  return (
    <div className="panel tab-panel">
      <div className="panel-head">
        <div>
          <h2>Реакции на ВМ</h2>
          <p>
            Активные реальные реакции: Wazuh Manager принял команду (active response)
            и доставил её агенту актива. Отменяются кнопкой «Сбросить реакции» в карточке
            инцидента{updatedAt ? ` · обновлено: ${formatDate(updatedAt)}` : ''}
          </p>
        </div>
        <button className="ghost" onClick={load} disabled={loading}>{loading ? <><span className="spinner spinner-dark"></span> Обновление...</> : '↻ Обновить'}</button>
      </div>
      {error && <div className="alert error">⚠ {error}</div>}
      {loading && items.length === 0 ? (
        <div className="empty">Загрузка данных...</div>
      ) : items.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">⬡</div>
          <h3>Активных реакций нет</h3>
          <p>Запустите действие в режиме «Реально» из карточки инцидента — реакция появится здесь до отмены.</p>
        </div>
      ) : (
        <div className="responses-grid">
          {items.map((item) => (
            <div className="responses-card" key={`${item.asset}-${item.incident_id}`}>
              <div className="responses-head">
                <strong>{item.asset}</strong>
                <span className="responses-incident">инцидент #{item.incident_id}</span>
              </div>
              <div className="responses-actions">
                {(item.actions || []).map((a, i) => (
                  <div
                    className="responses-action"
                    key={`${a.action}-${i}`}
                    data-testid={`resp-${a.action}-${item.incident_id}`}
                    title={RESPONSE_ACTION_RU[a.action] || a.action}
                  >
                    <span>
                      {RESPONSE_ACTION_RU[a.action] || a.action}
                      {a.target ? <>: <b>{a.target}</b></> : null}
                    </span>
                    <span className="responses-meta">
                      {a.by || '—'} · {formatDate(a.at)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default ResponsesView;
