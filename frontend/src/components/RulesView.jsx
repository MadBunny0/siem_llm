// Вкладка «Правила корреляции»: просмотр, создание, редактирование и удаление правил (admin).
// Вынесено из main.jsx (stage-19-legacy-cleanup); загрузка — общий хук
// useListResource (legacy-cleanup).

import React, { useState } from 'react';
import { request } from '../api.js';
import { useListResource } from '../hooks/useListResource.js';
import { CONDITION_OPERATORS, PRIORITIES } from '../constants.js';
import { MITRE_TACTIC_RU, priorityLabel } from '../lib/helpers.js';

/* ==================== Вкладка «Правила корреляции» ==================== */

export default function RulesView({ notify, toastError, isAdmin }) {
  const { items, setItems, loading, error, setError, load } = useListResource('/correlation-rules');
  const [busy, setBusy] = useState(false);
  const [busyId, setBusyId] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(() => emptyRuleForm());

  // [17] MITRE ATT&CK у правила: тактика (матрица критичности), техника (T-код)
  // и признак «поставщик логов отметил событие как крайне значимое» (+1 уровень).
  function emptyRuleForm() {
    return {
      name: '',
      description: '',
      time_window_minutes: '10',
      min_events: '2',
      priority: 2,
      mitre_tactic: '',
      mitre_technique: '',
      escalated_by_vendor: false,
      is_active: true,
      conditions: [{ field: '', operator: 'eq', value: '' }],
    };
  }

  function openCreate() {
    setEditing(null);
    setForm(emptyRuleForm());
    setShowForm(true);
  }

  function openEdit(rule) {
    const conditions = Array.isArray(rule.conditions) ? rule.conditions : [];
    setEditing(rule);
    setForm({
      name: rule.name || '',
      description: rule.description || '',
      time_window_minutes: String(rule.time_window_minutes ?? 10),
      min_events: String(rule.min_events ?? 2),
      priority: rule.priority === null || rule.priority === undefined ? 2 : Number(rule.priority),
      // [17] тактика/техника из правила; отсутствуют (старые записи) → пусто/false
      mitre_tactic: rule.mitre_tactic || '',
      mitre_technique: rule.mitre_technique || '',
      escalated_by_vendor: rule.escalated_by_vendor === true,
      is_active: rule.is_active !== false,
      conditions: conditions.length
        ? conditions.map(c => ({
            field: c.field || '',
            operator: CONDITION_OPERATORS.includes(c.operator) ? c.operator : 'eq',
            value: Array.isArray(c.value)
              ? c.value.join(', ')
              : (c.value === null || c.value === undefined ? '' : String(c.value)),
          }))
        : [{ field: '', operator: 'eq', value: '' }],
    });
    setShowForm(true);
  }

  function updateCondition(index, patch) {
    setForm(f => ({ ...f, conditions: f.conditions.map((c, i) => (i === index ? { ...c, ...patch } : c)) }));
  }

  function addCondition() {
    setForm(f => ({ ...f, conditions: [...f.conditions, { field: '', operator: 'eq', value: '' }] }));
  }

  function removeCondition(index) {
    setForm(f => ({ ...f, conditions: f.conditions.length > 1 ? f.conditions.filter((_, i) => i !== index) : f.conditions }));
  }

  function buildPayload() {
    const conditions = form.conditions
      .filter(c => c.field.trim())
      .map(c => ({
        field: c.field.trim(),
        operator: c.operator,
        value: c.operator === 'in'
          ? c.value.split(',').map(v => v.trim()).filter(Boolean)
          : c.value,
      }));
    const priorityNumber = Number(form.priority);
    return {
      name: form.name.trim(),
      description: form.description.trim(),
      conditions,
      time_window_minutes: parseInt(form.time_window_minutes, 10) || 0,
      min_events: parseInt(form.min_events, 10) || 1,
      priority: Number.isFinite(priorityNumber) ? priorityNumber : 1,
      // [17] пустые тактика/техника уходят в null — бэкенд ждёт null, а не ''
      mitre_tactic: form.mitre_tactic || null,
      mitre_technique: form.mitre_technique.trim() || null,
      escalated_by_vendor: form.escalated_by_vendor,
      is_active: form.is_active,
    };
  }

  async function saveRule() {
    if (!form.name.trim()) {
      toastError('Укажите название правила корреляции');
      return;
    }
    if (!buildPayload().conditions.length) {
      toastError('Добавьте хотя бы одно условие с заполненным полем');
      return;
    }
    setBusy(true);
    try {
      const payload = buildPayload();
      if (editing) {
        await request(`/correlation-rules/${editing.id}`, { method: 'PUT', body: JSON.stringify(payload) });
        notify('Правило корреляции обновлено');
      } else {
        await request('/correlation-rules', { method: 'POST', body: JSON.stringify(payload) });
        notify('Правило корреляции создано');
      }
      setShowForm(false);
      setEditing(null);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function toggleActive(rule) {
    setBusyId(rule.id);
    try {
      const updated = await request(`/correlation-rules/${rule.id}`, {
        method: 'PUT',
        body: JSON.stringify({ ...rule, is_active: !rule.is_active }),
      });
      setItems(prev => prev.map(r => (r.id === rule.id ? { ...r, ...updated } : r)));
      notify(`Правило «${rule.name}» ${rule.is_active ? 'деактивировано' : 'активировано'}`);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  async function deleteRule(rule) {
    if (!window.confirm(`Удалить правило корреляции «${rule.name}»?`)) return;
    setBusyId(rule.id);
    try {
      await request(`/correlation-rules/${rule.id}`, { method: 'DELETE' });
      notify(`Правило «${rule.name}» удалено`);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  function conditionSummary(rule) {
    const list = Array.isArray(rule.conditions) ? rule.conditions : [];
    if (!list.length) return '—';
    return list
      .map(c => `${c.field || '?'} ${c.operator || 'eq'} ${Array.isArray(c.value) ? `[${c.value.join(', ')}]` : (c.value === null || c.value === undefined ? '—' : c.value)}`)
      .join('  AND  ');
  }

  const priorityOptions = PRIORITIES.includes(form.priority)
    ? PRIORITIES
    : [...PRIORITIES, form.priority].sort((a, b) => a - b);

  return (
    <div className="panel tab-panel">
      <div className="panel-head">
        <div>
          <h2>Правила корреляции</h2>
          <p>Правила объединения сырых событий в инциденты</p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="ghost" onClick={load} disabled={loading}>{loading ? <><span className="spinner spinner-dark"></span> Обновление...</> : '↻ Обновить'}</button>
          {isAdmin && <button className="primary" onClick={openCreate} disabled={busy}>＋ Новое правило</button>}
        </div>
      </div>
      {error && <div className="alert error">⚠ {error}</div>}
      {loading ? (
        <div className="empty">Загрузка данных...</div>
      ) : items.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">⚡</div>
          <h3>Правил пока нет</h3>
          <p>Создайте первое правило, чтобы события начали объединяться в инциденты.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Название</th>
                <th>Условия</th>
                <th>MITRE</th>
                <th>Окно</th>
                <th>События</th>
                <th>Приоритет</th>
                <th>Активно</th>
                {isAdmin && <th>Действия</th>}
              </tr>
            </thead>
            <tbody>
              {items.map(rule => (
                <tr key={rule.id}>
                  <td>
                    <strong>{rule.name}</strong>
                    {rule.description && <div className="rule-desc">{rule.description}</div>}
                  </td>
                  <td className="clamp">{conditionSummary(rule)}</td>
                  {/* [17] Привязка к тактике MITRE: чип с русской подписью (полный текст —
                      в title вместе с техникой), под чипом мелко код техники */}
                  <td className="rule-mitre">
                    {rule.mitre_tactic && MITRE_TACTIC_RU[rule.mitre_tactic] ? (
                      <>
                        <span
                          className="chip accent"
                          title={`${MITRE_TACTIC_RU[rule.mitre_tactic]}${rule.mitre_technique ? ` — ${rule.mitre_technique}` : ''}`}
                        >
                          {MITRE_TACTIC_RU[rule.mitre_tactic]}
                        </span>
                        {rule.mitre_technique && <div className="rule-mitre-code">{rule.mitre_technique}</div>}
                      </>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="nowrap">{rule.time_window_minutes} мин</td>
                  <td>{rule.min_events}</td>
                  <td>{rule.priority ? <span className="chip">{priorityLabel(rule.priority)}</span> : '—'}</td>
                  <td>
                    {isAdmin ? (
                      <button
                        className={`toggle ${rule.is_active ? 'on' : ''}`}
                        onClick={() => toggleActive(rule)}
                        disabled={busyId === rule.id}
                        title={rule.is_active ? 'Деактивировать' : 'Активировать'}
                      >
                        <i></i>
                      </button>
                    ) : (
                      <span className="active-flag">{rule.is_active ? 'да' : 'нет'}</span>
                    )}
                  </td>
                  {isAdmin && (
                    <td>
                      <div className="row-actions">
                        <button className="ghost small" onClick={() => openEdit(rule)} disabled={busyId === rule.id}>Редактировать</button>
                        <button className="icon-btn" onClick={() => deleteRule(rule)} disabled={busyId === rule.id} title="Удалить правило">✕</button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showForm && isAdmin && (
        <div className="modal-overlay" onClick={() => setShowForm(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <h3>{editing ? `Редактирование правила #${editing.id}` : 'Новое правило корреляции'}</h3>
            <p className="modal-subtitle">События, совпавшие по условиям в пределах временного окна, объединяются в инцидент</p>

            <div className="form-group">
              <label>Название *</label>
              <input
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder="Например: Brute force SSH"
              />
            </div>

            <div className="form-group">
              <label>Описание</label>
              <input
                value={form.description}
                onChange={e => setForm({ ...form, description: e.target.value })}
                placeholder="Что обнаруживает правило"
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px' }}>
              <div className="form-group">
                <label>Окно, минут</label>
                <input
                  type="number"
                  min="1"
                  value={form.time_window_minutes}
                  onChange={e => setForm({ ...form, time_window_minutes: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label>Минимум событий</label>
                <input
                  type="number"
                  min="1"
                  value={form.min_events}
                  onChange={e => setForm({ ...form, min_events: e.target.value })}
                />
              </div>
              <div className="form-group">
                <label>Приоритет</label>
                <select value={form.priority} onChange={e => setForm({ ...form, priority: Number(e.target.value) })}>
                  {priorityOptions.map(p => <option key={p} value={p}>{priorityLabel(p)}</option>)}
                </select>
              </div>
            </div>

            {/* [17] Привязка правила к MITRE ATT&CK: тактика задаёт критичность по матрице
                (docs/CRITICALITY_MATRIX.md), пустой выбор — критичность по числовой модели риска */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: '12px' }}>
              <div className="form-group">
                <label>Тактика MITRE</label>
                <select value={form.mitre_tactic} onChange={e => setForm({ ...form, mitre_tactic: e.target.value })}>
                  <option value="">— не задана (критичность по числовой модели риска) —</option>
                  {Object.entries(MITRE_TACTIC_RU).map(([key, label]) => (
                    <option key={key} value={key}>{label}</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>Техника (T-код)</label>
                <input
                  value={form.mitre_technique}
                  onChange={e => setForm({ ...form, mitre_technique: e.target.value })}
                  placeholder="T1110"
                />
              </div>
            </div>

            <div className="form-group">
              <label>Условия: поле / оператор / значение</label>
              {form.conditions.map((cond, index) => (
                <div className="condition-row" key={index}>
                  <input
                    placeholder="rule.id"
                    value={cond.field}
                    onChange={e => updateCondition(index, { field: e.target.value })}
                  />
                  <select value={cond.operator} onChange={e => updateCondition(index, { operator: e.target.value })}>
                    {CONDITION_OPERATORS.map(op => <option key={op} value={op}>{op}</option>)}
                  </select>
                  <input
                    placeholder={cond.operator === 'in' ? 'значение1, значение2' : 'значение'}
                    value={cond.value}
                    onChange={e => updateCondition(index, { value: e.target.value })}
                  />
                  <button
                    className="icon-btn"
                    onClick={() => removeCondition(index)}
                    disabled={form.conditions.length <= 1}
                    title="Удалить условие"
                  >
                    ✕
                  </button>
                </div>
              ))}
              <button className="ghost small" onClick={addCondition}>＋ Добавить условие</button>
            </div>

            <label className="checkbox-item standalone">
              <input
                type="checkbox"
                checked={form.is_active}
                onChange={e => setForm({ ...form, is_active: e.target.checked })}
              />
              <span>Правило активно</span>
            </label>

            {/* [17] Эскалация от поставщика логов: +1 уровень критичности инцидента */}
            <label className="checkbox-item standalone">
              <input
                type="checkbox"
                checked={form.escalated_by_vendor}
                onChange={e => setForm({ ...form, escalated_by_vendor: e.target.checked })}
              />
              <span>Поставщик логов отметил событие как крайне значимое (+1 уровень критичности)</span>
            </label>
            <span className="form-hint">
              Повышение применяется по процедуре определения критичности (docs/CRITICALITY_MATRIX.md): максимум один уровень
            </span>

            <div className="form-actions">
              <button className="ghost" onClick={() => setShowForm(false)}>Отмена</button>
              <button className="primary" onClick={saveRule} disabled={busy}>
                {busy ? 'Сохранение...' : 'Сохранить правило'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
