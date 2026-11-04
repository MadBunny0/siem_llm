// Вкладка «Playbooks»: просмотр, создание, редактирование и удаление сценариев реагирования (admin).
// Вынесено из main.jsx (stage-19-legacy-cleanup).

import React, { useEffect, useState } from 'react';
import { request } from '../api.js';
import { PRIORITIES } from '../constants.js';
import { actionRuDescription, criteriaCountLabel, PLAYBOOK_ACTIONS, priorityLabel } from '../lib/helpers.js';

/* ==================== Вкладка «Playbooks» ==================== */

export default function PlaybooksView({ notify, toastError, isAdmin }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [busyId, setBusyId] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(() => emptyPlaybookForm());

  function emptyPlaybookForm() {
    return {
      name: '',
      description: '',
      priority: 2,
      is_active: true,
      allowed_actions: ['monitor'],
      steps: '',
      success_criteria: '',
    };
  }

  async function load() {
    setLoading(true);
    try {
      setError('');
      setItems(await request('/playbooks'));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  function openCreate() {
    setEditing(null);
    setForm(emptyPlaybookForm());
    setShowForm(true);
  }

  function openEdit(rule) {
    setEditing(rule);
    setForm({
      name: rule.name || '',
      description: rule.description || '',
      priority: rule.priority === null || rule.priority === undefined ? 2 : Number(rule.priority),
      is_active: rule.is_active !== false,
      allowed_actions: Array.isArray(rule.allowed_actions)
        ? rule.allowed_actions.filter(a => PLAYBOOK_ACTIONS.includes(a))
        : [],
      steps: rule.steps === null || rule.steps === undefined ? '' : JSON.stringify(rule.steps, null, 2),
      // Stage 11: массив критериев сериализуется в строки — по одному на строку
      success_criteria: Array.isArray(rule.success_criteria) ? rule.success_criteria.join('\n') : '',
    });
    setShowForm(true);
  }

  function toggleAction(action, checked) {
    setForm(f => ({
      ...f,
      allowed_actions: checked
        ? [...f.allowed_actions, action]
        : f.allowed_actions.filter(a => a !== action),
    }));
  }

  async function savePlaybook() {
    if (!form.name.trim()) {
      toastError('Укажите название playbook');
      return;
    }
    if (!form.allowed_actions.length) {
      toastError('Выберите хотя бы одно разрешённое действие');
      return;
    }
    let steps = [];
    if (form.steps.trim()) {
      try {
        steps = JSON.parse(form.steps);
      } catch (e) {
        toastError(`Некорректный JSON в поле «Шаги»: ${e.message}`);
        return;
      }
      if (!Array.isArray(steps)) {
        toastError('Поле «Шаги» должно быть JSON-массивом, например [{"action": "isolate_host"}]');
        return;
      }
      if (!steps.every(item => item !== null && typeof item === 'object' && !Array.isArray(item))) {
        toastError('Каждый элемент «Шагов» должен быть JSON-объектом');
        return;
      }
    }
    const priorityNumber = Number(form.priority);
    // Stage 11: критерии успешного завершения — по одному на строку, пустые отбрасываем
    const successCriteria = form.success_criteria
      .split('\n')
      .map(line => line.trim())
      .filter(Boolean);
    const payload = {
      name: form.name.trim(),
      description: form.description.trim(),
      allowed_actions: form.allowed_actions,
      steps,
      success_criteria: successCriteria.length ? successCriteria : null,
      priority: Number.isFinite(priorityNumber) ? priorityNumber : 1,
      is_active: form.is_active,
    };
    if (editing) payload.trigger_conditions = editing.trigger_conditions ?? {};
    setBusy(true);
    try {
      if (editing) {
        await request(`/playbooks/${editing.id}`, { method: 'PUT', body: JSON.stringify(payload) });
        notify('Playbook обновлён');
      } else {
        await request('/playbooks', { method: 'POST', body: JSON.stringify(payload) });
        notify('Playbook создан');
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
      const updated = await request(`/playbooks/${rule.id}`, {
        method: 'PUT',
        body: JSON.stringify({ ...rule, is_active: !rule.is_active }),
      });
      setItems(prev => prev.map(r => (r.id === rule.id ? { ...r, ...updated } : r)));
      notify(`Playbook «${rule.name}» ${rule.is_active ? 'деактивирован' : 'активирован'}`);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  async function deletePlaybook(rule) {
    if (!window.confirm(`Удалить playbook «${rule.name}»?`)) return;
    setBusyId(rule.id);
    try {
      await request(`/playbooks/${rule.id}`, { method: 'DELETE' });
      notify(`Playbook «${rule.name}» удалён`);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  }

  const priorityOptions = PRIORITIES.includes(form.priority)
    ? PRIORITIES
    : [...PRIORITIES, form.priority].sort((a, b) => a - b);

  return (
    <div className="panel tab-panel">
      <div className="panel-head">
        <div>
          <h2>Playbooks реагирования</h2>
          <p>Сценарии автоматических действий по инцидентам</p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="ghost" onClick={load} disabled={loading}>{loading ? <><span className="spinner spinner-dark"></span> Обновление...</> : '↻ Обновить'}</button>
          {isAdmin && <button className="primary" onClick={openCreate} disabled={busy}>＋ Новый playbook</button>}
        </div>
      </div>
      {error && <div className="alert error">⚠ {error}</div>}
      {loading ? (
        <div className="empty">Загрузка данных...</div>
      ) : items.length === 0 ? (
        <div className="empty">
          <div className="empty-icon">▶</div>
          <h3>Playbooks пока нет</h3>
          <p>Создайте сценарий, чтобы модуль Playbook Execution мог выполнять действия по инцидентам.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Название</th>
                <th>Разрешённые действия</th>
                <th>Шаги</th>
                <th>Приоритет</th>
                <th>Активен</th>
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
                  <td>
                    {(rule.allowed_actions || []).length ? (
                      <>
                        {/* [3] русское описание каждого действия — tooltip на чипе + строкой под ним */}
                        <div className="stack">
                          {(rule.allowed_actions || []).map(a => <span key={a} title={actionRuDescription(a)}>{a}</span>)}
                        </div>
                        <div className="playbook-actions-ru">
                          {(rule.allowed_actions || []).map(a => actionRuDescription(a)).join(' · ')}
                        </div>
                      </>
                    ) : '—'}
                  </td>
                  <td>
                    {Array.isArray(rule.steps) ? rule.steps.length : '—'}
                    {Array.isArray(rule.success_criteria) && rule.success_criteria.length > 0 && (
                      <span
                        className="chip accent criteria-chip"
                        title={rule.success_criteria.map((c, i) => `${i + 1}. ${c}`).join('\n')}
                      >
                        {criteriaCountLabel(rule.success_criteria.length)}
                      </span>
                    )}
                  </td>
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
                        <button className="icon-btn" onClick={() => deletePlaybook(rule)} disabled={busyId === rule.id} title="Удалить playbook">✕</button>
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
            <h3>{editing ? `Редактирование playbook #${editing.id}` : 'Новый playbook'}</h3>
            <p className="modal-subtitle">Определяет, какие действия разрешено выполнять автоматически по инциденту</p>

            <div className="form-group">
              <label>Название *</label>
              <input
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder="Например: Изоляция хоста при успешном брутфорсе"
              />
            </div>

            <div className="form-group">
              <label>Описание</label>
              <input
                value={form.description}
                onChange={e => setForm({ ...form, description: e.target.value })}
                placeholder="Когда и зачем применяется сценарий"
              />
            </div>

            <div className="form-group">
              <label>Разрешённые действия *</label>
              <div className="checkbox-row">
                {PLAYBOOK_ACTIONS.map(action => (
                  <label className="checkbox-item" key={action}>
                    <input
                      type="checkbox"
                      checked={form.allowed_actions.includes(action)}
                      onChange={e => toggleAction(action, e.target.checked)}
                    />
                    <span>{action}</span>
                  </label>
                ))}
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div className="form-group">
                <label>Приоритет</label>
                <select value={form.priority} onChange={e => setForm({ ...form, priority: Number(e.target.value) })}>
                  {priorityOptions.map(p => <option key={p} value={p}>{priorityLabel(p)}</option>)}
                </select>
              </div>
              <div className="form-group">
                <label>Состояние</label>
                <label className="checkbox-item standalone" style={{ marginTop: '2px' }}>
                  <input
                    type="checkbox"
                    checked={form.is_active}
                    onChange={e => setForm({ ...form, is_active: e.target.checked })}
                  />
                  <span>Playbook активен</span>
                </label>
              </div>
            </div>

            <div className="form-group">
              <label>Шаги (JSON-массив)</label>
              <textarea
                className="mono"
                rows="6"
                value={form.steps}
                onChange={e => setForm({ ...form, steps: e.target.value })}
                placeholder={'[\n  { "order": 1, "action": "isolate_host", "description": "Изолировать скомпрометированный хост" }\n]'}
              />
            </div>

            <div className="form-group">
              <label>Критерии успешного завершения</label>
              <textarea
                rows="3"
                value={form.success_criteria}
                onChange={e => setForm({ ...form, success_criteria: e.target.value })}
                placeholder={'Необязательно, по одному критерию на строку, например:\nХост изолирован от корпоративной сети\nВредоносный IP-адрес добавлен в блок-лист'}
              />
            </div>

            <div className="form-actions">
              <button className="ghost" onClick={() => setShowForm(false)}>Отмена</button>
              <button className="primary" onClick={savePlaybook} disabled={busy}>
                {busy ? 'Сохранение...' : 'Сохранить playbook'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
