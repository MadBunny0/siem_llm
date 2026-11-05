// Экран входа SIEM Intelligence (демо-доступ: analyst1/analyst123, soc_lead/soclead123).
// Вынесено из main.jsx (stage-19-legacy-cleanup).

import React, { useState } from 'react';

/* ==================== Экран входа ==================== */

export default function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    if (busy) return;
    if (!username.trim() || !password) {
      setError('Введите имя пользователя и пароль');
      return;
    }
    setBusy(true);
    setError('');
    try {
      await onLogin(username.trim(), password);
    } catch (err) {
      setError(err.message || 'Не удалось выполнить вход');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={submit}>
        <div className="brand-mark">S</div>
        <h1 className="login-title">SIEM Intelligence — вход</h1>
        <p className="login-subtitle">Введите учётные данные центра мониторинга</p>

        <div className="form-group">
          <label>Логин</label>
          <input
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="analyst1"
            autoComplete="username"
            autoFocus
          />
        </div>

        <div className="form-group">
          <label>Пароль</label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="••••••••"
            autoComplete="current-password"
          />
        </div>

        {error && <div className="login-error">⚠ {error}</div>}

        <button className="primary login-submit" type="submit" disabled={busy}>
          {busy ? '◌ Проверка учётных данных...' : 'Войти'}
        </button>

        <p className="login-hint">
          Демо-доступ: <b>analyst1 / analyst123</b> — аналитик · <b>soc_lead / soclead123</b> — администратор
        </p>
      </form>
    </div>
  );
}
