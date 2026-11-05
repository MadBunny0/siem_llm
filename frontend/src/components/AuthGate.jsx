// Корневой компонент авторизации: проверка сохранённой сессии, экран входа, рендер App.
// Вынесено из main.jsx (stage-19-legacy-cleanup).
// App импортируется из ../App.jsx (точка входа main.jsx рендерит AuthGate).

import React, { useEffect, useState } from 'react';
import { AUTH_EXPIRED_EVENT, clearSession, getAuthToken, loginRequest, readStoredToken, request } from '../api.js';
import LoginScreen from './LoginScreen.jsx';
import App from '../App.jsx';

/* ==================== Авторизация: корневой компонент ==================== */

export default function AuthGate() {
  const [user, setUser] = useState(null);
  const [booting, setBooting] = useState(() => !!readStoredToken());

  // Стартовая проверка сессии: если в localStorage есть siem_token —
  // запрашиваем GET /auth/me; при 401 request() уже очистил хранилище.
  useEffect(() => {
    let cancelled = false;
    async function bootstrap() {
      if (!getAuthToken()) {
        setBooting(false);
        return;
      }
      try {
        const me = await request('/auth/me');
        if (!cancelled) setUser(me);
      } catch (e) {
        if (!cancelled) clearSession();
      } finally {
        if (!cancelled) setBooting(false);
      }
    }
    bootstrap();
    return () => { cancelled = true; };
  }, []);

  // Истечение токена во время работы: request() отправляет событие —
  // сбрасываем user, интерфейс возвращается на экран входа.
  useEffect(() => {
    function handleExpired() { setUser(null); }
    window.addEventListener(AUTH_EXPIRED_EVENT, handleExpired);
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, handleExpired);
  }, []);

  async function handleLogin(username, password) {
    const me = await loginRequest(username, password);
    setUser(me);
  }

  function handleLogout() {
    clearSession();
    setUser(null);
  }

  if (booting) {
    return (
      <div className="login-screen">
        <div className="login-card">
          <div className="brand-mark">S</div>
          <h1 className="login-title">SIEM Intelligence</h1>
          <p className="login-subtitle">Проверка сохранённой сессии...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  return <App user={user} onLogout={handleLogout} />;
}
