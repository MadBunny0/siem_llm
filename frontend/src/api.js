// API-клиент фронтенда: базовый путь, JWT-сессия в localStorage, fetch-обёртки.
// Вынесено из main.jsx (stage-19-legacy-cleanup).

import { detailToMessage } from './lib/helpers.js';

const API = '/api/v1';

/* ==================== Авторизация (JWT) ==================== */

const TOKEN_KEY = 'siem_token';
const USER_KEY = 'siem_user';
export const AUTH_EXPIRED_EVENT = 'siem-auth-expired';

// Зеркало токена на уровне модуля: request() вызывается из всех вкладок без
// пропсов, поэтому токен хранится здесь, а состояние React (AuthGate)
// синхронизирует эту переменную при входе, выходе и истечении сессии.
let authToken = readStoredToken();

export function readStoredToken() {
  try {
    return window.localStorage.getItem(TOKEN_KEY) || '';
  } catch (e) {
    return '';
  }
}

// Актуальное значение зеркала токена для модулей вне api.js (использует AuthGate).
export function getAuthToken() {
  return authToken;
}

function setStoredToken(token) {
  authToken = token || '';
  try {
    if (authToken) window.localStorage.setItem(TOKEN_KEY, authToken);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch (e) {
    /* localStorage может быть недоступен — сессия просто не переживёт перезагрузку */
  }
}

function setStoredUser(user) {
  try {
    if (user) window.localStorage.setItem(USER_KEY, JSON.stringify(user));
    else window.localStorage.removeItem(USER_KEY);
  } catch (e) {
    /* ignore */
  }
}

export function clearSession() {
  setStoredToken('');
  setStoredUser(null);
}

export async function request(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  const response = await fetch(`${API}${path}`, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    // 401 — токен отсутствует/просрочен: сбрасываем сессию, AuthGate покажет экран входа.
    // 403 (недостаточно прав) пробрасывается дальше как обычная ошибка (alert/тост).
    if (response.status === 401) {
      clearSession();
      try {
        window.dispatchEvent(new Event(AUTH_EXPIRED_EVENT));
      } catch (e) {
        /* ignore */
      }
    }
    throw new Error(detailToMessage(data && data.detail, `HTTP ${response.status}`));
  }
  return data;
}

export async function loginRequest(username, password) {
  const data = await request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  if (!data || !data.access_token) {
    throw new Error('Сервер не вернул токен доступа');
  }
  setStoredToken(data.access_token);
  try {
    const me = await request('/auth/me');
    setStoredUser(me);
    return me;
  } catch (e) {
    clearSession();
    throw e;
  }
}
