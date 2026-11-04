// [18] Отметки «действие playbook запускали вручную» по инцидентам — localStorage.
// Фидбек пользователя: состояние кнопок закреплено на таске — нажал block_ip на
// инциденте 5, перешёл на инцидент 4 и вернулся, на инциденте 5 кнопка по-прежнему
// помечена выполненной; отметки переживают и смену инцидента, и перезагрузку страницы.
// В отличие от helpers.js этот модуль МОЖЕТ обращаться к localStorage (как токен-стор
// в main.jsx); все обращения в try/catch — недоступен storage, работаем в памяти.
// Без кэша в памяти: каждый вызов читает localStorage заново (отметки ставятся
// и сбрасываются вне React-состояния, тестам проще проверять реальное хранилище).

const STORAGE_KEY = 'siem_action_runs_v1';

// Всё хранилище: { [incidentId]: { [action]: { mode, at } } }; порча JSON или
// неожиданная структура → пустая структура, функции не падают.
function readRuns() {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (e) {
    return {};
  }
}

function writeRuns(runs) {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(runs));
  } catch (e) {
    /* записать не удалось (переполнение/приватный режим) — отметка просто не переживёт перезагрузку */
  }
}

// Запомнить, что действие action запускали вручную на инциденте incidentId
// (mode — режим исполнения из ответа execute-action: 'simulation' | 'controlled').
export function markActionRun(incidentId, action, mode) {
  if (incidentId === null || incidentId === undefined || action === null || action === undefined) return;
  const runs = readRuns();
  const incidentKey = String(incidentId);
  const incidentRuns = runs[incidentKey] && typeof runs[incidentKey] === 'object' ? runs[incidentKey] : {};
  incidentRuns[String(action)] = { mode: mode || null, at: new Date().toISOString() };
  runs[incidentKey] = incidentRuns;
  writeRuns(runs);
}

// Запускали ли это действие вручную на данном инциденте.
export function isActionRun(incidentId, action) {
  if (incidentId === null || incidentId === undefined || action === null || action === undefined) return false;
  return !!getIncidentRuns(incidentId)[String(action)];
}

// Карта отметок одного инцидента: { [action]: { mode, at } }; нет отметок → {}.
export function getIncidentRuns(incidentId) {
  if (incidentId === null || incidentId === undefined) return {};
  const incidentRuns = readRuns()[String(incidentId)];
  return incidentRuns && typeof incidentRuns === 'object' ? incidentRuns : {};
}

// Сбросить отметки инцидента (кнопка «Сбросить отметки») → true, если они были.
export function clearIncidentRuns(incidentId) {
  if (incidentId === null || incidentId === undefined) return false;
  const runs = readRuns();
  const incidentKey = String(incidentId);
  const had = !!(runs[incidentKey] && typeof runs[incidentKey] === 'object' && Object.keys(runs[incidentKey]).length);
  if (had) {
    delete runs[incidentKey];
    writeRuns(runs);
  }
  return had;
}
