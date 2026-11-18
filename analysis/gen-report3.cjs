// Генератор docx-отчёта живого прогона Сценария 3 (E2E) «Инсайдер: бэкдор-аккаунт на сервере».
// Запуск: node:22-alpine, NODE_PATH=<node_modules с docx>, изображения analysis/run3/*.png.
const fs = require('fs');
const path = require('path');
function pngSize(p) { const b = fs.readFileSync(p); return { width: b.readUInt32BE(16), height: b.readUInt32BE(20) }; }
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, ImageRun,
  Table, TableRow, TableCell, WidthType, AlignmentType,
  ShadingType, Footer, PageNumber, NumberFormat, VerticalAlign,
} = require('docx');

const IMG_DIR = '/data/run3';
const OUT = '/data/Отчёт_прогон_Сценария3.docx';
const MAXW = 620;

const FONT = 'Times New Roman';
const body = (text, opts = {}) => new Paragraph({
  spacing: { line: 312, after: 120 },
  alignment: AlignmentType.JUSTIFIED,
  firstLineIndent: 709,
  children: [new TextRun({ text, font: FONT, size: 24, ...opts })],
});
const h1 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 }, children: [new TextRun({ text, font: FONT, size: 32, bold: true, color: '000000' })] });
const h2 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 120 }, children: [new TextRun({ text, font: FONT, size: 28, bold: true, color: '000000' })] });
const bullet = (text) => new Paragraph({
  spacing: { line: 312, after: 60 }, alignment: AlignmentType.JUSTIFIED,
  numbering: { reference: 'bullets', level: 0 },
  children: [new TextRun({ text, font: FONT, size: 24 })],
});

function img(file, caption, num) {
  const p = path.join(IMG_DIR, file);
  const dim = pngSize(p);
  const w = Math.min(MAXW, dim.width);
  const h = Math.round(dim.height * (w / dim.width));
  return [
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 120, after: 60 },
      keepNext: true,
      children: [new ImageRun({ type: 'png', data: fs.readFileSync(p), transformation: { width: w, height: h } })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 160 },
      children: [new TextRun({ text: `Рисунок ${num} — ${caption}`, font: FONT, size: 22, italics: true, color: '333333' })],
    }),
  ];
}

const cell = (text, { bold = false, header = false, w } = {}) => new TableCell({
  width: w ? { size: w, type: WidthType.PERCENTAGE } : undefined,
  verticalAlign: VerticalAlign.CENTER,
  shading: header ? { type: ShadingType.CLEAR, fill: 'EDF1F7' } : undefined,
  margins: { top: 80, bottom: 80, left: 120, right: 120 },
  children: [new Paragraph({
    spacing: { line: 276 },
    children: [new TextRun({ text, font: FONT, size: 22, bold: bold || header })],
  })],
});

const FIGS = [
  ['01_feed_backdoor_incident.png', 'Лента инцидентов после атаки: инцидент №6 «Создание учётной записи на сервере: возможный бэкдор-аккаунт» (critical, NEW), ниже — закрытые инциденты Сценариев 1 и 2'],
  ['02_card_top.png', 'Карточка инцидента №6: статус NEW, риск 100/100, актив mail-prod-01 (critical); «Оценка критичности»: тактика Privilege Escalation (T1068) — «Высокий», повышение за критичный актив → critical'],
  ['03_card_pipeline_events.png', 'Числовая модель риска (уровень правила 70, актив 100, опасность типа атаки 95), конвейер обработки и хронология четырёх событий privilege_escalation с пользователем svc_helper'],
  ['04_pipeline_qwen_running.png', 'Интеллектуальный анализ выполняется в фоне (этап QWEN)'],
  ['05_verdict_panel.png', 'Структурированный результат анализа: разбор команд и событий (useradd/usermod/passwd с именем svc_helper), подозрительные фрагменты, возможные легитимные объяснения, затронутые сущности, рекомендации, дерево процессов; проверка DVE'],
  ['06_verdict_summary.png', 'Результат анализа: вердикт Pending, уверенность 75%, рекомендация monitor; резюме: учётная запись создана с привилегиями sudo и сменён пароль — возможный бэкдор-аккаунт, недостаточно доказательств'],
  ['07_dve_before_action.png', 'Блок «Все действия playbook» перед реакцией; в истории анализов — вердикт qwen2.5:3b (Pending, privilege_escalation, 75%)'],
  ['08_action_done.png', 'Исполнение disable_account: отметка «✓ Выполнено», оператор soc_lead, цель svc_helper (взята из событий инцидента)'],
  ['09_responses_vm_tab.png', 'Вкладка «Реакции (ВМ)»: блокировка учётной записи svc_helper на активе mail-prod-01 (инцидент №6)'],
  ['10_after_reset.png', 'После «Сбросить реакции»: отметка исполненного действия снята, кнопки playbook доступны снова'],
  ['11_closed.png', 'Инцидент №6 переведён в статус «Закрыт»'],
];

const MEAS = [
  ['Правило Wazuh (id, уровень)', '100300 (level 10, useradd) + 100301/100302 (level 9, usermod/passwd)', 'Кастомные правила стенда; родитель — built-in 5902 (adduser)'],
  ['Событие (event_type)', 'privilege_escalation ×4; пользователь события = svc_helper (декодер stand-useradd), источник /var/log/auth.log', 'Нормализация: groups[0] — семантическое имя'],
  ['Корреляция (порог/окно)', 'privilege_escalation_attempt: 1 событие (T1068)', 'В прогоне: 4 события атаки в одной сессии'],
  ['Критичность (severity_factors)', 'База privilege_escalation = high; повышение «критичный бизнес-актив» → critical; риск 100/100 (актив critical)', 'Матрица MITRE + модель риска §3.3.3'],
  ['Время детекции', 'атака 16:03:38–42 → инцидент 16:03:46 (≈4–8 с)', 'Локальные команды логируются мгновенно'],
  ['Результат LLM (Qwen2.5-3B, GPU)', 'Вердикт Pending, тип атаки privilege_escalation, уверенность 75%; рекомендация monitor; разбор команд, дерево процессов; ≈13 с', 'Честный вердикт: признаки бэкдор-аккаунта, но доказательств недостаточно'],
  ['Решение DVE', 'disable_account разрешён политикой для critical; исполнено soc_lead (администратор)', '§3.4 ВКР; на high-инциденте действием можно показать отказ валидации'],
  ['Реакция', '!lock-account.sh lock svc_helper, агент 001; клик 16:11:22.4 → passwd -l 16:11:22 (<1 с)', 'Цель взята из событий инцидента'],
  ['Физический эффект', 'passwd -S svc_helper = L; хеш в /etc/shadow с «!»; ssh под svc_helper с верным паролем — Permission denied', 'Проверено на ВМ-1 и сетевым входом'],
  ['Откат («Сбросить реакции»)', '!lock-account.sh unlock; хеш без «!», ssh-вход под svc_helper восстановлен (uid=1002); инцидент closed; svc_helper удалён после сценария', 'best-effort через Wazuh API'],
];

const children = [
  new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 60 },
    children: [new TextRun({ text: 'SIEM + LLM: интеллектуальная обработка инцидентов', font: FONT, size: 28, bold: true })],
  }),
  new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 240 },
    children: [new TextRun({ text: 'Живой прогон Сценария 3 (E2E) «Инсайдер: бэкдор-аккаунт на сервере» — протокол эксперимента и материалы', font: FONT, size: 26, bold: true })],
  }),
  body('Дата прогона: 18.11.2026. Оператор: soc_lead (администратор). Цель — проверка конвейера на Insider-сценарии: создание бэкдор-учётной записи непосредственно на критичном сервере, реакция disable_account с целью, извлечённой из событий инцидента, и физической проверкой блокировки учётной записи. Третий сценарий серии, замыкающий проверку всех типов реакций playbook.'),

  h1('1. Топология и предусловия'),
  bullet('Windows-хост: SIEM-стенд в Docker (PostgreSQL, Ollama с Qwen2.5-3B на GPU RTX 4060 Ti, FastAPI, веб-интерфейс :3000, Wazuh-manager); хост используется для SSH-доступа оператора к ВМ-1.'),
  bullet('ВМ-1 mail-prod-01 — 192.168.56.101 (VirtualBox, Kali): sshd + rsyslog + wazuh-agent 4.7.4 (ID 001, Active), AR-скрипты block-ip/lock-account/isolate-host; учётная запись оператора socop (sudo).'),
  bullet('Канал детекции: /var/log/auth.log → агент (правила стенда 100300/100301/100302) → менеджер → интегратор → POST /api/v1/ingest/wazuh. Канал реакции: API SIEM → Wazuh Manager API → агент ВМ.'),
  bullet('Особенность сценария: команды выполняются локально на ВМ (легенда «злоумышленник получил сессию на сервере»), источник атаки — сама ВМ; имя создаваемой учётной записи svc_helper извлекается кастомным декодером stand-useradd и становится пользователем события — именно оно используется как цель реакции.'),

  h1('2. Ход прогона'),

  h2('2.1. Атака (создание бэкдор-аккаунта)'),
  body('На ВМ-1 от имени оператора с повышением до root выполнены: useradd -m -s /bin/bash svc_helper (создание учётной записи), usermod -aG sudo svc_helper (добавление в группу sudo) и passwd svc_helper (установка пароля). Каждая операция отражена строками в /var/log/auth.log; wazuh-агент доставил алерты правил стенда 100300 (level 10), 100301 и 100302 (level 9) с пользователем события svc_helper.'),
  ...img(FIGS[0][0], FIGS[0][1], 1),

  h2('2.2. Детекция и корреляция'),
  body('Правило корреляции privilege_escalation_attempt имеет порог 1 событие — инцидент №6 создан через ≈4–8 секунд после первой команды. Критичность по матрице MITRE: тактика Privilege Escalation — «Высокий», повышение за критичный бизнес-актив → critical; риск 100/100 (актив critical; уровень правила 70; опасность типа атаки 95).'),
  ...img(FIGS[1][0], FIGS[1][1], 2),
  ...img(FIGS[2][0], FIGS[2][1], 3),

  h2('2.3. Интеллектуальный анализ (Qwen2.5-3B)'),
  body('Анализ запущен оператором; инференс на GPU занял ≈13 секунд. Модель вернула вердикт Pending (уверенность 75%) с типом атаки privilege_escalation и рекомендацией monitor. Структурированный результат содержит разбор команд и событий с именем svc_helper, подозрительные фрагменты, возможные легитимные объяснения (штатное использование useradd), затронутые сущности и дерево процессов (useradd → usermod → passwd) — резюме фиксирует: учётная запись создана с привилегиями sudo и сменён пароль, что может быть бэкдор-аккаунтом, однако доказательств недостаточно.'),
  ...img(FIGS[3][0], FIGS[3][1], 4),
  ...img(FIGS[4][0], FIGS[4][1], 5),
  ...img(FIGS[5][0], FIGS[5][1], 6),

  h2('2.4. Реакция: отключение учётной записи'),
  body('Оператор-администратор запускает disable_account из перечня всех действий playbook; действие разрешено политикой DVE для уровня critical. Цель реакции — svc_helper — извлечена из событий инцидента (декодер stand-useradd). Команда !lock-account.sh lock svc_helper доставлена агенту 001; в карточке — отметка «✓ Выполнено» с указанием оператора и цели.'),
  ...img(FIGS[6][0], FIGS[6][1], 7),
  ...img(FIGS[7][0], FIGS[7][1], 8),

  h2('2.5. Физическая проверка эффекта'),
  body('На ВМ-1: passwd -S svc_helper возвращает статус L (locked), хеш пароля в /etc/shadow начинается с «!», сетевой вход под svc_helper с заведомо верным паролем отклонён (Permission denied). В active-responses.log — запись lock-account.sh о блокировке в момент клика (11:11:22 EST — совпадает с временем нажатия кнопки, реакция быстрее одной секунды). Вкладка «Реакции (ВМ)» отображает активную блокировку учётной записи с указанием оператора и времени.'),
  ...img(FIGS[8][0], FIGS[8][1], 9),

  h2('2.6. Откат реакции и закрытие инцидента'),
  body('«Сбросить реакции» выполняет обратную команду lock-account unlock: «!» снят с хеша, вход под svc_helper с тем же паролем снова успешен (uid=1002). Инцидент №6 переведён в статус «Закрыт»; после сценария тестовая учётная запись удалена с ВМ (userdel -r).'),
  ...img(FIGS[9][0], FIGS[9][1], 10),
  ...img(FIGS[10][0], FIGS[10][1], 11),

  h1('3. Таблица замеров'),
  new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({ tableHeader: true, cantSplit: true, children: [cell('Параметр', { header: true, w: 28 }), cell('Наблюдение в прогоне', { header: true, w: 48 }), cell('Примечание', { header: true, w: 24 })] }),
      ...MEAS.map(([a, b, c]) => new TableRow({ cantSplit: true, children: [cell(a, { bold: true, w: 28 }), cell(b, { w: 48 }), cell(c, { w: 24 })] })),
    ],
  }),

  h1('4. Замечания по прогону'),
  bullet('Склейка событий корреляцией выполняется по активу в окне ±5 минут, поэтому служебные события сессии оператора (SSH-вход, sudo) попали в состав инцидента и в его заголовок; перед фиксацией материалов инцидент вычищен точечной правкой демо-БД (оставлены 4 события атаки).'),
  bullet('Запрос статуса блокировки (passwd -S) порождает запись auth.log с программой passwd и сам матчится правилом 100302 — проверки статуса выполнялись через чтение /etc/shadow и сетевой вход.'),
  bullet('Удаление учётной записи (userdel) порождает событие правила 100300 без пользователя (декодер обрабатывает useradd/usermod/passwd) и формирует отдельный шумовой инцидент после закрытия сценария — инцидент вычищен из демо-БД; для повторных прогонов удаление выполняется после фиксации материалов.'),

  h1('5. Выводы'),
  body('Insider-сценарий воспроизведён на реальных компонентах: локальные действия на сервере детектируются агентом Wazuh в реальном времени, корреляция с порогом 1 событие формирует критический инцидент, LLM даёт осторожный вердикт с полным разбором последовательности команд, реакция disable_account блокирует учётную запись за время менее секунды с проверяемым эффектом (passwd -l, отказ сетевого входа), откат возвращает доступ. Три сценария серии (внешний подбор пароля, веб-атака, инсайдер) совместно покрывают все три типа реакций playbook — block_ip, isolate-host-класс и disable_account (lock-account). Материалы (рисунки 1–11 и таблица замеров) предназначены для экспериментальной части ВКР.'),
];

const doc = new Document({
  numbering: { config: [{ reference: 'bullets', levels: [{ level: 0, format: 'bullet', text: '—', alignment: AlignmentType.LEFT }] }] },
  styles: { default: { document: { run: { font: FONT, size: 24 } } } },
  sections: [{
    properties: {
      page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 }, pageNumbers: { start: 1, formatType: NumberFormat.DECIMAL } },
    },
    footers: {
      default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 20 })] })] }),
    },
    children,
  }],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(OUT, buf);
  console.log('OK:', OUT, buf.length, 'bytes');
});
