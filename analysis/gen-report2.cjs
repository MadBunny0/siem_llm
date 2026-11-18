// Генератор docx-отчёта живого прогона Сценария 2 (E2E) «SQL-инъекция на веб-сервис».
// Запуск: node:22-alpine, NODE_PATH=<node_modules с docx>, изображения analysis/run2/*.png.
const fs = require('fs');
const path = require('path');
function pngSize(p) { const b = fs.readFileSync(p); return { width: b.readUInt32BE(16), height: b.readUInt32BE(20) }; }
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, ImageRun,
  Table, TableRow, TableCell, WidthType, AlignmentType, BorderStyle,
  ShadingType, Footer, PageNumber, NumberFormat, VerticalAlign,
} = require('docx');

const IMG_DIR = '/data/run2';
const OUT = '/data/Отчёт_прогон_Сценария2.docx';
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
  ['01_feed_before.png', 'Лента инцидентов до атаки: инцидент первого сценария в статусе «Закрыт»'],
  ['02_feed_sqli_incident.png', 'Лента после атаки: инцидент №5 «nginx: SQL-инъекция в параметрах запроса» (high, NEW) сформирован корреляцией из двух событий web_attack'],
  ['03_card_top.png', 'Карточка инцидента №5: статус NEW, риск 100/100, актив mail-prod-01 (critical); «Оценка критичности»: тактика Initial Access (T1190) — «Средний», повышение за критичный актив → high'],
  ['04_card_pipeline_events.png', 'Конвейер обработки (WAZUH→NORMALIZE→CORRELATE→RISK пройдены, QWEN ожидает) и хронология двух событий web_attack с адреса атакующего 192.168.56.50'],
  ['05_pipeline_qwen_running.png', 'Интеллектуальный анализ выполняется в фоне (этап QWEN)'],
  ['06_history_verdict_playbook.png', 'История анализов: qwen2.5:3b, вердикт Pending (web_attack, уверенность 80%), рекомендация monitor, collect_evidence'],
  ['07_verdict_panel.png', 'Шапка инцидента после анализа: статус IN_PROGRESS, тип атаки web_attack, назначен soc_lead'],
  ['08_verdict_details.png', 'Разбор вердикта: рекомендации, предложенные действия (проверка DVE: monitor — РАЗРЕШЕНО, ожидает запуска) и все действия playbook'],
  ['09_verdict_summary.png', 'Конвейер после анализа (QWEN, VALIDATE пройдены) и результат анализа: PENDING, уверенность 80%, рекомендация monitor; резюме: пара подозрительных SQL-запросов не привела к успешному выполнению'],
  ['10_playbook_before_action.png', 'Рекомендации для дальнейших действий, проверка DVE (monitor и collect_evidence разрешены) и перечень всех действий playbook до реакции'],
  ['11_action_done.png', 'Исполнение block_ip: тост о доставке команды (!block-ip.sh add 192.168.56.50, агент 001), отметка «✓ Выполнено» с указанием оператора и цели'],
  ['12_responses_vm_tab.png', 'Вкладка «Реакции (ВМ)»: активная блокировка на активе mail-prod-01 (инцидент №5), оператор soc_lead, время'],
  ['13_after_reset.png', 'После «Сбросить реакции»: отметка исполненного действия снята, кнопки playbook доступны снова'],
  ['14_closed.png', 'Инцидент №5 переведён в статус «Закрыт»'],
];

const MEAS = [
  ['Правило Wazuh (id, уровень)', '100200 (level 10); родитель — built-in 31103 (SQLi UNION)', 'Кастомное правило стенда: SQL-инъекция в параметрах запроса'],
  ['Событие (event_type)', 'web_attack ×2 (src_ip=192.168.56.50), источник /var/log/nginx/access.log', 'Нормализация: groups[0] — семантическое имя'],
  ['Корреляция (порог/окно)', 'web_attack: 2 события за 5 мин (T1190)', 'В прогоне: 2 UNION-запроса за ~4 с'],
  ['Критичность (severity_factors)', 'База initial_access = medium; повышение «критичный бизнес-актив» → high; риск 100/100 (актив critical)', 'Матрица MITRE + модель риска §3.3.3'],
  ['Время детекции', 'атака 15:42:08 → инцидент 15:42:14 (≈6 с)', 'Агент доставляет алерты в реальном времени'],
  ['Результат LLM (Qwen2.5-3B, GPU)', 'Вердикт Pending, тип атаки web_attack, уверенность 80%; рекомендация monitor + collect_evidence; ≈16 с', 'Честный вердикт: запросы не привели к успеху, подозрительность требует анализа'],
  ['Решение DVE', 'block_ip разрешён политикой для high; исполнено soc_lead (администратор)', '§3.4 ВКР'],
  ['Реакция', '!block-ip.sh add 192.168.56.50, агент 001; клик 15:47:34.9 → iptables 15:47:35 (≈1 с)', 'Wazuh AR: PUT /active-response → агент'],
  ['Физический эффект', 'iptables INPUT DROP для 192.168.56.50; curl с .50 — timeout (curl exit 28)', 'Проверено с атакующего адреса'],
  ['Откат («Сбросить реакции»)', '!block-ip.sh delete; iptables пуст; curl — HTTP 200 за 4 мс; инцидент closed', 'best-effort через Wazuh API'],
];

const children = [
  new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 60 },
    children: [new TextRun({ text: 'SIEM + LLM: интеллектуальная обработка инцидентов', font: FONT, size: 28, bold: true })],
  }),
  new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 240 },
    children: [new TextRun({ text: 'Живой прогон Сценария 2 (E2E) «SQL-инъекция на веб-сервис» — протокол эксперимента и материалы', font: FONT, size: 26, bold: true })],
  }),
  body('Дата прогона: 18.11.2026. Оператор: soc_lead (администратор). Цель — проверка конвейера на втором классе атак: веб-атака по HTTP на сервис, размещённый на критичном сервере, с исполнением реальной реакции блокирования адреса источника. Прогон выполнен на той же топологии, что и Сценарий 1; блок физического эффекта и откат верифицированы консольными проверками.'),

  h1('1. Топология и предусловия'),
  bullet('Windows-хост: SIEM-стенд в Docker (PostgreSQL, Ollama с Qwen2.5-3B на GPU RTX 4060 Ti, FastAPI, веб-интерфейс :3000, Wazuh-manager); хост — атакующий узел с дополнительным адресом 192.168.56.50.'),
  bullet('ВМ-1 mail-prod-01 — 192.168.56.101 (VirtualBox, Kali): sshd + nginx + rsyslog + wazuh-agent 4.7.4 (ID 001, Active); nginx пишет access.log в формате apache, файл включён в ossec.conf как localfile.'),
  bullet('Канал детекции: nginx access.log → агент (правила стенда 100200/100201) → менеджер → интегратор → POST /api/v1/ingest/wazuh. Канал реакции: API SIEM → Wazuh Manager API → агент ВМ.'),
  bullet('Перед прогоном: демо-БД вычищена от шумовых инцидентов (правило repeated_scan, склеивающее любой SSH-шум с непустым src_ip, деактивировано), окно корреляции выдержано тихим (≥6 мин без событий по активу).'),

  h1('2. Ход прогона'),

  h2('2.1. Атака (SQL-инъекция по HTTP)'),
  body('С атакующего адреса 192.168.56.50 выполнены два запроса с SQL-конструкциями в параметре id (UNION SELECT username,password FROM users и UNION SELECT version(),user()) к http://192.168.56.101/index.php. Ответ сервера 404 не важен: в журнал доступа попадает сам факт запроса, который wazuh-агент доставляет менеджеру. На обе строки сработало правило стенда 100200 (level 10, groups[0]=web_attack) — две атаки за ~4 секунды.'),
  ...img(FIGS[0][0], FIGS[0][1], 1),

  h2('2.2. Детекция и корреляция'),
  body('Порог правила web_attack (2 события за 5 минут, T1190) набран мгновенно — инцидент №5 «nginx: SQL-инъекция в параметрах запроса (стенд)» создан через ≈6 секунд после первого запроса. В хронологии инцидента — ровно два события атаки от 192.168.56.50.'),
  ...img(FIGS[1][0], FIGS[1][1], 2),

  h2('2.3. Оценка критичности инцидента'),
  body('Блок «Оценка критичности»: базовый уровень по тактике Initial Access — «Средний»; повышение на один уровень за критичный бизнес-актив → итог high. Числовая модель риска: база = максимум слагаемых (критичность актива 100), уровень правила 70, бонус серии +2,2 → 100/100.'),
  ...img(FIGS[2][0], FIGS[2][1], 3),
  ...img(FIGS[3][0], FIGS[3][1], 4),

  h2('2.4. Интеллектуальный анализ (Qwen2.5-3B)'),
  body('Анализ запущен оператором кнопкой в карточке; инференс на GPU занял ≈16 секунд. Модель вернула вердикт Pending (уверенность 80%) с типом атаки web_attack и рекомендацией monitor + collect_evidence: резюме честно фиксирует, что SQL-запросы не привели к успешному выполнению, но подозрительность требует дополнительного анализа. В блоке «Предложенные действия (проверка DVE)» оба действия разрешены политикой и ожидают запуска оператором.'),
  ...img(FIGS[4][0], FIGS[4][1], 5),
  ...img(FIGS[5][0], FIGS[5][1], 6),
  ...img(FIGS[6][0], FIGS[6][1], 7),
  ...img(FIGS[7][0], FIGS[7][1], 8),
  ...img(FIGS[8][0], FIGS[8][1], 9),

  h2('2.5. Реакция: блокирование IP атакующего'),
  body('Оператор-администратор запускает block_ip из перечня всех действий playbook (действие разрешено политикой DVE). Команда !block-ip.sh add 192.168.56.50 доставлена агенту 001 через Wazuh active response; в карточке появилась серверная отметка «✓ Выполнено» с указанием оператора и цели.'),
  ...img(FIGS[9][0], FIGS[9][1], 10),
  ...img(FIGS[10][0], FIGS[10][1], 11),

  h2('2.6. Физическая проверка эффекта'),
  body('С атакующего адреса 192.168.56.50 обращение к http://192.168.56.101/ завершается таймаутом (curl exit 28, соединение не устанавливается); на ВМ-1 в цепочке INPUT присутствует правило «DROP all — 192.168.56.50», в active-responses.log — запись block-ip.sh о блокировке в момент клика (11:47:35 EST, ≈1 с от нажатия кнопки). Канал агент↔менеджер (192.168.56.1:1514) сохранён.'),
  ...img(FIGS[11][0], FIGS[11][1], 12),

  h2('2.7. Откат реакции и закрытие инцидента'),
  body('«Сбросить реакции» выполняет обратную команду block-ip delete: правило iptables снято, обращение с атакующего адреса снова возвращает HTTP 200 (за 4 мс). Инцидент №5 переведён в статус «Закрыт».'),
  ...img(FIGS[12][0], FIGS[12][1], 13),
  ...img(FIGS[13][0], FIGS[13][1], 14),

  h1('3. Таблица замеров'),
  new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({ tableHeader: true, cantSplit: true, children: [cell('Параметр', { header: true, w: 28 }), cell('Наблюдение в прогоне', { header: true, w: 48 }), cell('Примечание', { header: true, w: 24 })] }),
      ...MEAS.map(([a, b, c]) => new TableRow({ cantSplit: true, children: [cell(a, { bold: true, w: 28 }), cell(b, { w: 48 }), cell(c, { w: 24 })] })),
    ],
  }),

  h1('4. Замечания по прогону'),
  bullet('Правило корреляции repeated_scan (условие «src_ip не пуст») на живом стенде объединяет в инциденты любой шум с адресом источника (в том числе служебные SSH-подключения оператора); для чистоты эксперимента правило деактивировано в демо-БД.'),
  bullet('Связанность событий корреляцией проверяется по активу в окне ±5 минут: служебные события самой сессии оператора попадают в «События» инцидента, если создаются в окне формирования; перед атакой выдержан тихий период (≥6 минут).'),
  bullet('Запрос с литеральными кавычками из инструкции (id=1\' OR \'1\'=\'1) нормализуется как built-in правило 31101 (event_type «web»); для получения семантического web_attack запросы построены на UNION-конструкциях (родитель 31103).'),

  h1('5. Выводы'),
  body('Второй класс атак воспроизведён на реальных компонентах: HTTP-запросы логируются nginx, wazuh-агент доставляет алерты мгновенно, корреляция формирует инцидент за ≈6 секунд, LLM даёт осторожный обоснованный вердикт, реакция block_ip исполняется на ВМ за ~1 секунду с проверяемым физическим эффектом, откат возвращает исходное состояние. Материалы (рисунки 1–14 и таблица замеров) предназначены для экспериментальной части ВКР.'),
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
