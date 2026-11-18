// Генератор docx-отчёта живого прогона Сценария 1 (E2E) — ВКР материалы.
// Запуск: node:22-alpine контейнер (npm i docx image-size), изображения analysis/run1/*.png.
const fs = require('fs');
const path = require('path');
function pngSize(p) { const b = fs.readFileSync(p); return { width: b.readUInt32BE(16), height: b.readUInt32BE(20) }; }
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, ImageRun,
  Table, TableRow, TableCell, WidthType, AlignmentType, BorderStyle,
  ShadingType, Footer, PageNumber, NumberFormat, VerticalAlign,
} = require('docx');

const IMG_DIR = '/data/run1';
const OUT = '/data/Отчёт_прогон_Сценария1.docx';
const MAXW = 620; // px @96dpi, ширина полосы A4 с полями 2 см

const FONT = 'Times New Roman';
const body = (text, opts = {}) => new Paragraph({
  spacing: { line: 312, after: 120 },
  alignment: AlignmentType.JUSTIFIED,
  firstLineIndent: 709, // 1.25 см
  children: [new TextRun({ text, font: FONT, size: 24, ...opts })],
});
const h1 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 160 }, children: [new TextRun({ text, font: FONT, size: 32, bold: true, color: '000000' })] });
const h2 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 120 }, children: [new TextRun({ text, font: FONT, size: 28, bold: true, color: '000000' })] });
const h3 = (text) => new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 100 }, children: [new TextRun({ text, font: FONT, size: 24, bold: true, color: '000000' })] });
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

// ---- содержание рисунков ----------------------------------------------------
const FIGS = [
  ['44838732436babfc5762d7b26da41707.png', 'Атака: неудачные попытки SSH-входа под учётной записью admin с адреса атакующего (192.168.56.50)'],
  ['c37144fbdb3c762cb8e2c4d3b12cf517.png', 'Лента SIEM: инцидент №1 (critical, NEW) создан корреляционным правилом brute_force_attempts'],
  ['746ea747ca4a4ee8b9fdba63cb21f4d7.png', 'Карточка инцидента: хронология 18 связанных событий (authentication_failed, pam, syslog)'],
  ['b11b94555b7c3e2910cffb4be83ec47a.png', 'Карточка инцидента: статус NEW, уровень риска 100/100, блок «Оценка критичности»'],
  ['70cd8a21ad71e6cf4965a1a5aa1cd1b7.png', '«Оценка критичности» крупным планом: матрица MITRE (Credential Access → Высокий), повышение «Критичный бизнес-актив», числовая модель 100/100'],
  ['c772bf629a9d170b0134fab149352407.png', 'Конвейер обработки: этапы WAZUH, NORMALIZE, CORRELATE, RISK пройдены, этап QWEN (анализ LLM) запущен'],
  ['a38bc5c9fb842da3ff8cc79fe027a1a1.png', 'Шапка инцидента после анализа: статус IN_PROGRESS, назначен soc_lead'],
  ['42cc89ae6f4a4e722401bc5bb65963ab.png', 'Результат анализа: вердикт Pending, рекомендованное действие monitor, разбор команд и событий'],
  ['5010c36a4a68a7d1bab45fbed610b129.png', 'Рекомендации для дальнейших действий, проверка DVE (monitor разрешён политикой) и перечень всех действий playbook'],
  ['0eecf103036bfe2747a935bea8130583.png', 'Исполнение block_ip: отметка «Выполнено», оператор soc_lead, цель 192.168.56.50'],
  ['421865a4bbeced50285afd8ceb194b1d.png', 'Вкладка «Реакции (ВМ)»: активная блокировка на активе mail-prod-01 (инцидент №1)'],
  ['9e9cdd0382a349391613007b5126bf5a.png', 'Проверка с атакующего узла: ping 192.168.56.101 с адреса 192.168.56.50 — 100% потерь'],
  ['5617d9a3a0d38fc8d4c5f109506b2fe2.png', 'Проверка с атакующего узла: SSH-подключение — «Connection timed out» (соединение не устанавливается)'],
  ['70ed9c2e5334422388263a2b02577837.png', 'Консоль ВМ-1: цепочка INPUT содержит правило «1 DROP all — 192.168.56.50»'],
  ['b5b15b563853dee55280bced6402cd69.png', 'После «Сбросить реакции»: отметка исполненного действия снята, все кнопки playbook доступны снова'],
  ['3e9f8392692408206ffa1b34ca749764.png', 'После отката: ping с атакующего адреса — 0% потерь, доступ восстановлен'],
  ['43036fa040c279425f9d6df5fdb5c4b3.png', 'Инцидент переведён в статус «Закрыт»'],
];

// ---- замеры -----------------------------------------------------------------
const MEAS = [
  ['Правило Wazuh (id, уровень)', '100100 (level 7); параллельно срабатывает built-in unix_chkpwd', 'Кастомное правило стенда: Failed password'],
  ['Событие (event_type)', 'authentication_failed (user=admin, src_ip=192.168.56.50)', 'Нормализация: groups[0] — семантическое имя'],
  ['Корреляция (порог/окно)', 'brute_force_attempts: 3 события за 5 мин (T1110)', 'В прогоне: 9 auth_failed за ~5 мин'],
  ['Критичность (severity_factors)', 'База credential_access = high; повышение «критичный бизнес-актив» → critical; риск 100/100', 'Матрица MITRE + модель риска §3.3.3'],
  ['Время детекции', 'инцидент создан при наборе порога корреляции (в пределах окна 5 мин)', 'События поступают с агентом в реальном времени'],
  ['Результат LLM (Qwen2.5-3B, GPU)', 'Вердикт Pending, рекомендация monitor; разбор всех команд', 'Честный вердикт при отсутствии доказательств успеха атаки'],
  ['Решение DVE', 'block_ip разрешён политикой critical; критический актив — подтверждение администратора (soc_lead)', '§3.4 ВКР, p.102'],
  ['Время реакции', 'Клик «▶ Блокировать IP» 01:25:40 → правило iptables на ВМ 01:25:42 (≈2 с)', 'Wazuh AR: PUT /active-response → агент'],
  ['Физический эффект', 'iptables INPUT/OUTPUT DROP для 192.168.56.50; ping — 100% потерь; SSH — connection timed out', 'Проверено с атакующего узла и на ВМ'],
  ['Откат («Сбросить реакции»)', 'Обратная команда block-ip delete; ping — 0% потерь', 'best-effort через Wazuh API'],
];

// ---- сборка -----------------------------------------------------------------
const children = [
  new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 60 },
    children: [new TextRun({ text: 'SIEM + LLM: интеллектуальная обработка инцидентов', font: FONT, size: 28, bold: true })],
  }),
  new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 240 },
    children: [new TextRun({ text: 'Живой прогон Сценария 1 (E2E) «Подбор пароля по SSH» — протокол эксперимента и материалы', font: FONT, size: 26, bold: true })],
  }),
  body('Дата прогона: 18.11.2026. Оператор: soc_lead (администратор). Цель — сквозная проверка учебного стенда: атака с узла нарушителя на критичный сервер, детекция средствами Wazuh и конвейера SIEM, интеллектуальный анализ локальной моделью Qwen2.5-3B, исполнение реакции playbook (Wazuh active response) и физическая проверка её эффекта на виртуальной машине.'),

  h1('1. Топология и предусловия'),
  bullet('Windows-хост: SIEM-стенд в Docker (PostgreSQL, Ollama с Qwen2.5-3B на GPU RTX 4060 Ti, FastAPI, веб-интерфейс :3000, Wazuh-manager :1514/:1515/:55000); хост выполняет роль атакующего узла с дополнительным адресом 192.168.56.50 (аналог ВМ-2 «АРМ пользователя»).'),
  bullet('ВМ-1 mail-prod-01 — 192.168.56.101 (VirtualBox, консольная Kali Linux): критичный сервер, sshd + nginx + rsyslog + wazuh-agent 4.7.4 (ID 001, Active), AR-скрипты block-ip/lock-account/isolate-host, учётная запись-жертва admin.'),
  bullet('Привязка: имя wazuh-агента = имя актива SIEM (mail-prod-01); IP актива в БД — 192.168.56.101.'),
  bullet('Канал детекции: агент → менеджер (правило стенда 100100) → интегратор → POST /api/v1/ingest/wazuh. Канал реакции: API SIEM → Wazuh Manager API (PUT /active-response) → агент ВМ.'),
  bullet('Перед прогоном: БД очищена до заводского seed, снапшот ВМ «stand-ready» снят.'),

  h1('2. Ход прогона'),

  h2('2.1. Атака (имитация подбора пароля по SSH)'),
  body('С узла атакующего выполнено 5–9 неудачных попыток входа ssh admin@192.168.56.101 с заведомо неверным паролем. Каждая попытка фиксируется sshd в /var/log/auth.log ВМ-1 и мгновенно доставляется wazuh-агентом в менеджер (правило стенда 100100, level 7).'),
  ...img(FIGS[0][0], FIGS[0][1], 1),

  h2('2.2. Детекция и корреляция'),
  body('Нормализованные события поступают в SIEM, где набирается порог правила brute_force_attempts (3 события за 5 минут, T1110) — инцидент создаётся автоматически, критичность определяется матрицей MITRE с учётом критичности актива.'),
  ...img(FIGS[1][0], FIGS[1][1], 2),
  ...img(FIGS[2][0], FIGS[2][1], 3),

  h2('2.3. Оценка критичности инцидента'),
  body('Блок «Оценка критичности» в карточке показывает разбор: базовый уровень по тактике Credential Access — «Высокий»; повышение на один уровень за критичный бизнес-актив; числовая модель риска — 100/100 (база = критичность актива 100, уровень правила 70, опасность типа атаки 60, бонус серии +10,2).'),
  ...img(FIGS[3][0], FIGS[3][1], 4),
  ...img(FIGS[4][0], FIGS[4][1], 5),
  ...img(FIGS[5][0], FIGS[5][1], 6),

  h2('2.4. Интеллектуальный анализ (Qwen2.5-3B)'),
  body('Оператор запускает анализ кнопкой в карточке (выполняется в фоне, инференс локальной модели на GPU — около 1,5 минуты). Модель возвращает вердикт по критериям SOC-аналитика: при отсутствии в событиях доказательств успешной компрометации выставлен вердикт Pending с рекомендацией monitor — поведение соответствует заложенным критериям (осторожность при недостатке доказательств).'),
  ...img(FIGS[6][0], FIGS[6][1], 7),
  ...img(FIGS[7][0], FIGS[7][1], 8),
  ...img(FIGS[8][0], FIGS[8][1], 9),

  h2('2.5. Реакция: блокировка IP атакующего'),
  body('Оператор-администратор запускает block_ip из перечня действий playbook. Действие разрешено политикой DVE для уровня critical (администратор — подтверждение для критического актива не требуется). Команда доставляется через Wazuh active response: agent 001 исполняет block-ip.sh с целью 192.168.56.50 — на ВМ добавляются правила iptables INPUT/OUTPUT DROP.'),
  ...img(FIGS[9][0], FIGS[9][1], 10),
  ...img(FIGS[10][0], FIGS[10][1], 11),

  h2('2.6. Физическая проверка эффекта'),
  body('С атакующего адреса 192.168.56.50: ping — 100% потерь, SSH-подключение не устанавливается (connection timed out). На ВМ-1 в цепочке INPUT присутствует правило DROP. Канал доставки реакций (агент ↔ менеджер, 192.168.56.1:1514) сохранён — блокировка затрагивает только адрес нарушителя.'),
  ...img(FIGS[11][0], FIGS[11][1], 12),
  ...img(FIGS[12][0], FIGS[12][1], 13),
  ...img(FIGS[13][0], FIGS[13][1], 14),

  h2('2.7. Откат реакции и закрытие инцидента'),
  body('Кнопка «Сбросить реакции» выполняет обратную AR-команду (block-ip delete): правила iptables снимаются, доступ атакующего восстанавливается, записи реакций удаляются из сводки. Инцидент переводится в статус «Закрыт».'),
  ...img(FIGS[14][0], FIGS[14][1], 15),
  ...img(FIGS[15][0], FIGS[15][1], 16),
  ...img(FIGS[16][0], FIGS[16][1], 17),

  h1('3. Таблица замеров'),
  new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      new TableRow({ tableHeader: true, cantSplit: true, children: [cell('Параметр', { header: true, w: 28 }), cell('Наблюдение в прогоне', { header: true, w: 48 }), cell('Примечание', { header: true, w: 24 })] }),
      ...MEAS.map(([a, b, c]) => new TableRow({ cantSplit: true, children: [cell(a, { bold: true, w: 28 }), cell(b, { w: 48 }), cell(c, { w: 24 })] })),
    ],
  }),

  h1('4. Обнаруженные и устранённые дефекты доставки реакций'),
  body('Живой прогон вскрыл три корневых дефекта, не проявлявшихся при статической проверке. Все устранены в этом же прогоне, изменения внесены в репозиторий (PR #25).'),
  bullet('Протокол передачи параметров: Wazuh 4.2+ передаёт аргументы AR-скрипту в виде JSON через стандартный поток ввода (argv пуст); скрипты переписаны на чтение stdin с извлечением массива extra_args.'),
  bullet('Валидация имени команды агентом: execd отвергает команды, отсутствующие в его реестре (ERROR 1311); обход — вызов скрипта по имени с префиксом «!» (исполнение напрямую из active-response/bin), зафиксировано в WAZUH_AR_COMMANDS.'),
  bullet('Отсутствие iptables в минимальной установке Kali: пакет добавлен в provisioning ВМ.'),
  bullet('Дополнительно: подключён GPU для инференса (анализ ~1,5 мин против 5+ мин на CPU), увеличен лимит генерации модели (4096 токенов — вердикты по инцидентам с 12+ событиями не помещались в прежний лимит), исправлен контраст вкладки «Реакции (ВМ)».'),

  h1('5. Выводы'),
  body('Сквозной сценарий детекции и реагирования воспроизведён на реальных компонентах: события доставляются wazuh-агентом в реальном времени, корреляция формирует инцидент, локальная LLM даёт обоснованный вердикт, реакция playbook исполняется на ВМ за ~2 секунды и имеет проверяемый физический эффект, откат возвращает исходное состояние. Материалы прогона (рисунки 1–17 и таблица замеров) предназначены для включения в экспериментальную часть ВКР.'),
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
