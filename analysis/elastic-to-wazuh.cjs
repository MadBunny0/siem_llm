// Конвертер алертов Elastic Security (выгрузка заказчика, формат kibana.alert._source)
// в формат Wazuh-алертов нашего ингеста (POST /api/v1/ingest/wazuh).
//
// Запуск (node:22-alpine, анализ/analysis смонтирован в /data):
//   docker run --rm -v "C:/Users/bruta/AppData/Local/Temp/feedback-data:/in:ro" \
//     -v "E:/VScodeProjects/siem_llm/analysis:/out" node:22-alpine node /out/elastic-to-wazuh.cjs /in /out/elastic-converted
// На выходе: <severity>/<rule>/<host>.wazuh.json — по одному алерту на файл.
//
// Маппинг (формат заказчика → наш):
//   _source["@timestamp"]                        → timestamp
//   _source["kibana.alert.severity"]             → rule.level (critical=10, high=8, medium=6, low=3)
//   _source["kibana.alert.rule.name"]            → rule.description
//   _source["kibana.alert.rule.threat"][0]       → rule.groups[1..] = tactic/technique (snake_case)
//   _source["host.name"]                         → agent.name (привязка актива по имени агента)
//   _source["kibana.alert.reason"] + process     → full_log (доказательная строка)
//   _source["user.id"], process.command_line     → data
// ВНИМАНИЕ: для корреляции в SIEM нужны активные правила корреляции под
// event_type из groups[0] (см. отчет по правкам заказчика, п.8).

const fs = require('fs');
const path = require('path');

const IN = process.argv[2];
const OUT = process.argv[3];
if (!IN || !OUT) {
  console.error('usage: node elastic-to-wazuh.cjs <inputDir> <outputDir>');
  process.exit(1);
}

const SEVERITY_LEVEL = { critical: 10, high: 8, medium: 6, low: 3 };

// Устойчивый парсер: часть выгрузок — склейка нескольких документов или
// значения-массивы с BOM/CRLF; берём первый сбалансированный {...} с учётом
// строк и вложенности.
function parseFirstJson(raw) {
  let text = raw.replace(/^\uFEFF/, '').trim();
  try {
    return JSON.parse(text);
  } catch (e) { /* переходим к сканированию */ }
  let start = -1;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === '\\') esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; continue; }
    if (c === '{') {
      if (depth === 0) start = i;
      depth++;
    } else if (c === '}') {
      depth--;
      if (depth === 0 && start >= 0) {
        const candidate = text.slice(start, i + 1);
        try {
          return JSON.parse(candidate);
        } catch (e) { start = -1; } // битый объект — ищем следующий
      }
    }
  }
  throw new Error('no parsable JSON object');
}

function snake(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

function* walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(p);
    else if (entry.name.endsWith('.txt')) yield p;
  }
}

let converted = 0;
let skipped = 0;
for (const file of walk(IN)) {
  let doc;
  try {
    doc = parseFirstJson(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    console.error('SKIP (not JSON):', file);
    skipped++;
    continue;
  }
  const s = doc._source || {};
  const severity = String(s['kibana.alert.severity'] || 'low').toLowerCase();
  const ruleName = s['kibana.alert.rule.name'] || 'Elastic alert';
  const host = (s['host'] && (s['host'].name || s['host'].hostname)) || 'unknown-host';
  const threat = (s['kibana.alert.rule.threat'] || [])[0] || {};
  const tactic = snake(threat.tactic && threat.tactic.name);
  const technique = snake(threat.technique && threat.technique.name);
  const process = s['process'] || {};
  const reason = s['kibana.alert.reason'] || '';
  const commandLine = process.command_line || '';

  const groups = ['elastic'];
  if (tactic) groups.push(tactic);

  const wazuh = {
    timestamp: s['@timestamp'] || s['kibana.alert.start'] || new Date().toISOString(),
    rule: {
      // синтетический id: детерминированный по имени правила (в наших правилах
      // 100xxx заняты стендом, Elastic-идентификаторы — uuid)
      id: 200000 + (Math.abs([...ruleName].reduce((a, c) => (a * 31 + c.charCodeAt(0)) | 0, 7)) % 100000),
      level: SEVERITY_LEVEL[severity] || 3,
      description: ruleName,
      groups,
      confidence: Math.max(0.05, Math.min(0.95, (s['kibana.alert.risk_score'] || 50) / 100)),
      mitre_tactic: tactic || undefined,
      mitre_technique: technique || undefined,
    },
    agent: { id: 'E1', name: host },
    data: {
      srcip: (s.source && (s.source.ip || s.source.address)) || undefined,
      user: (s.user && s.user.id) || undefined,
      process: process.name || undefined,
      command_line: commandLine || undefined,
      elastic_rule_uuid: s['kibana.alert.rule.uuid'],
      elastic_severity: severity,
      elastic_risk_score: s['kibana.alert.risk_score'],
    },
    full_log: [reason, commandLine].filter(Boolean).join(' | ').slice(0, 1000),
  };

  const rel = path.relative(IN, file).replace(/\.txt$/i, '.wazuh.json');
  const out = path.join(OUT, rel);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(wazuh, null, 1));
  converted++;
}
console.log(`OK: converted ${converted}, skipped ${skipped}, out -> ${OUT}`);
