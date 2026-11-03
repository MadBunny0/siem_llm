#!/bin/sh
# ---------------------------------------------------------------------------
# Кастомная интеграция Wazuh → SIEM+LLM API (stage-10).
#
# Wazuh integratord вызывает скрипт так:
#   <script> <alert_file> <api_key> <hook_url> [<optional_args>...]
# Алерт передаётся JSON-файлом (alert_format=json в блоке <integration>).
#
# Скрипт отправляет алерт в наш эндпоинт POST /api/v1/ingest/wazuh
# (открытый для машинной интеграции — без JWT, см. app/services/auth.py).
# ---------------------------------------------------------------------------

WPYTHON_BIN="framework/python/bin/python3"

ALERT_FILE="$1"
# hook_url из аргументов integratord ($3); fallback — env контейнера HOOK_URL, затем дефолт
HOOK_URL="$3"
if [ -z "$HOOK_URL" ]; then
    HOOK_URL="${HOOK_URL:-http://api:8000/api/v1/ingest/wazuh}"
fi

if [ ! -f "$ALERT_FILE" ]; then
    echo "integrator: alert file not found: $ALERT_FILE" >&2
    exit 1
fi

# Используем встроенный python Wazuh-менеджера (curl в slim-образах может отсутствовать)
"$WPYTHON_BIN" - "$ALERT_FILE" "$HOOK_URL" <<'PYEOF'
import json
import sys
import urllib.request

alert_file, hook_url = sys.argv[1], sys.argv[2]

with open(alert_file, encoding="utf-8") as f:
    alert = json.load(f)

req = urllib.request.Request(
    hook_url,
    data=json.dumps(alert, ensure_ascii=False).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read().decode("utf-8", "replace")
        print(f"integrator: HTTP {resp.status} -> {body[:200]}")
except Exception as exc:  # не роняем integratord — только логируем
    print(f"integrator: POST {hook_url} failed: {exc}", file=sys.stderr)
    sys.exit(1)
PYEOF
