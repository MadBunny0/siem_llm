#!/bin/sh
# ---------------------------------------------------------------------------
# block-ip.sh — кастомная AR-реакция стенда SIEM+LLM (stage-23): блокировка
# IP нарушителя на ВМ актива средствами iptables (docs/E2E_SCENARIOS.md, С1/С2).
#
# Запускается execd wazuh-АГЕНТА на ВМ (не на менеджере!) — скрипт обязан
# лежать в /var/ossec/active-response/bin/ на каждой ВМ (менеджер скрипты
# агентам не рассылает). Менеджер вызывает его командой '!block-ip.sh':
# префикс '!' заставляет execd агента исполнять скрипт напрямую из
# active-response/bin без регистрации в ar.conf (src/os_execd/exec.c).
#
# Параметры (Wazuh 4.2+, src/os_execd/execd.c): argv пуст — execd передаёт
# ВСЕ параметры JSON'ом ЧЕРЕЗ STDIN:
#   {"parameters": {"alert": {...}, "arguments": ["add", "192.168.56.50"], ...}}
#   arguments[0] — действие (add / delete), arguments[1] — цель (IP).
# Факт запуска пишет сам framework в /var/ossec/logs/active-responses.log,
# скрипт добавляет строку о результате.
# ---------------------------------------------------------------------------

LOG="/var/ossec/logs/active-responses.log"

# --- разбор JSON из stdin (execd передаёт параметры именно туда) -----------
IFS= read -r INPUT
ARGS=$(printf '%s\n' "$INPUT" | grep -Eo '"(extra_args|arguments)": *\[[^]]*\]' | head -1 | sed 's/^"[^"]*": *\[//; s/\]$//')
ACTION=$(printf '%s\n' "$ARGS" | cut -d '"' -f2)
TARGET=$(printf '%s\n' "$ARGS" | cut -d '"' -f4)

log() {
  echo "$(date '+%a %b %d %H:%M:%S %Z %Y') block-ip.sh: $1" >> "$LOG" 2>/dev/null || true
}

# цель должна быть похожа на IP (IPv4 с точками или IPv6 с двоеточиями)
case "$TARGET" in
  *.*) ;;
  *:*) ;;
  *)
    log "не распознаны аргументы (нужны add|delete и IP): arguments=$ARGS"
    exit 1
    ;;
esac

case "$ACTION" in
  add)
    iptables -I INPUT -s "$TARGET" -j DROP 2>/dev/null
    iptables -I OUTPUT -d "$TARGET" -j DROP 2>/dev/null
    log "IP $TARGET заблокирован (INPUT/OUTPUT DROP)"
    ;;
  delete)
    iptables -D INPUT -s "$TARGET" -j DROP 2>/dev/null
    iptables -D OUTPUT -d "$TARGET" -j DROP 2>/dev/null
    log "блокировка IP $TARGET снята"
    ;;
  *)
    log "неизвестное действие '$ACTION'"
    ;;
esac
