#!/bin/sh
# ---------------------------------------------------------------------------
# lock-account.sh — кастомная AR-реакция стенда SIEM+LLM (stage-23): блокировка
# учётной записи нарушителя на ВМ актива через passwd -l/-u
# (docs/E2E_SCENARIOS.md, С3 «Инсайдер: бэкдор-аккаунт»).
#
# Запускается execd wazuh-АГЕНТА на ВМ — скрипт обязан лежать в
# /var/ossec/active-response/bin/ на каждой ВМ. Менеджер вызывает его
# командой '!lock-account.sh' (префикс '!' — исполнение напрямую из
# active-response/bin без регистрации в ar.conf).
#
# Параметры (Wazuh 4.2+): argv пуст — execd передаёт ВСЕ параметры JSON'ом
# ЧЕРЕЗ STDIN: {"parameters": {"arguments": ["lock", "username"], ...}}
#   arguments[0] — действие (lock / unlock), arguments[1] — учётная запись.
# ---------------------------------------------------------------------------

LOG="/var/ossec/logs/active-responses.log"

# --- разбор JSON из stdin (execd передаёт параметры именно туда) -----------
IFS= read -r INPUT
ARGS=$(printf '%s\n' "$INPUT" | grep -Eo '"(extra_args|arguments)": *\[[^]]*\]' | head -1 | sed 's/^"[^"]*": *\[//; s/\]$//')
ACTION=$(printf '%s\n' "$ARGS" | cut -d '"' -f2)
TARGET=$(printf '%s\n' "$ARGS" | cut -d '"' -f4)

log() {
  echo "$(date '+%a %b %d %H:%M:%S %Z %Y') lock-account.sh: $1" >> "$LOG" 2>/dev/null || true
}

if [ -z "$ACTION" ] || [ -z "$TARGET" ]; then
  log "не распознаны аргументы (нужны lock|unlock и имя учётной записи): arguments=$ARGS"
  exit 1
fi

case "$ACTION" in
  lock)
    if passwd -l "$TARGET" >/dev/null 2>&1; then
      log "учётная запись $TARGET заблокирована (passwd -l)"
    else
      log "passwd -l $TARGET завершился с ошибкой (проверь: passwd -S $TARGET)"
    fi
    ;;
  unlock)
    if passwd -u "$TARGET" >/dev/null 2>&1; then
      log "учётная запись $TARGET разблокирована (passwd -u)"
    else
      log "passwd -u $TARGET завершился с ошибкой (проверь: passwd -S $TARGET)"
    fi
    ;;
  *)
    log "неизвестное действие '$ACTION'"
    ;;
esac
