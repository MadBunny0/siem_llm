#!/bin/sh
# ---------------------------------------------------------------------------
# lock-account.sh — кастомная AR-реакция стенда SIEM+LLM (stage-23): блокировка
# учётной записи нарушителя на ВМ актива через passwd -l/-u
# (docs/E2E_SCENARIOS.md, С3 «Инсайдер: бэкдор-аккаунт»).
#
# Запускается execd wazuh-АГЕНТА на ВМ — скрипт обязан лежать в
# /var/ossec/active-response/bin/ на каждой ВМ. Определение команды
# lock-account — в ossec.conf менеджера (добавляет wazuh/setup.sh).
#
# Сканируются ВСЕ аргументы (порядок от менеджера не гарантирован):
#   lock / unlock — заблокировать / разблокировать;
#   цель — первый аргумент-слово (учётная запись), placeholder'ы "-",
#   пустые и пути "/" пропускаются.
# ---------------------------------------------------------------------------

LOG="/var/ossec/logs/active-responses.log"
ACTION=""
TARGET=""

for arg in "$@"; do
  case "$arg" in
    lock|unlock)
      [ -z "$ACTION" ] && ACTION="$arg"
      ;;
    "-"|"")
      ;;
    /*)
      ;;
    *)
      [ -z "$TARGET" ] && TARGET="$arg"
      ;;
  esac
done

log() {
  echo "$(date '+%a %b %d %H:%M:%S %Z %Y') lock-account.sh: $1" >> "$LOG" 2>/dev/null || true
}

if [ -z "$ACTION" ] || [ -z "$TARGET" ]; then
  log "не распознаны аргументы (нужны lock|unlock и имя учётной записи): $*"
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
esac
