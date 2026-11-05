#!/bin/sh
# ---------------------------------------------------------------------------
# block-ip.sh — кастомная AR-реакция стенда SIEM+LLM (stage-23): блокировка
# IP нарушителя на ВМ актива средствами iptables (docs/E2E_SCENARIOS.md, С1/С2).
#
# Запускается execd wazuh-АГЕНТА на ВМ (не на менеджере!) — скрипт обязан
# лежать в /var/ossec/active-response/bin/ на каждой ВМ (менеджер скрипты
# агентам не рассылает). Определение команды block-ip — в ossec.conf
# менеджера (добавляет wazuh/setup.sh).
#
# Аргументы от менеджера приходят как позиционные параметры, порядок может
# искажаться (перед аргументами API менеджер подставляет placeholder'ы
# стандартного AR-протокола) — поэтому сканируются ВСЕ аргументы:
#   add / delete — заблокировать / снять блокировку;
#   цель — первый аргумент, похожий на IP-адрес (IPv4 с точками, IPv6
#   с двоеточиями).
# Факт запуска пишет сам framework в /var/ossec/logs/active-responses.log,
# скрипт добавляет строку о результате.
# ---------------------------------------------------------------------------

LOG="/var/ossec/logs/active-responses.log"
ACTION=""
TARGET=""

for arg in "$@"; do
  case "$arg" in
    add|delete)
      [ -z "$ACTION" ] && ACTION="$arg"
      ;;
    "-"|"")
      ;;
    *)
      case "$arg" in
        # не IPv4 (есть символы кроме цифр и точек)
        *[!0-9.]*)
          # IPv6: содержит ':' и только hex-символы/двоеточия
          case "$arg" in
            *:*) case "$arg" in
                   *[!0-9a-fA-F:]*) ;;
                   *) [ -z "$TARGET" ] && TARGET="$arg" ;;
                 esac ;;
          esac
          ;;
        # IPv4: есть точка
        *.*) [ -z "$TARGET" ] && TARGET="$arg" ;;
      esac
      ;;
  esac
done

log() {
  echo "$(date '+%a %b %d %H:%M:%S %Z %Y') block-ip.sh: $1" >> "$LOG" 2>/dev/null || true
}

if [ -z "$ACTION" ] || [ -z "$TARGET" ]; then
  log "не распознаны аргументы (нужны add|delete и IP): $*"
  exit 1
fi

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
esac
