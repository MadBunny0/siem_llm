#!/bin/sh
# ---------------------------------------------------------------------------
# isolate-host.sh — кастомная AR-реакция стенда SIEM+LLM (stage-23): изоляция
# ВМ актива от сети (docs/E2E_SCENARIOS.md, playbook isolate_host).
#
# Запускается execd wazuh-АГЕНТА на ВМ — скрипт обязан лежать в
# /var/ossec/active-response/bin/ на каждой ВМ. Определение команды
# isolate-host — в ossec.conf менеджера (добавляет wazuh/setup.sh).
#
# add — изолировать: отдельная цепочка iptables SIEM_ISOLATE рвёт весь
#   входящий/исходящий трафик КРОМЕ loopback, установленных соединений и
#   связи с Wazuh-менеджером (TCP 1514/1515 — чтобы агент продолжал
#   доставлять алерты и обратные команды отката).
# delete — снять изоляцию: цепочка удаляется целиком.
# ---------------------------------------------------------------------------

CHAIN="SIEM_ISOLATE"
LOG="/var/ossec/logs/active-responses.log"
ACTION=""

for arg in "$@"; do
  case "$arg" in
    add|delete)
      [ -z "$ACTION" ] && ACTION="$arg"
      ;;
  esac
done

log() {
  echo "$(date '+%a %b %d %H:%M:%S %Z %Y') isolate-host.sh: $1" >> "$LOG" 2>/dev/null || true
}

if [ -z "$ACTION" ]; then
  log "не распознаны аргументы (нужен add|delete): $*"
  exit 1
fi

case "$ACTION" in
  add)
    iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
    iptables -A "$CHAIN" -i lo -j ACCEPT
    iptables -A "$CHAIN" -o lo -j ACCEPT
    iptables -A "$CHAIN" -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A "$CHAIN" -p tcp --dport 1514 -j ACCEPT
    iptables -A "$CHAIN" -p tcp --dport 1515 -j ACCEPT
    iptables -A "$CHAIN" -j DROP
    iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN"
    iptables -C OUTPUT -j "$CHAIN" 2>/dev/null || iptables -I OUTPUT 1 -j "$CHAIN"
    log "узел изолирован (цепочка $CHAIN: всё, кроме lo/established/1514-1515)"
    ;;
  delete)
    iptables -D INPUT -j "$CHAIN" 2>/dev/null
    iptables -D OUTPUT -j "$CHAIN" 2>/dev/null
    iptables -F "$CHAIN" 2>/dev/null
    iptables -X "$CHAIN" 2>/dev/null
    log "изоляция снята (цепочка $CHAIN удалена)"
    ;;
esac
