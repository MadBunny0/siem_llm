#!/bin/sh
# ---------------------------------------------------------------------------
# setup.sh — идемпотентная настройка Wazuh-менеджера стенда SIEM+LLM (stage-23).
#
# Запуск ВНУТРИ контейнера (маунты заданы в docker-compose.yml):
#   docker compose exec wazuh-manager bash /wazuh-config/setup.sh
#
# Повторять после каждого recreate контейнера менеджера (docker compose
# down/up): /var/ossec/etc/ossec.conf живёт в файловой системе образа,
# а не в томе wazuh_data — при пересоздании он возвращается к дефолтному.
# Правила (local_rules.xml) и декодеры (local_decoder.xml) приходят маунтами
# и подхватываются рестартом ниже.
#
# Что делает:
#   1. chmod +x интегратору (bind-mount с Windows может терять exec-бит);
#   2. дописывает блок <integration> (алерты → POST /api/v1/ingest/wazuh)
#      в ossec.conf, если его там нет;
#   3. убеждается, что active-response включён (<disabled>no</disabled>);
#   4. дописывает <command>-объявления block-ip / isolate-host /
#      lock-account (сами скрипты исполняются на АГЕНТАХ — их копируют
#      на ВМ отдельно, см. docs/E2E_STAND.md);
#   5. перезапускает менеджер, чтобы всё подхватилось.
# ---------------------------------------------------------------------------

set -u

OSSEC_CONF="/var/ossec/etc/ossec.conf"
INTEGRATION_FRAGMENT="/wazuh-config/ossec-integration.xml"
PYTHON="/var/ossec/framework/python/bin/python3"

# Вставка блока перед ПОСЛЕДНИМ закрывающим </ossec_config> (python — в
# slim-образе менеджера нет ни xmlstarlet, ни полноценного sed-окружения)
insert_block() {
    "$PYTHON" - "$OSSEC_CONF" "$1" <<'PYEOF'
import sys

conf_path, block = sys.argv[1], sys.argv[2]
with open(conf_path, encoding="utf-8") as f:
    conf = f.read()
marker = "</ossec_config>"
idx = conf.rfind(marker)
conf = conf[:idx] + block + "\n" + conf[idx:]
with open(conf_path, "w", encoding="utf-8") as f:
    f.write(conf)
PYEOF
}

echo "[setup] 1/5 exec-бит интегратора"
if chmod +x /var/ossec/integrator_files/custom-integration 2>/dev/null; then
    echo "        ок"
else
    echo "        ВНИМАНИЕ: chmod не удался — проверь исполнимость интегратора"
fi

echo "[setup] 2/5 блок <integration> в ossec.conf"
if grep -q "custom-integration" "$OSSEC_CONF"; then
    echo "        уже настроен"
else
    FRAG="$(cat "$INTEGRATION_FRAGMENT")"
    insert_block "$FRAG"
    echo "        блок добавлен"
fi

echo "[setup] 3/5 active-response включён"
if grep -q "<active-response>" "$OSSEC_CONF"; then
    sed -i 's|<disabled>yes</disabled>|<disabled>no</disabled>|' "$OSSEC_CONF"
    echo "        ок (disabled=yes заменён на no при наличии)"
else
    insert_block '<active-response>
  <disabled>no</disabled>
</active-response>'
    echo "        блок <active-response> добавлен"
fi

echo "[setup] 4/5 объявления AR-команд"
add_command() {
    name="$1"
    executable="$2"
    if grep -q "<name>$name</name>" "$OSSEC_CONF"; then
        echo "        $name: уже объявлена"
    else
        insert_block "<command>
  <name>$name</name>
  <executable>$executable</executable>
  <timeout_allowed>no</timeout_allowed>
</command>"
        echo "        $name: добавлена"
    fi
}
add_command block-ip block-ip.sh
add_command isolate-host isolate-host.sh
add_command lock-account lock-account.sh

echo "[setup] 5/5 перезапуск менеджера (10-40 с)"
if command -v wazuh-control >/dev/null 2>&1; then
    wazuh-control restart
else
    /var/ossec/bin/wazuh-control restart
fi
RC=$?
if [ "$RC" -eq 0 ]; then
    echo "[setup] готово. Проверка: docker compose exec wazuh-manager /var/ossec/bin/agent_control -l"
else
    echo "[setup] ВНИМАНИЕ: restart вернул код $RC — смотри /var/ossec/logs/ossec.log"
fi
exit $RC
