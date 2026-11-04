"""Определение критичности инцидентов по матрице MITRE (stage-17).

Источник — «[DRAFT] Процедура определения критичности рулов в SOC», v3.1
(N. Mironov, 22.04.2026), таблица соответствия тактик MITRE ATT&CK
и категорий повышения критичности (см. docs/CRITICALITY_MATRIX.md).

Логика (derive_severity):
1. Базовая критичность — по тактике правила (MITRE_TACTIC_SEVERITY); если у
   правила тактика не задана или неизвестна, возвращается None — вызывающий
   использует числовую модель риска (§3.3.3 ВКР) как fallback.
2. Повышение — по процедуре PDF: ЕСЛИ правило удовлетворяет хотя бы одному
   условию (критичный актив, маркеры категорий в группах/имени/описании,
   периметровый актив с внешним источником, ручной флаг поставщика), критичность
   повышается НА ОДИН уровень (суммарно максимум +1, не за каждую категорию).
"""

import ipaddress

# ---------------------------------------------------------------------------
# Матрица «тактика MITRE → базовая критичность» — источник: «[DRAFT] Процедура
# определения критичности рулов в SOC», v3.1 (N. Mironov, 22.04.2026), таблица
# соответствия тактик (см. docs/CRITICALITY_MATRIX.md)
# ---------------------------------------------------------------------------
MITRE_TACTIC_SEVERITY = {
    "reconnaissance": "low",
    "resource_development": "low",
    "initial_access": "medium",
    "discovery": "medium",
    "privilege_escalation": "high",
    "credential_access": "high",
    "execution": "high",
    "persistence": "high",
    "defense_evasion": "high",
    "lateral_movement": "high",
    "collection": "high",
    "command_and_control": "critical",
    "exfiltration": "critical",
    "impact": "critical",
}

# ---------------------------------------------------------------------------
# Маркеры категорий повышения критичности (процедура PDF, v3.1): поиск —
# lowercase substring в группах события (raw_data.rule.groups), event_type,
# имени и описании правила корреляции.
#
# ВНИМАНИЕ: голые слова "admin", "ll", "web" сознательно НЕ включены —
# дают ложные срабатывания (см. docs/CRITICALITY_MATRIX.md).
# ---------------------------------------------------------------------------
ESCALATION_GROUP_MARKERS = {
    "personal_data": ["pii", "personal_data", "personal", "confidential", "gdpr"],
    "perimeter": ["vpn", "perimeter", "internet_facing", "external_attack"],
    "admin_zones": ["admin_panel", "admin_console", "management", "cloud_control", "hypervisor", "vcenter", "control_plane"],
    "ll_redteam": ["pentest", "red_team", "redteam", "purple_team"],
    "stop_crane": ["debug", "emergency", "kill_switch", "bypass", "manual_override"],
}

# Сетевые сегменты периметра: актив из такого сегмента с внешним источником
# (см. условие периметра ниже) повышает критичность (категория "perimeter")
PERIMETER_SEGMENTS = {"dmz", "edge", "internet"}

# Внутренние сети — ручной список (процедура PDF, v3.1). Не используем
# ipaddress.is_private/is_global: их поведение различается между версиями
# Python (TEST-NET), собственный список детерминирован.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(net) for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
]

# Лестница уровней критичности для повышения (escalate)
_SEVERITY_LADDER = ["low", "medium", "high", "critical"]


def escalate(severity: str, steps: int = 1) -> str:
    """Повышение критичности по лестнице low→medium→high→critical.

    Выше critical не поднимается; неизвестный уровень возвращается как есть.
    """
    if severity not in _SEVERITY_LADDER:
        return severity
    index = _SEVERITY_LADDER.index(severity) + max(0, steps)
    return _SEVERITY_LADDER[min(len(_SEVERITY_LADDER) - 1, index)]


def _is_external_ip(src_ip: str) -> bool:
    """Внешний ли IP-адрес источника: не входит ни в одну внутреннюю сеть.

    Некорректный src_ip (не парсится) внешним не считается.
    """
    try:
        address = ipaddress.ip_address(str(src_ip).strip())
    except ValueError:
        return False
    # сравнение версий: IPv6-адрес не может принадлежать IPv4-сети
    return not any(
        address.version == network.version and address in network
        for network in INTERNAL_NETWORKS
    )


def _escalation_markers_hit(rule, events) -> set[str]:
    """Категории повышения по маркерам ESCALATION_GROUP_MARKERS.

    Haystack — текстовые поля в lowercase: группы (raw_data.rule.groups) и
    event_type всех событий, имя и описание правила корреляции.
    """
    parts: list[str] = []
    for event in events:
        parts.append(str(getattr(event, "event_type", "") or ""))
        rule_data = (getattr(event, "raw_data", None) or {}).get("rule") or {}
        parts.extend(str(g) for g in (rule_data.get("groups") or []) if g)
    parts.append(str(getattr(rule, "name", "") or ""))
    parts.append(str(getattr(rule, "description", "") or ""))
    haystack = " ".join(parts).lower()

    return {
        category
        for category, markers in ESCALATION_GROUP_MARKERS.items()
        if any(marker in haystack for marker in markers)
    }


def _perimeter_hit(events, asset) -> bool:
    """Условие периметра (процедура PDF, v3.1): актив из сегмента периметра
    (PERIMETER_SEGMENTS, lowercase network_segment) при наличии у событий
    непустого внешнего src_ip (не входит в INTERNAL_NETWORKS)."""
    if asset is None:
        return False
    segment = str(getattr(asset, "network_segment", "") or "").strip().lower()
    if segment not in PERIMETER_SEGMENTS:
        return False
    return any(
        getattr(event, "src_ip", None) and _is_external_ip(event.src_ip)
        for event in events
    )


def derive_severity(rule, events, asset) -> tuple[str | None, list[str]]:
    """Критичность инцидента по матрице MITRE (stage-17, процедура PDF v3.1).

    Аргументы:
    rule — сработавшее правило корреляции (mitre_tactic, name, description,
        escalated_by_vendor);
    events — связанные события инцидента (event_type, raw_data.rule.groups,
        src_ip);
    asset — защищаемый актив инцидента (criticality, network_segment) или None.

    Возвращает (критичность, причины повышения) либо (None, []), если базовая
    критичность по тактике не определена (тактика не задана или неизвестна) —
    вызывающий использует числовую модель риска (fallback).

    Повышение: при выполнении ХОТЯ БЫ ОДНОГО условия критичность повышается
    НА ОДИН уровень (суммарно максимум +1, не за каждую категорию); reasons —
    коды сработавших категорий (их может быть несколько при одном повышении):
    - critical_asset — критичные бизнес-активы (asset.criticality == "critical");
    - категории по маркерам ESCALATION_GROUP_MARKERS в текстовых полях;
    - perimeter — актив сегмента периметра + внешний источник;
    - vendor_flag — отдельно отмеченные критичные события поставщика логов
      (п.7 процедуры — ручной флаг escalated_by_vendor).
    """
    tactic = getattr(rule, "mitre_tactic", None)
    base = MITRE_TACTIC_SEVERITY.get(tactic) if tactic else None
    if base is None:
        return None, []

    reasons: set[str] = set()

    # (a) критичные бизнес-активы
    if asset is not None and getattr(asset, "criticality", None) == "critical":
        reasons.add("critical_asset")

    # (b) маркеры категорий повышения в текстовых полях
    reasons.update(_escalation_markers_hit(rule, events))

    # (c) условие периметра: сегмент DMZ/edge/internet + внешний источник
    if _perimeter_hit(events, asset):
        reasons.add("perimeter")

    # (d) ручной флаг поставщика логов (п.7 процедуры)
    if getattr(rule, "escalated_by_vendor", False):
        reasons.add("vendor_flag")

    severity = escalate(base) if reasons else base
    return severity, sorted(reasons)
