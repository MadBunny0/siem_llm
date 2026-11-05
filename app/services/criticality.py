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

# Русские названия категорий повышения (stage-22 — для карточки инцидента,
# docs/CRITICALITY_MATRIX.md); ключи — коды категорий из derive_severity_detail
ESCALATION_CATEGORY_INFO = {
    "critical_asset": "Критичный бизнес-актив",
    "personal_data": "Персональные данные",
    "perimeter": "Периметр сети",
    "admin_zones": "Административные зоны",
    "ll_redteam": "Красная команда (pentest/red team)",
    "stop_crane": "Аварийные функции (stop crane)",
    "vendor_flag": "Критичное событие поставщика логов",
}


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


def _escalation_markers_hit(rule, events) -> dict[str, str]:
    """Категории повышения по маркерам ESCALATION_GROUP_MARKERS → сработавший маркер.

    Haystack — текстовые поля в lowercase: группы (raw_data.rule.groups) и
    event_type всех событий, имя и описание правила корреляции.
    Возвращает {код категории, совпавший маркер} — маркер нужен для
    объяснения фактора в карточке инцидента (stage-22).
    """
    parts: list[str] = []
    for event in events:
        parts.append(str(getattr(event, "event_type", "") or ""))
        rule_data = (getattr(event, "raw_data", None) or {}).get("rule") or {}
        parts.extend(str(g) for g in (rule_data.get("groups") or []) if g)
    parts.append(str(getattr(rule, "name", "") or ""))
    parts.append(str(getattr(rule, "description", "") or ""))
    haystack = " ".join(parts).lower()

    hits: dict[str, str] = {}
    for category, markers in ESCALATION_GROUP_MARKERS.items():
        for marker in markers:
            if marker in haystack:
                hits[category] = marker
                break
    return hits


def _perimeter_external_ip(events) -> str | None:
    """Первый непустой внешний src_ip событий (для объяснения фактора) или None."""
    for event in events:
        src_ip = getattr(event, "src_ip", None)
        if src_ip and _is_external_ip(src_ip):
            return str(src_ip)
    return None


def _perimeter_hit(events, asset) -> bool:
    """Условие периметра (процедура PDF, v3.1): актив из сегмента периметра
    (PERIMETER_SEGMENTS, lowercase network_segment) при наличии у событий
    непустого внешнего src_ip (не входит в INTERNAL_NETWORKS)."""
    if asset is None:
        return False
    segment = str(getattr(asset, "network_segment", "") or "").strip().lower()
    if segment not in PERIMETER_SEGMENTS:
        return False
    return _perimeter_external_ip(events) is not None


def derive_severity_detail(rule, events, asset) -> tuple[str | None, list[str], list[dict]]:
    """Критичность по матрице MITRE с разбором факторов (stage-22).

    Тот же расчёт, что derive_severity (см. ниже), дополнительно возвращает
    detail — список объяснений сработавших условий повышения для карточки
    инцидента (Incident.severity_factors):

    [{"category": "critical_asset",
      "title": "Критичный бизнес-актив",
      "explanation": "Актив «web-db-01» имеет критичность critical"}, ...]
    """
    tactic = getattr(rule, "mitre_tactic", None)
    base = MITRE_TACTIC_SEVERITY.get(tactic) if tactic else None
    if base is None:
        return None, [], []

    hits = _escalation_markers_hit(rule, events)
    detail: list[dict] = []

    # (a) критичные бизнес-активы
    if asset is not None and getattr(asset, "criticality", None) == "critical":
        detail.append({
            "category": "critical_asset",
            "title": ESCALATION_CATEGORY_INFO["critical_asset"],
            "explanation": (
                f"Актив «{getattr(asset, 'name', '?')}» имеет критичность "
                f"{getattr(asset, 'criticality', '?')}"
            ),
        })

    # (b) маркеры категорий повышения в текстовых полях
    for category in sorted(hits):
        detail.append({
            "category": category,
            "title": ESCALATION_CATEGORY_INFO.get(category, category),
            "explanation": (
                f"Маркер «{hits[category]}» найден в группах/типе событий "
                f"или имени/описании правила «{getattr(rule, 'name', '?')}»"
            ),
        })

    # (c) условие периметра: сегмент DMZ/edge/internet + внешний источник
    if asset is not None and _perimeter_hit(events, asset):
        segment = str(getattr(asset, "network_segment", "") or "").strip().lower()
        detail.append({
            "category": "perimeter",
            "title": ESCALATION_CATEGORY_INFO["perimeter"],
            "explanation": (
                f"Актив «{getattr(asset, 'name', '?')}» в периметровом сегменте "
                f"«{segment}», внешний источник {_perimeter_external_ip(events)}"
            ),
        })

    # (d) ручной флаг поставщика логов (п.7 процедуры)
    if getattr(rule, "escalated_by_vendor", False):
        detail.append({
            "category": "vendor_flag",
            "title": ESCALATION_CATEGORY_INFO["vendor_flag"],
            "explanation": (
                "Правило отмечено флагом escalated_by_vendor — критичное "
                "событие поставщика логов (п.7 процедуры)"
            ),
        })

    reasons = sorted({item["category"] for item in detail})
    severity = escalate(base) if reasons else base
    return severity, reasons, detail


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

    Разбор факторов с объяснениями — derive_severity_detail (stage-22).
    """
    severity, reasons, _ = derive_severity_detail(rule, events, asset)
    return severity, reasons
