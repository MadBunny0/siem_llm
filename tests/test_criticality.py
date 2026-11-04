"""Юнит-тесты матрицы критичности (app/services/criticality.py, stage-17).

Источник значений — «[DRAFT] Процедура определения критичности рулов в SOC»,
v3.1 (N. Mironov, 22.04.2026): базовая критичность по тактике MITRE + повышение
на один уровень при выполнении хотя бы одного условия (максимум +1 суммарно).
"""

from types import SimpleNamespace

from app.services.criticality import (
    ESCALATION_GROUP_MARKERS,
    MITRE_TACTIC_SEVERITY,
    derive_severity,
    escalate,
)


def make_rule(**overrides):
    """Фейковое правило корреляции (утинная типизация — как ORM CorrelationRule)."""
    params = dict(
        name="test_rule",
        description="тестовое правило",
        mitre_tactic=None,
        mitre_technique=None,
        escalated_by_vendor=False,
    )
    params.update(overrides)
    return SimpleNamespace(**params)


def make_event(groups=None, event_type="security_event", src_ip=None):
    """Фейковое событие (event_type, raw_data.rule.groups, src_ip)."""
    return SimpleNamespace(
        event_type=event_type,
        raw_data={"rule": {"groups": groups or []}},
        src_ip=src_ip,
    )


def make_asset(**overrides):
    """Фейковый актив (criticality, network_segment)."""
    params = dict(name="srv-01", criticality="medium", network_segment=None)
    params.update(overrides)
    return SimpleNamespace(**params)


# ---------------------------------------------------------------------------
# Матрица «тактика MITRE → базовая критичность» (таблица процедуры PDF v3.1)
# ---------------------------------------------------------------------------
def test_mitre_matrix_full():
    """Каждая из 14 тактик даёт уровень из процедуры PDF v3.1."""
    expected = {
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
    assert MITRE_TACTIC_SEVERITY == expected
    assert len(MITRE_TACTIC_SEVERITY) == 14
    # маркеры категорий повышения — ровно 5 категорий процедуры
    assert set(ESCALATION_GROUP_MARKERS) == {
        "personal_data", "perimeter", "admin_zones", "ll_redteam", "stop_crane",
    }


# ---------------------------------------------------------------------------
# escalate — лестница повышения
# ---------------------------------------------------------------------------
def test_escalate_ladder():
    """Лестница low→medium→high→critical."""
    assert escalate("low") == "medium"
    assert escalate("medium") == "high"
    assert escalate("high") == "critical"


def test_escalate_critical_is_ceiling():
    """Выше critical не поднимается."""
    assert escalate("critical") == "critical"
    assert escalate("critical", steps=3) == "critical"


def test_escalate_unknown_level_unchanged():
    """Неизвестный уровень возвращается как есть."""
    assert escalate("unknown") == "unknown"
    assert escalate("") == ""


def test_escalate_multiple_steps():
    """steps > 1 поднимает на несколько ступеней, но не выше critical."""
    assert escalate("low", steps=2) == "high"
    assert escalate("low", steps=10) == "critical"


# ---------------------------------------------------------------------------
# derive_severity — базовая критичность по тактике
# ---------------------------------------------------------------------------
def test_derive_base_from_tactic():
    """Базовая критичность по тактике без повышения: (уровень, [])."""
    rule = make_rule(mitre_tactic="credential_access")
    events = [make_event(groups=["syslog", "authentication_failed"], src_ip="10.0.0.5")]
    assert derive_severity(rule, events, None) == ("high", [])

    rule = make_rule(mitre_tactic="reconnaissance")
    assert derive_severity(rule, [make_event()], None) == ("low", [])


def test_derive_no_tactic_returns_none():
    """Правило без тактики (None) или с неизвестной тактикой → (None, []):
    вызывающий использует числовую модель риска (fallback)."""
    assert derive_severity(make_rule(mitre_tactic=None), [make_event()], None) == (None, [])
    assert derive_severity(make_rule(mitre_tactic="hacking"), [make_event()], None) == (None, [])


# ---------------------------------------------------------------------------
# derive_severity — условия повышения (максимум +1 суммарно)
# ---------------------------------------------------------------------------
def test_derive_critical_asset_escalates():
    """(a) Критичный бизнес-актив повышает на один уровень."""
    rule = make_rule(mitre_tactic="credential_access")  # high
    asset = make_asset(criticality="critical")
    severity, reasons = derive_severity(rule, [make_event(src_ip="10.0.0.5")], asset)
    assert severity == "critical"
    assert reasons == ["critical_asset"]


def test_derive_critical_asset_does_not_exceed_critical():
    """Критичный актив не поднимает уже-критичную тактику выше critical."""
    rule = make_rule(mitre_tactic="exfiltration")  # critical
    asset = make_asset(criticality="critical")
    severity, reasons = derive_severity(rule, [make_event()], asset)
    assert severity == "critical"
    assert reasons == ["critical_asset"]


def test_derive_group_markers_escalate():
    """(b) Маркеры категорий в группах события повышают критичность."""
    rule = make_rule(mitre_tactic="discovery")  # medium
    events = [make_event(groups=["syslog", "pii"])]
    severity, reasons = derive_severity(rule, events, None)
    assert severity == "high"
    assert reasons == ["personal_data"]


def test_derive_markers_in_rule_name_and_event_type():
    """Маркеры ищутся и в event_type событий, и в имени/описании правила."""
    rule = make_rule(mitre_tactic="discovery", name="red_team_probe")
    severity, reasons = derive_severity(rule, [make_event()], None)
    assert severity == "high"
    assert reasons == ["ll_redteam"]

    rule = make_rule(mitre_tactic="discovery")
    severity, reasons = derive_severity(rule, [make_event(event_type="vpn_tunnel_down")], None)
    assert severity == "high"
    assert reasons == ["perimeter"]


def test_derive_bare_words_do_not_match():
    """Голые слова "admin"/"ll"/"web" сознательно не дают ложных срабатываний."""
    rule = make_rule(mitre_tactic="discovery", name="web_portal_check")
    events = [make_event(groups=["sshd", "admin_ui"], event_type="llm_gateway")]
    assert derive_severity(rule, events, None) == ("medium", [])


def test_derive_multiple_conditions_single_step():
    """Несколько условий одновременно → всё равно ОДИН шаг повышения,
    reasons содержит коды всех сработавших категорий."""
    rule = make_rule(mitre_tactic="credential_access", escalated_by_vendor=True)
    events = [make_event(groups=["pentest"], src_ip="10.0.0.5")]
    asset = make_asset(criticality="critical")
    severity, reasons = derive_severity(rule, events, asset)
    # high +1 = critical, несмотря на три сработавшие категории
    assert severity == "critical"
    assert reasons == ["critical_asset", "ll_redteam", "vendor_flag"]


def test_derive_vendor_flag_escalates():
    """(d) Ручной флаг поставщика логов (п.7 процедуры) повышает критичность."""
    rule = make_rule(mitre_tactic="reconnaissance", escalated_by_vendor=True)  # low
    severity, reasons = derive_severity(rule, [make_event()], None)
    assert severity == "medium"
    assert reasons == ["vendor_flag"]


def test_derive_perimeter_external_ip():
    """(c) Периметр: актив из сегмента DMZ + внешний src_ip (192.0.2.x —
    внешний по ручному списку внутренних сетей)."""
    rule = make_rule(mitre_tactic="discovery")  # medium
    asset = make_asset(network_segment="DMZ")
    events = [make_event(src_ip="192.0.2.99")]
    severity, reasons = derive_severity(rule, events, asset)
    assert severity == "high"
    assert reasons == ["perimeter"]


def test_derive_perimeter_internal_ip_not_escalated():
    """10.x — внутренний по ручному списку: периметр не повышает."""
    rule = make_rule(mitre_tactic="discovery")
    asset = make_asset(network_segment="dmz")  # lowercase сегмент
    events = [make_event(src_ip="10.20.30.40")]
    assert derive_severity(rule, events, asset) == ("medium", [])


def test_derive_perimeter_invalid_ip_not_external():
    """Некорректный src_ip (не парсится) — не внешний: периметра нет."""
    rule = make_rule(mitre_tactic="discovery")
    asset = make_asset(network_segment="edge")
    events = [make_event(src_ip="not-an-ip")]
    assert derive_severity(rule, events, asset) == ("medium", [])


def test_derive_perimeter_requires_segment():
    """Актив вне периметровых сегментов (dmz/edge/internet) — повышения нет."""
    rule = make_rule(mitre_tactic="discovery")
    asset = make_asset(network_segment="internal")
    events = [make_event(src_ip="192.0.2.99")]
    assert derive_severity(rule, events, asset) == ("medium", [])

    # внешний IP без актива тоже не повышает
    assert derive_severity(rule, events, None) == ("medium", [])


def test_derive_escalation_from_low_and_medium_bases():
    """Повышение работает с любого базового уровня матрицы."""
    low_rule = make_rule(mitre_tactic="resource_development", escalated_by_vendor=True)
    assert derive_severity(low_rule, [make_event()], None) == ("medium", ["vendor_flag"])

    med_rule = make_rule(mitre_tactic="initial_access", escalated_by_vendor=True)
    assert derive_severity(med_rule, [make_event()], None) == ("high", ["vendor_flag"])
