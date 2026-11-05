LEVEL_TO_SCORE = {
    str(i): min(100, i * 7) for i in range(16)
}

# Уровень опасности выявленного типа атаки (§3.3.3 ВКР).
# Сопоставление по подстроке в event_type или groups правила Wazuh.
ATTACK_TYPE_DANGER = {
    "privilege": 95,
    "exfiltration": 95,
    "malware": 90,
    "credential": 85,
    "brute": 80,
    "authentication_failed": 60,
    "scan": 55,
}

# Пороги числовой модели риска (score_to_severity): порог → уровень.
SEVERITY_THRESHOLDS = (("critical", 85), ("high", 65), ("medium", 40))


def attack_danger_score(event: dict) -> int | None:
    """Опасность типа атаки по событию: максимум совпадений по event_type и groups."""
    match = _attack_danger_match(event)
    return match[0] if match else None


def _attack_danger_match(event: dict) -> tuple[int, str] | None:
    """(балл, совпавший маркер) опасности типа атаки или None (stage-22).

    Маркер нужен для объяснения фактора в карточке инцидента
    (severity_factors), сам расчёт совпадает с attack_danger_score.
    """
    event_type = str(event.get("event_type") or "").lower()
    rule = (event.get("raw_data") or {}).get("rule") or {}
    groups = [str(g).lower() for g in (rule.get("groups") or [])]
    haystacks = [event_type, *groups]
    best: tuple[int, str] | None = None
    for pattern, score in ATTACK_TYPE_DANGER.items():
        if any(pattern in h for h in haystacks) and (best is None or score > best[0]):
            best = (score, pattern)
    return best


def score_to_severity(score: int) -> str:
    for severity, threshold in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return "low"


def calculate_risk(
    events: list[dict],
    p_implement: float = 0.5,
    correlation_confidence: float = 1.0,
) -> tuple[int, str]:
    """Расчёт интегральной оценки риска инцидента (согласно §3.3.3 ВКР, p:69-80).

    Пять факторов эталона и их реализация:
    * критичность защищаемого актива — asset_criticality события (critical→100,
      high→75, medium→60 добавляются к базе);
    * количество взаимосвязанных событий — бонус за серию +5 за событие, до +20;
    * уровень опасности выявленного типа атаки — ATTACK_TYPE_DANGER;
    * достоверность результатов корреляции — correlation_confidence (0–1: средняя
      доля совпавших признаков IP/учётка/актив между связанными событиями,
      из correlation.evaluate_correlation);
    * вероятность реализации угрозы — p_implement (0–1: из данных события,
      см. routes._p_implement).

    Итог: score = min(100, max(оценок) + бонус_серии × p_implement × достоверность).
    """
    score, severity, _ = calculate_risk_detail(events, p_implement, correlation_confidence)
    return score, severity


def calculate_risk_detail(
    events: list[dict],
    p_implement: float = 0.5,
    correlation_confidence: float = 1.0,
) -> tuple[int, str, dict]:
    """Расчёт риска с разбором факторов (stage-22, для карточки инцидента).

    Возвращает (score, severity, breakdown); score/severity совпадают с
    calculate_risk (та же логика, расчёт один). breakdown — сохраняемый на
    инциденте разбор чисел:

    {
      "score": 74, "severity": "high",
      "base": 60, "base_from": "rule_level",
      "factors": [  # слагаемые базы, каждое с числом и объяснением
        {"kind": "rule_level", "value": 60, "detail": "Уровень правила Wazuh: 10 → 60/100"},
        ...
      ],
      "series_bonus": 10,            # бонус за серию до сужения
      "p_implement": 0.67,           # вероятность реализации (0–1)
      "correlation_confidence": 0.78,# достоверность корреляции (0–1)
      "adjusted_bonus": 5.2,         # серия × p × достоверность (добавка к базе)
      "thresholds": {"critical": 85, "high": 65, "medium": 40},
    }
    """
    # максимальные слагаемые базы по каждому виду фактора (как в calculate_risk:
    # база = максимум оценок, а не сумма)
    max_rule_level: tuple[int, str] | None = None   # (балл, уровень Wazuh)
    max_asset: tuple[int, str] | None = None        # (балл, критичность актива)
    max_danger: tuple[int, str] | None = None       # (балл, маркер типа атаки)

    for event in events:
        level = str((event.get("raw_data") or {}).get("rule", {}).get("level", "3"))
        level_score = LEVEL_TO_SCORE.get(level, 20)
        if max_rule_level is None or level_score > max_rule_level[0]:
            max_rule_level = (level_score, level)

        asset_criticality = event.get("asset_criticality")
        if asset_criticality in ("critical", "high", "medium"):
            asset_score = {"critical": 100, "high": 75, "medium": 60}[asset_criticality]
            if max_asset is None or asset_score > max_asset[0]:
                max_asset = (asset_score, asset_criticality)

        danger = _attack_danger_match(event)
        if danger is not None and (max_danger is None or danger[0] > max_danger[0]):
            max_danger = danger

    factors = []
    if max_rule_level is not None:
        factors.append({
            "kind": "rule_level",
            "value": max_rule_level[0],
            "detail": f"Уровень правила Wazuh: {max_rule_level[1]} → {max_rule_level[0]}/100",
        })
    if max_asset is not None:
        factors.append({
            "kind": "asset_criticality",
            "value": max_asset[0],
            "detail": f"Критичность актива: {max_asset[1]} → {max_asset[0]}/100",
        })
    if max_danger is not None:
        factors.append({
            "kind": "attack_danger",
            "value": max_danger[0],
            "detail": f"Опасность типа атаки (маркер «{max_danger[1]}») → {max_danger[0]}/100",
        })

    # база = максимальное слагаемое (порядок factors детерминирован —
    # соответствуют порядку добавления в расчёте выше)
    base = max((f["value"] for f in factors), default=0)
    base_from = max(factors, key=lambda f: f["value"])["kind"] if factors else None

    # бонус за серию событий (корреляция)
    bonus = min(20, max(0, len(events) - 1) * 5)
    # достоверность корреляции и вероятность реализации сужают бонус
    confidence = max(0.0, min(1.0, correlation_confidence))
    probability = max(0.0, min(1.0, p_implement))
    adjusted_bonus = bonus * probability * confidence
    score = int(round(min(100, base + adjusted_bonus)))
    severity = score_to_severity(score)

    breakdown = {
        "score": score,
        "severity": severity,
        "base": base,
        "base_from": base_from,
        "factors": factors,
        "series_bonus": bonus,
        "p_implement": round(probability, 3),
        "correlation_confidence": round(confidence, 3),
        "adjusted_bonus": round(adjusted_bonus, 1),
        "thresholds": dict(SEVERITY_THRESHOLDS),
    }
    return score, severity, breakdown
