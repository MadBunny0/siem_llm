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


def attack_danger_score(event: dict) -> int | None:
    """Опасность типа атаки по событию: максимум совпадений по event_type и groups."""
    event_type = str(event.get("event_type") or "").lower()
    rule = (event.get("raw_data") or {}).get("rule") or {}
    groups = [str(g).lower() for g in (rule.get("groups") or [])]
    haystacks = [event_type, *groups]
    scores = [
        score
        for pattern, score in ATTACK_TYPE_DANGER.items()
        if any(pattern in h for h in haystacks)
    ]
    return max(scores) if scores else None


def score_to_severity(score: int) -> str:
    if score >= 85: return "critical"
    if score >= 65: return "high"
    if score >= 40: return "medium"
    return "low"

def calculate_risk(events: list[dict], p_implement: float = 0.5, min_events: int = 1) -> tuple[int, str]:
    """Расчёт уровня риска инцидента (согласно алгоритму 3.3.3 ВКР).

    Учитывает комплекс показателей:
    * уровень опасности события (rule.level из Wazuh);
    * критичность защищаемого актива;
    * уровень опасности выявленного типа атаки (ATTACK_TYPE_DANGER);
    * количество взаимосвязанных событий (бонус за серию);
    * достоверность результатов корреляции (соотношение с порогом min_events);
    * вероятность реализации угрозы (p_implement, 0.0–1.0).
    """
    scores = []
    for event in events:
        level = str((event.get("raw_data") or {}).get("rule", {}).get("level", "3"))
        scores.append(LEVEL_TO_SCORE.get(level, 20))

        # критичность защищаемого актива
        asset_criticality = event.get("asset_criticality")
        if asset_criticality in ("critical", "high"):
            scores.append(100 if asset_criticality == "critical" else 75)
        elif asset_criticality == "medium":
            scores.append(60)

        # уровень опасности выявленного типа атаки
        danger = attack_danger_score(event)
        if danger is not None:
            scores.append(danger)

    base = max(scores, default=0)
    # бонус за серию событий (корреляция)
    bonus = min(20, max(0, len(events) - 1) * 5)
    # достоверность корреляции: растёт с числом связанных событий относительно порога правила
    if min_events > 1:
        correlation_confidence = min(1.0, len(events) / (min_events + 2))
    else:
        correlation_confidence = 1.0
    # вероятность реализации угрозы: масштабирование бонуса на вероятность
    adjusted_bonus = bonus * p_implement * correlation_confidence
    score = int(round(min(100, base + adjusted_bonus)))
    return score, score_to_severity(score)
