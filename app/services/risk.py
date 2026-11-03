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
    # достоверность корреляции и вероятность реализации сужают бонус
    confidence = max(0.0, min(1.0, correlation_confidence))
    probability = max(0.0, min(1.0, p_implement))
    adjusted_bonus = bonus * probability * confidence
    score = int(round(min(100, base + adjusted_bonus)))
    return score, score_to_severity(score)
