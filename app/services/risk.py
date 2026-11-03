LEVEL_TO_SCORE = {
    str(i): min(100, i * 7) for i in range(16)
}

def score_to_severity(score: int) -> str:
    if score >= 85: return "critical"
    if score >= 65: return "high"
    if score >= 40: return "medium"
    return "low"

def calculate_risk(events: list[dict], p_implement: float = 0.5) -> tuple[int, str]:
    """Расчёт уровня риска инцидента (согласно алгоритму 3.3.3 ВКР).

    Учитывает комплекс показателей:
    * критичность защищаемого актива;
    * количество взаимосвязанных событий;
    * уровень опасности выявленного типа атаки;
    * достоверность результатов корреляции;
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

    base = max(scores, default=0)
    # бонус за серию событий (корреляция)
    bonus = min(20, max(0, len(events) - 1) * 5)
    # вероятность реализации угрозы: масштабирование бонуса на вероятность
    adjusted_bonus = bonus * p_implement
    score = min(100, base + adjusted_bonus)
    return score, score_to_severity(score)
