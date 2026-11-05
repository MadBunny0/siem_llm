"""ITSM-уведомления аналитикам SOC (Глава 3.5).

Сервис имитирует отправку уведомлений через email/Slack/Teams: записи
создаются со статусом 'pending' и выводятся в лог — реальная интеграция
с почтовым сервером или Slack API остаётся за рамками прототипа
(настройка AUTO_RESPONSE, управлявшая пометкой 'sent', удалена в stage-23
вместе с режимом симуляции).
"""

import logging

from sqlalchemy.orm import Session

from app.models import Incident, Notification

logger = logging.getLogger("notification")


def _choose_recipients(severity: str, criticality: str | None) -> list[tuple[str, str]]:
    """Выбор получателей уведомления в зависимости от критичности."""
    high_severity = severity in ("critical", "high")
    high_criticality = criticality in ("critical", "high")
    if high_severity or high_criticality:
        return [
            ("analyst@example.com", "email"),
            ("soc-channel@slack.com", "slack"),
        ]
    return [("analyst@example.com", "email")]


def build_incident_notification(
    incident: Incident,
    event_type: str,
) -> tuple[str, dict]:
    """Формирует тело уведомления об инциденте."""
    asset_name = incident.asset.name if incident.asset else "не определён"
    asset_criticality = incident.asset.criticality if incident.asset else None
    message = (
        f"INCIDENT #{incident.id}: {incident.title}\n"
        f"Severity: {incident.severity} | Risk: {incident.risk_score}/100 | "
        f"Attack: {incident.attack_type or 'unknown'}\n"
        f"Asset: {asset_name} (criticality: {asset_criticality or 'n/a'})\n"
        f"Status: {incident.status} | Created: {incident.created_at.isoformat()}"
    )
    payload = {
        "incident_id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "attack_type": incident.attack_type,
        "asset": {
            "name": asset_name,
            "criticality": asset_criticality,
        },
        "status": incident.status,
    }
    return message, payload


def notify_analyst(
    db: Session,
    incident: Incident,
    event_type: str = "incident_created",
) -> Notification | None:
    """Отправить уведомление аналитикам SOC об инциденте.

    Создаёт запись в notification_logs для каждого канала и получателя.
    """
    if not db:
        logger.warning("notify_analyst: db session not provided")
        return None

    recipients = _choose_recipients(
        incident.severity,
        incident.asset.criticality if incident.asset else None,
    )
    message, payload = build_incident_notification(incident, event_type)

    created = []
    for recipient, channel in recipients:
        notification = Notification(
            event_type=event_type,
            incident_id=incident.id,
            recipient=recipient,
            channel=channel,
            message=message,
            payload=payload,
            status="pending",
        )
        db.add(notification)
        created.append(notification)

    try:
        db.flush()
    except Exception as exc:
        logger.error("notify_analyst: failed to flush notifications: %s", exc)
        for n in created:
            n.status = "failed"
        db.rollback()
        return None

    for n in created:
        logger.info(
            "NOTIFICATION %s -> [%s] recipient=%s incident_id=%s",
            n.status,
            n.channel,
            n.recipient,
            n.incident_id,
        )
    return created[0]