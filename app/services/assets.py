"""Привязка событий к защищаемым активам (§3.2 ВКР — сущность Asset).

Определение актива необходимо для учёта его критичности при расчёте риска
(§3.3.3) и при выборе сценария реагирования (§3.4, p:102).
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset


def resolve_asset_id(
    db: Session,
    src_ip: str | None = None,
    agent_name: str | None = None,
) -> int | None:
    """Определение защищаемого актива по IP-адресу источника или имени агента.

    Сравнивает src_ip с перечнем ip_addresses актива (разделители: запятая,
    точка с запятой, пробел) и имя агента Wazuh с наименованием актива.
    Возвращает id актива либо None, если актив не определён.
    """
    if src_ip:
        assets = list(db.scalars(select(Asset)).all())
        for asset in assets:
            raw_ips = (asset.ip_addresses or "").replace(";", ",").replace(" ", ",")
            ips = [ip for ip in raw_ips.split(",") if ip]
            if src_ip in ips:
                return asset.id

    if agent_name:
        asset = db.scalar(select(Asset).where(Asset.name == agent_name))
        if asset:
            return asset.id

    return None
