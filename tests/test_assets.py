"""Тесты привязки событий к защищаемым активам (app/services/assets.py).

resolve_asset_id ищет актив по IP-адресу источника (поле Asset.ip_addresses,
разделители: запятая, точка с запятой, пробел) либо по имени агента Wazuh
(совпадение с Asset.name). Результат — id актива или None.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Asset, Base


@pytest.fixture
def db():
    """Изолированная in-memory SQLite-БД (как в test_correlation.py)."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    yield SessionLocal()
    engine.dispose()


def test_resolve_by_ip_multi_value(db):
    """Актив находится по одному из нескольких IP в поле ip_addresses."""
    from app.services.assets import resolve_asset_id

    asset = Asset(
        name="web-server",
        type="server",
        criticality="high",
        ip_addresses="10.20.30.10, 10.20.30.11",  # несколько адресов через запятую и пробел
    )
    db.add(asset)
    db.commit()

    assert resolve_asset_id(db, src_ip="10.20.30.10") == asset.id
    assert resolve_asset_id(db, src_ip="10.20.30.11") == asset.id


def test_resolve_by_ip_semicolon_separator(db):
    """Разделителем перечня IP может быть точка с запятой."""
    from app.services.assets import resolve_asset_id

    asset = Asset(
        name="db-server",
        type="server",
        criticality="critical",
        ip_addresses="10.20.30.20;10.20.30.21",
    )
    db.add(asset)
    db.commit()

    assert resolve_asset_id(db, src_ip="10.20.30.21") == asset.id


def test_resolve_by_agent_name(db):
    """Актив находится по имени агента Wazuh (совпадение с Asset.name)."""
    from app.services.assets import resolve_asset_id

    asset = Asset(
        name="test-host",
        type="workstation",
        criticality="medium",
        ip_addresses=None,
    )
    db.add(asset)
    db.commit()

    assert resolve_asset_id(db, agent_name="test-host") == asset.id


def test_ip_takes_priority_over_name(db):
    """При совпадении и IP, и имени агента приоритет у поиска по IP-адресу."""
    from app.services.assets import resolve_asset_id

    ip_asset = Asset(
        name="web-server",
        type="server",
        criticality="high",
        ip_addresses="10.20.30.10",
    )
    name_asset = Asset(
        name="test-host",
        type="workstation",
        criticality="low",
        ip_addresses=None,
    )
    db.add(ip_asset)
    db.add(name_asset)
    db.commit()

    resolved_id = resolve_asset_id(db, src_ip="10.20.30.10", agent_name="test-host")
    assert resolved_id == ip_asset.id
    assert resolved_id != name_asset.id


def test_no_match_returns_none(db):
    """Если ни IP, ни имя агента не совпали — актив не определён (None)."""
    from app.services.assets import resolve_asset_id

    db.add(
        Asset(
            name="web-server",
            type="server",
            criticality="high",
            ip_addresses="10.20.30.10",
        )
    )
    db.commit()

    assert resolve_asset_id(db, src_ip="203.0.113.99", agent_name="unknown-host") is None


def test_none_arguments_returns_none(db):
    """Без входных данных (src_ip=None, agent_name=None) возвращается None."""
    from app.services.assets import resolve_asset_id

    db.add(
        Asset(
            name="web-server",
            type="server",
            criticality="high",
            ip_addresses="10.20.30.10",
        )
    )
    db.commit()

    assert resolve_asset_id(db) is None
    assert resolve_asset_id(db, src_ip=None, agent_name=None) is None
