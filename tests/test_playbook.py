"""Тесты справочника сценариев реагирования (app/services/playbook.py).

execute_playbook (движок симуляции, stage-12…20) удалён в stage-23 вместе
с режимом симуляции: исполнение всегда реальное — app/services/execution.py
(тесты — test_execution.py, test_responses_api.py). Здесь остаётся
загрузка сценариев из БД по типу действия.
"""

from app.models import Playbook
from app.services.playbook import load_playbook_by_action


def _add(db, name="block_ip", allowed=None):
    playbook = Playbook(
        name=name,
        description=f"Сценарий {name}",
        trigger_conditions={},
        allowed_actions=allowed or [name],
        steps=[{"action": name}],
        is_active=True,
    )
    db.add(playbook)
    db.commit()
    return playbook


def test_load_playbook_by_action_found(db):
    playbook = _add(db)
    assert load_playbook_by_action(db, "block_ip") is playbook


def test_load_playbook_by_action_string_allowed_actions(db):
    """allowed_actions может храниться строкой (старые записи) — ищем и так."""
    _add(db, allowed="block_ip")
    assert load_playbook_by_action(db, "block_ip") is not None


def test_load_playbook_by_action_unknown(db):
    assert load_playbook_by_action(db, "nonexistent_action") is None


def test_load_playbook_by_action_inactive_excluded(db):
    playbook = _add(db)
    playbook.is_active = False
    db.commit()
    assert load_playbook_by_action(db, "block_ip") is None
