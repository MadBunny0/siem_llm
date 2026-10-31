import pytest
from unittest.mock import patch

from app.services.playbook import execute_playbook, load_playbook_by_action


def test_execute_playbook_simulation_mode():
    with patch("app.services.playbook.settings.auto_response", False):
        result = execute_playbook("block_ip", {"incident_id": 1})
        assert result["executed"] is False
        assert result["mode"] == "simulation"
        assert result["action"] == "block_ip"


def test_execute_playbook_controlled_mode():
    with patch("app.services.playbook.settings.auto_response", True):
        result = execute_playbook("block_ip", {"incident_id": 1})
        assert result["executed"] is True
        assert result["mode"] == "controlled"
        assert result["action"] == "block_ip"
        assert result["playbook"] == "block_ip"