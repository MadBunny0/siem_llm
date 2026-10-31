from app.services.normalization import normalize_wazuh


def test_normalize_wazuh_basic():
    alert = {
        "timestamp": "2026-10-28T12:00:00Z",
        "rule": {"level": 5, "groups": ["authentication_failed"], "description": "Test rule"},
        "agent": {"name": "server-01", "id": "001"},
        "data": {
            "srcip": "192.168.1.100",
            "dstuser": "root",
            "full_log": "Failed password for root from 192.168.1.100",
        },
    }
    normalized = normalize_wazuh(alert)

    assert normalized["source"] == "server-01"
    assert normalized["event_type"] == "authentication_failed"
    assert normalized["user"] == "root"
    assert normalized["src_ip"] == "192.168.1.100"
    assert normalized["criticality_level"] == 5
    assert normalized["raw_message"] == "Failed password for root from 192.168.1.100"
    assert normalized["raw_data"]["data"]["srcip"] == "192.168.1.100"
    assert "full_log" in normalized["raw_data"]


def test_normalize_wazuh_missing_fields():
    alert = {"rule": {"level": 1}}
    normalized = normalize_wazuh(alert)

    assert normalized["source"] == "wazuh"
    assert normalized["event_type"] == "security_event"
    assert normalized["user"] is None
    assert normalized["src_ip"] is None
    assert normalized["criticality_level"] == 1
    assert normalized["raw_message"] is None