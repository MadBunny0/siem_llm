"""Мок-сценарии событий Wazuh для демонстрации (stage-12 → stage-15).

Единый пул для двух эндпоинтов:
- POST /demo/populate — полный прогон всех сценариев → ~7 инцидентов всех уровней;
- POST /demo/test-event — случайное событие из случайного сценария (кнопка
  «Тестовое событие», stage-15: рандомное событие из мок-пула).

Каждый сценарий — небольшой всплеск событий, который гарантированно проходит
корреляцию соответствующего seed-правила (MITRE ATT&CK, см. init_db):
одиночное событие с порогом min_events > 1 инцидент не создаст.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class MockScenario:
    """Мок-сценарий атаки.

    key — машинное имя (аудит, тесты); title — русское название для UI;
    events — payload-ы алертов Wazuh (формат POST /ingest/wazuh).
    """

    key: str
    title: str
    events: list[dict] = field(default_factory=list)


def build_mock_scenarios(now: datetime) -> list[MockScenario]:
    """Пул мок-сценариев; таймстампы алертов отсчитываются от now.

    Содержимое и порядок сценариев зафиксированы (19 событий → 7 инцидентов):
    поведение POST /demo/populate не меняется (stage-15 — только вынос из routes).
    Сценарии разведены по времени/активам, чтобы при полном прогоне соседние
    сценарии не склеивались в один инцидент (общий актив или общий IP дают
    совпадение по атрибутам корреляции).
    """

    def ev(minutes_ago: float, *, level: int, groups: list[str], agent: str,
           srcip: str, user: str | None = None, description: str = "") -> dict:
        return {
            "timestamp": (now - timedelta(minutes=minutes_ago)).isoformat(),
            "rule": {"id": "900000", "level": level, "description": description or groups[0],
                     "groups": groups},
            "agent": {"id": "001", "name": agent},
            "data": {"srcip": srcip, "dstuser": user} if user else {"srcip": srcip},
            "full_log": f"{groups[0]} from {srcip}" + (f" user={user}" if user else ""),
        }

    return [
        MockScenario(
            key="brute_force",
            title="Подбор пароля SSH (T1110) — mail-prod-01",
            events=[
                ev(4 - i, level=10, groups=["syslog", "sshd", "authentication_failed"],
                   agent="mail-prod-01", srcip="198.51.100.7", user="root",
                   description="sshd: authentication failure")
                for i in range(4)
            ],
        ),
        MockScenario(
            key="password_spraying",
            title="Распыление паролей (T1110.003) — db-primary-01",
            events=[
                # 6 событий: порог spraying 5, чтобы перебить brute_force на том же паттерне
                ev(6 - i, level=9, groups=["syslog", "sshd", "authentication_failed"],
                   agent="db-primary-01", srcip="198.51.100.23", user=f"user{i:02d}",
                   description="sshd: authentication failure")
                for i in range(6)
            ],
        ),
        MockScenario(
            key="privilege_escalation",
            title="Повышение привилегий (T1068/T1548) — mail-prod-01",
            events=[
                # 40 мин назад — вне окон других сценариев: общий актив иначе
                # склеил бы инциденты
                ev(40, level=15, groups=["privilege_escalation"],
                   agent="mail-prod-01", srcip="198.51.100.7", user="root",
                   description="user added to sudo group"),
            ],
        ),
        MockScenario(
            key="repeated_scan",
            title="Сетевое сканирование (T1046) — fw-edge-01",
            events=[
                ev(8 - i, level=5, groups=["syslog", "sshd"],
                   agent="fw-edge-01", srcip="203.0.113.99",
                   description="Connection closed by scanning host")
                for i in range(3)
            ],
        ),
        MockScenario(
            key="web_attack_sqlinjection",
            title="Веб-атака: SQL-инъекция (T1190) — app-web-01",
            events=[
                ev(5 - i, level=8, groups=["web", "attack", "sqlinjection"],
                   agent="app-web-01", srcip="203.0.113.77",
                   description="SQL injection attempt in query string")
                for i in range(2)
            ],
        ),
        MockScenario(
            key="malware_detection",
            title="Вредоносное ПО (T1204) — wks-finance-12",
            events=[
                ev(3, level=12, groups=["malware"],
                   agent="wks-finance-12", srcip="198.51.100.50",
                   description="Malicious executable detected"),
            ],
        ),
        MockScenario(
            key="background_noise",
            title="Фоновый шум — wks-office-15",
            events=[
                # 41/40 мин назад — вне окна malware-сценария; агент вне инвентаря →
                # актив не определён, критичность актива не завышает оценку → низкий риск
                ev(41 - i, level=2, groups=["syslog"],
                   agent="wks-office-15", srcip="203.0.113.250",
                   description="Minor system event")
                for i in range(2)
            ],
        ),
    ]
