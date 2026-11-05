"""REST API — оркестрация конвейера обработки инцидентов (Главы 3.1–3.4 ВКР).

Этапы обработки события (§3.1, рис. 3.1):
сбор (ingest) → нормализация → привязка актива → корреляция по правилам БД →
оценка риска → [авто]LLM-анализ → Decision Validation Engine → playbook → аудит.

Критичность инцидента (stage-17) — по матрице «тактика MITRE → критичность»
(процедура PDF v3.1, docs/CRITICALITY_MATRIX.md); при тактике без матричного
правила — числовая модель §3.3.3. Low-инциденты после успешного автоанализа
закрываются автоматически (AUTO_CLOSE_LEVELS) — без участия человека.

Stage-18 (фидбек): автоанализ и автоконвейер реагирования — только для low
(AUTO_ANALYSIS_LEVELS); critical/high/medium обрабатывает оператор. Ручной
POST /incidents/{id}/analyze выполняется в фоне (ответ scheduled) — синхронный
CPU-инференс упирался в таймаут nginx (504); инференс LLM сериализуется
(LLM_INFERENCE_LOCK) — пачка анализов не душит модель.

Stage-19: монолит разрезан по доменам — этот модуль теперь тонкий агрегатор
роутеров (app/api/{auth,ingest,incident,catalog,response,system}_routes.py);
конвейер приёма — app/services/ingest.py, оркестрация анализа —
app/services/auto_analysis.py, общие хелперы роутеров — app/api/common.py.
Здесь же — живой compat-шов для тестов (см. ниже).
"""

# ---------------------------------------------------------------------------
# Живой compat-шов для тестов (stage-19): имя должно СУЩЕСТВОВАТЬ как атрибут
# модуля app.api.routes — тесты подменяют его через monkeypatch.setattr(...):
#   "app.api.routes.analyze_incident" — фейковый LLM-вызов (test_routes.py,
#       test_auth.py); реальный вызов резолвится в рантайме через этот модуль
#       делегатом app/services/auto_analysis.analyze_incident.
# (Швы "app.api.routes.datetime" и "app.api.routes.random.choice" удалены в
# legacy-cleanup 2026-11-05 — потребителей больше нет, история в
# analysis/DEVIATIONS.md.)
# ---------------------------------------------------------------------------

from fastapi import APIRouter

from app.api.auth_routes import router as auth_router
from app.api.catalog_routes import router as catalog_router
from app.api.ingest_routes import router as ingest_router
from app.api.incident_routes import router as incident_router
from app.api.response_routes import router as response_router
from app.api.system_routes import router as system_router
# noqa: F401 — реэкспорт: тесты подменяют LLM-вызов именно на этом модуле
from app.services.llm import analyze_incident  # noqa: F401

# реэкспорт для тестов: tests/test_routes.py делает
# from app.api.routes import run_auto_analysis
from app.services.auto_analysis import run_auto_analysis

router = APIRouter(prefix="/api/v1", tags=["SIEM"])

# теги вешаются при включении: include_router НЕ наследует теги родительского
# роутера (FastAPI), поэтому каждый под-роутер получает тег явно — как у
# монолита, где все маршруты жили на одном роутере с tags=["SIEM"]
router.include_router(auth_router, tags=["SIEM"])
router.include_router(ingest_router, tags=["SIEM"])
router.include_router(incident_router, tags=["SIEM"])
router.include_router(response_router, tags=["SIEM"])
router.include_router(catalog_router, tags=["SIEM"])
router.include_router(system_router, tags=["SIEM"])

__all__ = ["router", "run_auto_analysis"]
