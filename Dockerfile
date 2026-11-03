# Прод-стадия: API (используется сервисами db-init и api)
FROM python:3.12-slim AS base
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Dev-стадия: прод + автотесты — docker compose --profile tests run --rm tests
# (см. DEPLOYMENT.md, раздел «Автотесты»); локальный Python не требуется
FROM base AS dev
COPY pytest.ini ./
COPY tests ./tests
RUN pip install --no-cache-dir pytest
CMD ["pytest"]
