# Агент ВМ наблюдаемого пользователя (stage-20) — standalone-образ,
# зависимости минимальны: fastapi + uvicorn (остальное — stdlib)
FROM python:3.12-slim

WORKDIR /agent
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py emu_state.py activity.py ./

ENV AGENT_PORT=8100
EXPOSE 8100

# каталог состояния (монтируется volume'ом — демонстрация переживает рестарт)
RUN mkdir -p /data
VOLUME ["/data"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100"]
