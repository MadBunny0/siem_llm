from fastapi import FastAPI
from app.api.routes import router

app = FastAPI(
    title="Intelligent Incident Processing System",
    version="1.0.0",
    description="Wazuh + LLM + controlled response prototype",
)
app.include_router(router)


@app.get("/")
def root():
    return {
        "service": "Intelligent Incident Processing System",
        "status": "ok",
        "docs": "/docs",
    }
