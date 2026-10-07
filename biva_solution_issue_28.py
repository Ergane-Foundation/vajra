from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

app = FastAPI(title="Inference API Health Check")


class HealthResponse(BaseModel):
    status: str
    placeholder_models: List[str]


# In a real setup this could be loaded from a DB or config file
PLACEHOLDER_MODELS = ["sentiment‑v1", "ner‑beta", "image‑classifier‑stub"]


@app.get("/health", response_model=HealthResponse)
def health_check():
    """
    Simple health check that reports the service status
    and any placeholder models currently registered.
    """
    return HealthResponse(
        status="ok",
        placeholder_models=PLACEHOLDER_MODELS,
    )