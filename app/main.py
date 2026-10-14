from fastapi import FastAPI

from app.api.addresses import router as addresses_router
from app.api.body_limit import BodySizeLimitMiddleware
from app.api.errors import register_error_handlers
from app.api.investigations import router as investigations_router
from app.api.relationships import router as relationships_router
from app.api.transactions import router as transactions_router

app = FastAPI(
    title="ChainShield",
    version="0.1.0",
    description=(
        "Defensive crypto-scam risk assessment. Results are decision-support "
        "indicators, never proof of fraud."
    ),
)
register_error_handlers(app)
# Oversized bodies are rejected before routing, so no route or dependency runs.
app.add_middleware(BodySizeLimitMiddleware)
app.include_router(transactions_router, prefix="/api/v1")
app.include_router(addresses_router, prefix="/api/v1")
app.include_router(relationships_router, prefix="/api/v1")
app.include_router(investigations_router, prefix="/api/v1")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
