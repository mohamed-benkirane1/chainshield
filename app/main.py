from fastapi import FastAPI

from app.api.errors import register_error_handlers
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
app.include_router(transactions_router, prefix="/api/v1")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
