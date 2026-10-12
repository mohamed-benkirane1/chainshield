from fastapi import FastAPI

app = FastAPI(
    title="ChainShield",
    version="0.1.0",
    description=(
        "Defensive crypto-scam risk assessment. Results are decision-support "
        "indicators, never proof of fraud."
    ),
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
