"""Transaction inspection endpoint."""

import os
from collections.abc import Mapping
from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.assessment_schemas import TransactionAssessmentRequest, TransactionAssessmentResponse
from app.api.schemas import ErrorResponse, TransactionInspectionResponse
from app.domain.analysis_input import TransactionAnalysisRequest
from app.providers.ethereum import RPC_URL_ENV_VAR as ETHEREUM_RPC_URL_ENV_VAR
from app.providers.ethereum import EthereumProvider
from app.providers.tron import RPC_URL_ENV_VAR as TRON_RPC_URL_ENV_VAR
from app.providers.tron import TronProvider
from app.risk.assessment import assess_transaction
from app.services.transaction_analysis import (
    TransactionAnalysisService,
    UsdtTransferProvider,
)

router = APIRouter(tags=["transactions"])


def build_transaction_analysis_service(
    environ: Mapping[str, str] | None = None,
) -> TransactionAnalysisService:
    """Build the service from the environment, without any network call.

    Only networks whose RPC URL is set get a provider; requests for another
    network fail with ``provider_not_configured``. An invalid configuration
    raises ``ProviderConfigurationError``.
    """
    env = os.environ if environ is None else environ
    providers: list[UsdtTransferProvider] = []
    if env.get(ETHEREUM_RPC_URL_ENV_VAR, "").strip():
        providers.append(EthereumProvider.from_env(env))
    if env.get(TRON_RPC_URL_ENV_VAR, "").strip():
        providers.append(TronProvider.from_env(env))
    return TransactionAnalysisService(providers)


@lru_cache(maxsize=1)
def get_transaction_analysis_service() -> TransactionAnalysisService:
    """FastAPI dependency; built on first use, then reused (override in tests)."""
    return build_transaction_analysis_service()


_ERROR_RESPONSES = {
    status: {"model": ErrorResponse, "description": description}
    for status, description in (
        (422, "Invalid request, conflicting reports or unsupported transaction type."),
        (500, "Internal error."),
        (502, "Malformed, inconsistent or wrong-network provider data."),
        (503, "Provider not configured, unavailable or rate limited."),
        (504, "Provider timeout."),
    )
}


@router.post(
    "/transactions/inspect",
    response_model=TransactionInspectionResponse,
    responses=_ERROR_RESPONSES,
    summary="Inspect a transaction and its official USDT transfers",
)
def inspect_transaction(
    request: TransactionAnalysisRequest,
    service: Annotated[TransactionAnalysisService, Depends(get_transaction_analysis_service)],
) -> TransactionInspectionResponse:
    """Read-only lookup on Ethereum or TRON. Not a fraud verdict or risk score.

    Synchronous on purpose: providers use blocking I/O, so FastAPI runs this
    handler in its thread pool instead of the event loop.
    """
    inspection = service.inspect_transaction(request.network, request.tx_hash)
    return TransactionInspectionResponse.from_inspection(inspection)


@router.post(
    "/transactions/assess",
    response_model=TransactionAssessmentResponse,
    responses=_ERROR_RESPONSES,
    summary="Assess a transaction against client-supplied, unverified reports",
)
def assess_transaction_endpoint(
    request: TransactionAssessmentRequest,
    service: Annotated[TransactionAnalysisService, Depends(get_transaction_analysis_service)],
) -> TransactionAssessmentResponse:
    """Inspect once, then match supplied reports. No score, never a fraud verdict.

    ``risk_determination`` is always ``indeterminate``; ``reports`` are taken
    as supplied and ``source_reference`` is never fetched. Synchronous for the
    same reason as ``/transactions/inspect``.
    """
    inspection = service.inspect_transaction(request.network, request.tx_hash)
    assessment = assess_transaction(inspection, request.reports)
    return TransactionAssessmentResponse.from_domain(inspection, assessment)
