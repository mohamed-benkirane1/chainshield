"""Multi-address investigation dossier endpoint (v0.2.0, in development)."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.auth import require_api_token
from app.api.concurrency_limit import hold_analysis_slot
from app.api.dossier_schemas import InvestigationDossierRequest, InvestigationDossierResponse
from app.api.rate_limit import SlidingWindowRateLimiter, get_rate_limiter
from app.api.schemas import ErrorResponse
from app.api.transactions import ANALYSIS_ERROR_RESPONSES, get_transaction_analysis_service
from app.services.investigation_dossier import investigate_dossier
from app.services.transaction_analysis import TransactionAnalysisService

router = APIRouter(
    tags=["investigations"],
    dependencies=[
        Depends(require_api_token),
        Depends(hold_analysis_slot, scope="function"),
    ],
)

_RESPONSES = {
    **ANALYSIS_ERROR_RESPONSES,
    429: {
        "model": ErrorResponse,
        "description": (
            "Shared quota of 30 units per 60 seconds exceeded; this route atomically "
            "uses one unit per transaction hash, never per address. See Retry-After."
        ),
    },
}


@router.post(
    "/investigations/dossier",
    response_model=InvestigationDossierResponse,
    responses=_RESPONSES,
    summary="Build a factual dossier for 2 to 5 addresses from supplied transactions",
)
def investigation_dossier_endpoint(
    request: InvestigationDossierRequest,
    service: Annotated[TransactionAnalysisService, Depends(get_transaction_analysis_service)],
    limiter: Annotated[SlidingWindowRateLimiter, Depends(get_rate_limiter)],
) -> InvestigationDossierResponse:
    """Inspect each hash once, then reuse the address and relationship engines."""
    limiter.acquire(cost=len(request.tx_hashes))
    dossier = investigate_dossier(
        service, request.network, request.addresses, request.tx_hashes
    )
    return InvestigationDossierResponse.from_domain(dossier)
