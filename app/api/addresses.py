"""Address investigation endpoint (ChainShield v0.2.0)."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.address_schemas import AddressInvestigationRequest, AddressInvestigationResponse
from app.api.auth import require_api_token
from app.api.concurrency_limit import hold_analysis_slot
from app.api.rate_limit import SlidingWindowRateLimiter, get_rate_limiter
from app.api.schemas import ErrorResponse
from app.api.transactions import ANALYSIS_ERROR_RESPONSES, get_transaction_analysis_service
from app.services.address_investigation import investigate_address
from app.services.transaction_analysis import TransactionAnalysisService

# Authentication, then a concurrent-analysis slot held for the whole
# investigation. The shared rate limit is NOT a router dependency here: the
# endpoint charges one unit per supplied hash itself, once the body is valid,
# so an investigation is never charged an extra standard admission.
router = APIRouter(
    tags=["addresses"],
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
            "Shared quota of 30 units per 60 seconds exceeded; this route uses one unit "
            "per transaction hash. See Retry-After."
        ),
    },
}


@router.post(
    "/addresses/investigate",
    response_model=AddressInvestigationResponse,
    responses=_RESPONSES,
    summary="Summarize an address's observed activity in 1 to 3 supplied transactions",
)
def investigate_address_endpoint(
    request: AddressInvestigationRequest,
    service: Annotated[TransactionAnalysisService, Depends(get_transaction_analysis_service)],
    limiter: Annotated[SlidingWindowRateLimiter, Depends(get_rate_limiter)],
) -> AddressInvestigationResponse:
    """Factual summary over the supplied transactions only. Not a wallet history,
    balance, score or fraud verdict.

    Each supplied hash consumes one unit of the shared quota, all at once and
    before any provider call. Fail-fast: if any inspection fails, the whole
    request fails with that safe error and no partial result is returned.
    Synchronous for the same reason as ``/transactions/inspect``.
    """
    limiter.acquire(cost=len(request.tx_hashes))
    investigation = investigate_address(
        service, request.network, request.address, request.tx_hashes
    )
    return AddressInvestigationResponse.from_domain(investigation)
