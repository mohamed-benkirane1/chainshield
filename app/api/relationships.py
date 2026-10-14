"""USDT relationship graph endpoint (ChainShield v0.2.0, in development)."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.auth import require_api_token
from app.api.concurrency_limit import hold_analysis_slot
from app.api.rate_limit import SlidingWindowRateLimiter, get_rate_limiter
from app.api.path_schemas import (
    RelationshipPathAnalysisResponse,
    RelationshipPathsRequest,
)
from app.api.relationship_schemas import (
    UsdtRelationshipGraphResponse,
    UsdtRelationshipsRequest,
)
from app.api.schemas import ErrorResponse
from app.api.transactions import ANALYSIS_ERROR_RESPONSES, get_transaction_analysis_service
from app.services.transaction_analysis import TransactionAnalysisService
from app.services.relationship_paths import analyze_relationship_paths
from app.services.usdt_relationships import inspect_usdt_relationships

router = APIRouter(
    tags=["relationships"],
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
            "uses one unit per transaction hash. See Retry-After."
        ),
    },
}


@router.post(
    "/relationships/usdt",
    response_model=UsdtRelationshipGraphResponse,
    responses=_RESPONSES,
    summary="Build a factual USDT event graph from 1 to 3 supplied transactions",
)
def usdt_relationships_endpoint(
    request: UsdtRelationshipsRequest,
    service: Annotated[TransactionAnalysisService, Depends(get_transaction_analysis_service)],
    limiter: Annotated[SlidingWindowRateLimiter, Depends(get_rate_limiter)],
) -> UsdtRelationshipGraphResponse:
    """No history exploration, ownership inference, scoring, netting or balance.

    The weighted quota is admitted once, atomically, after body validation and
    before the first provider call.  Inspection is ordered and fail-fast.
    """
    limiter.acquire(cost=len(request.tx_hashes))
    graph = inspect_usdt_relationships(service, request.network, request.tx_hashes)
    return UsdtRelationshipGraphResponse.from_domain(graph)


@router.post(
    "/relationships/paths",
    response_model=RelationshipPathAnalysisResponse,
    responses=_RESPONSES,
    summary="Find direct or two-hop directed USDT paths in supplied transactions",
)
def relationship_paths_endpoint(
    request: RelationshipPathsRequest,
    service: Annotated[TransactionAnalysisService, Depends(get_transaction_analysis_service)],
    limiter: Annotated[SlidingWindowRateLimiter, Depends(get_rate_limiter)],
) -> RelationshipPathAnalysisResponse:
    """Inspect once, build the existing graph, then perform a pure bounded search."""
    limiter.acquire(cost=len(request.tx_hashes))
    graph = inspect_usdt_relationships(service, request.network, request.tx_hashes)
    analysis = analyze_relationship_paths(
        graph, request.source_address, request.target_address
    )
    return RelationshipPathAnalysisResponse.from_domain(analysis)
