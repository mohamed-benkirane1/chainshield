"""Strict public JSON contract for directed USDT relationship paths."""

from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from app.api.relationship_schemas import (
    RelationshipTransactionView,
    UsdtRelationshipsRequest,
)
from app.api.schemas import DecimalString, SafeInteger, _ResponseModel, _safe_int
from app.domain.analysis_input import Network
from app.domain.usdt_registry import normalize_contract_address
from app.services.address_investigation import TransferCoverage
from app.services.relationship_paths import (
    MAX_RETURNED_PATHS,
    ConnectionStatus,
    PathLeg,
    RelationshipPath,
    RelationshipPathAnalysis,
)

_RawAddress = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class RelationshipPathsRequest(UsdtRelationshipsRequest):
    """Addresses and supplied transactions used for a bounded path search."""

    source_address: _RawAddress = Field(description="Start address of the directed path.")
    target_address: _RawAddress = Field(description="End address of the directed path.")

    @model_validator(mode="after")
    def _normalize_addresses(self) -> "RelationshipPathsRequest":
        self.source_address = normalize_contract_address(self.network, self.source_address)
        self.target_address = normalize_contract_address(self.network, self.target_address)
        if self.source_address == self.target_address:
            raise ValueError("source_address and target_address must be distinct")
        return self


class PathLegView(_ResponseModel):
    from_address: str
    to_address: str
    event_count: SafeInteger = Field(description="Number of observed events in this relation.")
    total_amount_atomic: DecimalString = Field(
        description="Exact sum for this leg only; never an end-to-end path amount."
    )
    tx_hashes: list[str] = Field(
        min_length=1,
        description="Distinct supplied transactions containing this relation, in input order."
    )
    event_ids: list[str] = Field(
        min_length=1,
        description="Identifiers of every observed graph edge aggregated into this leg."
    )

    @classmethod
    def from_domain(cls, leg: PathLeg) -> "PathLegView":
        return cls(
            from_address=leg.from_address,
            to_address=leg.to_address,
            event_count=_safe_int(leg.event_count),
            total_amount_atomic=str(leg.total_amount_atomic),
            tx_hashes=list(leg.tx_hashes),
            event_ids=list(leg.event_ids),
        )


class RelationshipPathView(_ResponseModel):
    hop_count: Literal[1, 2]
    addresses: list[str] = Field(
        min_length=2, max_length=3, description="Ordered canonical addresses along the path."
    )
    legs: list[PathLegView] = Field(
        min_length=1,
        max_length=2,
        description=(
            "Observed directed relations. Two legs establish topology only, not chronology, "
            "causality or movement of the same funds."
        )
    )

    @classmethod
    def from_domain(cls, path: RelationshipPath) -> "RelationshipPathView":
        return cls(
            hop_count=path.hop_count,
            addresses=list(path.addresses),
            legs=[PathLegView.from_domain(leg) for leg in path.legs],
        )


class RelationshipPathAnalysisResponse(_ResponseModel):
    network: Network
    source_address: str = Field(description="Canonical path origin.")
    target_address: str = Field(description="Canonical path destination.")
    sample_scope: Literal["supplied_transactions_only"] = Field(
        description="Only supplied transactions were inspected; no history was explored."
    )
    transfer_coverage: TransferCoverage = Field(
        description=(
            "complete: all supplied transaction events are known; partial: only some are "
            "known; none: connectivity is unknown."
        )
    )
    transactions: list[RelationshipTransactionView]
    connection_status: ConnectionStatus = Field(
        description="Factual path-observation status within the supplied sample."
    )
    observed_path_count: SafeInteger | None = Field(
        description="Total observable direct/two-hop paths; null when coverage is none."
    )
    truncated: bool = Field(
        description="True when more than the first 50 deterministically ordered paths exist."
    )
    paths: list[RelationshipPathView] | None = Field(
        max_length=MAX_RETURNED_PATHS,
        description=(
            "Direct path first, then two-hop paths by canonical intermediate address; "
            "null when coverage is none and [] when no path was observed in known data."
        )
    )

    @classmethod
    def from_domain(cls, analysis: RelationshipPathAnalysis) -> "RelationshipPathAnalysisResponse":
        return cls(
            network=analysis.network,
            source_address=analysis.source_address,
            target_address=analysis.target_address,
            sample_scope=analysis.sample_scope,
            transfer_coverage=analysis.transfer_coverage,
            transactions=[
                RelationshipTransactionView.from_domain(transaction)
                for transaction in analysis.transactions
            ],
            connection_status=analysis.connection_status,
            observed_path_count=_safe_int(analysis.observed_path_count),
            truncated=analysis.truncated,
            paths=(
                None
                if analysis.paths is None
                else [RelationshipPathView.from_domain(path) for path in analysis.paths]
            ),
        )
