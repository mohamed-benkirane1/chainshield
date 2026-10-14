"""Strict public JSON contract for the supplied-transaction USDT graph."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.api.schemas import DecimalString, SafeInteger, _ResponseModel, _safe_int
from app.domain.analysis_input import Network, normalize_transaction_hash
from app.providers.base import TransactionStatus
from app.services.address_investigation import TransferCoverage
from app.services.usdt_relationships import (
    MAX_RELATIONSHIP_TRANSACTIONS,
    GroupedRelationship,
    RelationshipEdge,
    RelationshipNode,
    RelationshipTransaction,
    UsdtRelationshipGraph,
)

_RawHash = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class UsdtRelationshipsRequest(BaseModel):
    """One network and 1 to 3 distinct transaction hashes to inspect."""

    model_config = ConfigDict(extra="forbid")

    network: Network = Field(description="Supported network: ethereum or tron.")
    tx_hashes: list[_RawHash] = Field(
        min_length=1,
        max_length=MAX_RELATIONSHIP_TRANSACTIONS,
        description="1 to 3 distinct hashes; each hash consumes one shared quota unit.",
    )

    @model_validator(mode="after")
    def _normalize(self) -> "UsdtRelationshipsRequest":
        hashes = [normalize_transaction_hash(self.network, value) for value in self.tx_hashes]
        if len(set(hashes)) != len(hashes):
            raise ValueError("tx_hashes must be distinct")
        self.tx_hashes = hashes
        return self


class RelationshipTransactionView(_ResponseModel):
    tx_hash: str
    transaction_status: TransactionStatus
    transfer_data_available: bool
    usdt_event_count: SafeInteger | None = Field(
        description=(
            "Number of known official USDT events; null for pending, unconfirmed or "
            "not-found transactions, where events are unknown rather than zero."
        )
    )

    @classmethod
    def from_domain(cls, transaction: RelationshipTransaction) -> "RelationshipTransactionView":
        return cls(
            tx_hash=transaction.tx_hash,
            transaction_status=transaction.transaction_status,
            transfer_data_available=transaction.transfer_data_available,
            usdt_event_count=_safe_int(transaction.usdt_event_count),
        )


class RelationshipNodeView(_ResponseModel):
    address: str = Field(description="Canonical event sender or recipient address.")

    @classmethod
    def from_domain(cls, node: RelationshipNode) -> "RelationshipNodeView":
        return cls(address=node.address)


class RelationshipEdgeView(_ResponseModel):
    event_id: str = Field(
        description="Deterministic network:transaction-hash:event-position identifier."
    )
    network: Network
    tx_hash: str
    event_position: SafeInteger = Field(
        description="Zero-based position in this transaction's ordered USDT event list."
    )
    log_index: SafeInteger | None = Field(
        description="Real Ethereum log index; null on TRON (never synthesized)."
    )
    from_address: str
    to_address: str
    amount_atomic: DecimalString = Field(
        description="Exact event amount in USDT atomic units, serialized without a float."
    )
    token_contract: str = Field(description="Canonical official USDT contract address.")

    @classmethod
    def from_domain(cls, edge: RelationshipEdge) -> "RelationshipEdgeView":
        return cls(
            event_id=edge.event_id,
            network=edge.network,
            tx_hash=edge.tx_hash,
            event_position=_safe_int(edge.event_position),
            log_index=_safe_int(edge.log_index),
            from_address=edge.from_address,
            to_address=edge.to_address,
            amount_atomic=str(edge.amount_atomic),
            token_contract=edge.token_contract,
        )


class GroupedRelationshipView(_ResponseModel):
    from_address: str
    to_address: str
    event_count: SafeInteger = Field(description="Number of underlying observed events.")
    total_amount_atomic: DecimalString = Field(
        description="Exact sum of event amounts; no netting or economic deduplication."
    )
    tx_hashes: list[str] = Field(
        description="Distinct supplied transactions containing this directed pair, in input order."
    )

    @classmethod
    def from_domain(cls, relationship: GroupedRelationship) -> "GroupedRelationshipView":
        return cls(
            from_address=relationship.from_address,
            to_address=relationship.to_address,
            event_count=_safe_int(relationship.event_count),
            total_amount_atomic=str(relationship.total_amount_atomic),
            tx_hashes=list(relationship.tx_hashes),
        )


class UsdtRelationshipGraphResponse(_ResponseModel):
    network: Network
    sample_scope: Literal["supplied_transactions_only"] = Field(
        description="Only supplied transactions were inspected; this is not wallet history."
    )
    transfer_coverage: TransferCoverage = Field(
        description=(
            "complete: every transaction's events are known; partial: some are unknown; "
            "none: all are unknown and graph fields are null."
        )
    )
    transactions: list[RelationshipTransactionView]
    nodes: list[RelationshipNodeView] | None = Field(
        description=(
            "Unique event endpoints, sorted lexicographically by canonical address; "
            "null only when coverage is none."
        )
    )
    edges: list[RelationshipEdgeView] | None = Field(
        description=(
            "Individual observed events in supplied-transaction then event order; null only "
            "when coverage is none. A routed transfer can yield several events."
        )
    )
    grouped_relationships: list[GroupedRelationshipView] | None = Field(
        description=(
            "Directed pair aggregates sorted by from_address then to_address; underlying "
            "edges remain present for audit."
        )
    )
    known_total_usdt_amount_atomic: DecimalString | None = Field(
        description=(
            "Exact sum of known event amounts, not a balance or net flow; null when every "
            "transaction's transfer data is unknown."
        )
    )

    @classmethod
    def from_domain(cls, graph: UsdtRelationshipGraph) -> "UsdtRelationshipGraphResponse":
        return cls(
            network=graph.network,
            sample_scope=graph.sample_scope,
            transfer_coverage=graph.transfer_coverage,
            transactions=[RelationshipTransactionView.from_domain(t) for t in graph.transactions],
            nodes=(
                None if graph.nodes is None
                else [RelationshipNodeView.from_domain(node) for node in graph.nodes]
            ),
            edges=(
                None if graph.edges is None
                else [RelationshipEdgeView.from_domain(edge) for edge in graph.edges]
            ),
            grouped_relationships=(
                None if graph.grouped_relationships is None
                else [
                    GroupedRelationshipView.from_domain(relationship)
                    for relationship in graph.grouped_relationships
                ]
            ),
            known_total_usdt_amount_atomic=(
                None
                if graph.known_total_usdt_amount_atomic is None
                else str(graph.known_total_usdt_amount_atomic)
            ),
        )
