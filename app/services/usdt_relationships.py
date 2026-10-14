"""Factual USDT relationship graph over a few supplied transactions.

Every edge is one official USDT ``Transfer`` event already present in a
``TransactionInspection``.  Nothing is discovered or inferred: the graph is
not a wallet history, an entity graph, a balance, a causal graph or a fraud
finding.  Aggregates group observed events without merging or netting them.

Unknown is never zero.  Pending, unconfirmed and not-found transactions have
unknown transfer data and contribute no invented edge.  If no supplied
transaction has known transfer data, all graph collections and the known
total are ``None``.
"""

from collections.abc import Sequence
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, StrictStr, model_validator

from app.domain.analysis_input import Network, normalize_transaction_hash
from app.domain.token_transfer import MAX_UINT256
from app.domain.usdt_registry import get_usdt_contract, normalize_contract_address
from app.providers.base import TransactionStatus
from app.services.address_investigation import (
    MAX_INVESTIGATED_TRANSACTIONS,
    TransferCoverage,
)
from app.services.transaction_analysis import FINAL_STATUSES, TransactionInspection

MAX_RELATIONSHIP_TRANSACTIONS = MAX_INVESTIGATED_TRANSACTIONS

_Count = Annotated[int, Field(ge=0)]
_Amount = Annotated[int, Field(ge=0)]  # a sum of uint256 values may exceed uint256


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RelationshipTransaction(_StrictFrozenModel):
    """Transfer-data coverage for one supplied transaction."""

    tx_hash: StrictStr
    transaction_status: TransactionStatus
    transfer_data_available: bool
    usdt_event_count: _Count | None

    @model_validator(mode="after")
    def _check_consistency(self) -> "RelationshipTransaction":
        known = self.transaction_status in FINAL_STATUSES
        if self.transfer_data_available != known or (self.usdt_event_count is not None) != known:
            raise ValueError("USDT event count is known only for a final transaction")
        return self


class RelationshipNode(_StrictFrozenModel):
    """One canonical address observed as sender or recipient of a known event."""

    address: StrictStr


def relationship_event_id(network: Network, tx_hash: str, event_position: int) -> str:
    """Stable identifier for one event in the inspection's ordered transfer list."""
    return f"{network.value}:{tx_hash}:{event_position}"


class RelationshipEdge(_StrictFrozenModel):
    """One observed official USDT Transfer event; never an inferred payment."""

    event_id: StrictStr
    network: Network
    tx_hash: StrictStr
    event_position: _Count
    log_index: _Count | None
    from_address: StrictStr
    to_address: StrictStr
    amount_atomic: Annotated[int, Field(ge=0, le=MAX_UINT256)]
    token_contract: StrictStr

    @model_validator(mode="after")
    def _check_consistency(self) -> "RelationshipEdge":
        if normalize_transaction_hash(self.network, self.tx_hash) != self.tx_hash:
            raise ValueError("tx_hash must be canonical")
        for address in (self.from_address, self.to_address, self.token_contract):
            if normalize_contract_address(self.network, address) != address:
                raise ValueError("addresses must be canonical")
        if self.token_contract != get_usdt_contract(self.network).contract_address:
            raise ValueError("token_contract must be the official USDT contract")
        if self.network is Network.ETHEREUM and self.log_index is None:
            raise ValueError("Ethereum edges require the real log_index")
        if self.network is Network.TRON and self.log_index is not None:
            raise ValueError("TRON edges must not invent a log_index")
        if self.event_id != relationship_event_id(
            self.network, self.tx_hash, self.event_position
        ):
            raise ValueError("event_id must identify the ordered event")
        return self


class GroupedRelationship(_StrictFrozenModel):
    """Exact aggregate of known events for one directed address pair."""

    from_address: StrictStr
    to_address: StrictStr
    event_count: Annotated[int, Field(ge=1)]
    total_amount_atomic: _Amount
    tx_hashes: tuple[StrictStr, ...] = Field(min_length=1)


class UsdtRelationshipGraph(_StrictFrozenModel):
    """Observed event graph limited to the supplied transactions."""

    network: Network
    sample_scope: Literal["supplied_transactions_only"]
    transfer_coverage: TransferCoverage
    transactions: tuple[RelationshipTransaction, ...] = Field(
        min_length=1, max_length=MAX_RELATIONSHIP_TRANSACTIONS
    )
    nodes: tuple[RelationshipNode, ...] | None
    edges: tuple[RelationshipEdge, ...] | None
    grouped_relationships: tuple[GroupedRelationship, ...] | None
    known_total_usdt_amount_atomic: _Amount | None

    @model_validator(mode="after")
    def _check_consistency(self) -> "UsdtRelationshipGraph":
        hashes = [transaction.tx_hash for transaction in self.transactions]
        if [normalize_transaction_hash(self.network, value) for value in hashes] != hashes:
            raise ValueError("transaction hashes must be canonical")
        if len(set(hashes)) != len(hashes):
            raise ValueError("transaction hashes must be unique")

        known = sum(t.transfer_data_available for t in self.transactions)
        expected_coverage = (
            TransferCoverage.NONE
            if known == 0
            else TransferCoverage.COMPLETE
            if known == len(self.transactions)
            else TransferCoverage.PARTIAL
        )
        if self.transfer_coverage is not expected_coverage:
            raise ValueError("transfer_coverage does not match the transactions")

        graph_parts = (
            self.nodes,
            self.edges,
            self.grouped_relationships,
            self.known_total_usdt_amount_atomic,
        )
        if known == 0:
            if any(part is not None for part in graph_parts):
                raise ValueError("no graph exists when no transfer data is known")
            return self
        if any(part is None for part in graph_parts):
            raise ValueError("the graph must be present when transfer data is known")

        edges = self.edges or ()
        expected_nodes = tuple(
            RelationshipNode(address=address)
            for address in sorted(
                {address for edge in edges for address in (edge.from_address, edge.to_address)}
            )
        )
        if self.nodes != expected_nodes:
            raise ValueError("nodes must exactly match edge endpoints and be sorted")
        if any(edge.network is not self.network for edge in edges):
            raise ValueError("every edge must use the graph network")

        transaction_by_hash = {transaction.tx_hash: transaction for transaction in self.transactions}
        expected_edge_order: list[tuple[int, int]] = []
        seen_per_transaction: dict[str, int] = {tx_hash: 0 for tx_hash in hashes}
        for edge in edges:
            transaction = transaction_by_hash.get(edge.tx_hash)
            if transaction is None or not transaction.transfer_data_available:
                raise ValueError("an edge must belong to a known supplied transaction")
            position = seen_per_transaction[edge.tx_hash]
            if edge.event_position != position:
                raise ValueError("event positions must be contiguous from zero")
            seen_per_transaction[edge.tx_hash] += 1
            expected_edge_order.append((hashes.index(edge.tx_hash), edge.event_position))
        if expected_edge_order != sorted(expected_edge_order):
            raise ValueError("edges must follow transaction and event order")
        for transaction in self.transactions:
            if transaction.usdt_event_count is not None and (
                transaction.usdt_event_count != seen_per_transaction[transaction.tx_hash]
            ):
                raise ValueError("transaction event count must match the edges")

        expected_groups = group_relationship_edges(edges, hashes)
        if self.grouped_relationships != expected_groups:
            raise ValueError("grouped_relationships must exactly aggregate the edges")
        if self.known_total_usdt_amount_atomic != sum(edge.amount_atomic for edge in edges):
            raise ValueError("known total must exactly sum the edges")
        return self


def group_relationship_edges(
    edges: Sequence[RelationshipEdge], transaction_order: Sequence[str]
) -> tuple[GroupedRelationship, ...]:
    """Group without mutating, merging or netting the underlying events."""
    grouped: dict[tuple[str, str], list[RelationshipEdge]] = {}
    for edge in edges:
        grouped.setdefault((edge.from_address, edge.to_address), []).append(edge)
    rank = {tx_hash: index for index, tx_hash in enumerate(transaction_order)}
    relationships = []
    for (sender, recipient), events in sorted(grouped.items()):
        hashes = tuple(
            sorted({edge.tx_hash for edge in events}, key=lambda tx_hash: rank[tx_hash])
        )
        relationships.append(
            GroupedRelationship(
                from_address=sender,
                to_address=recipient,
                event_count=len(events),
                total_amount_atomic=sum(edge.amount_atomic for edge in events),
                tx_hashes=hashes,
            )
        )
    return tuple(relationships)


def build_usdt_relationship_graph(
    network: Network, inspections: Sequence[TransactionInspection]
) -> UsdtRelationshipGraph:
    """Build a graph from already inspected transactions. Pure, with no I/O."""
    if not 1 <= len(inspections) <= MAX_RELATIONSHIP_TRANSACTIONS:
        raise ValueError(f"between 1 and {MAX_RELATIONSHIP_TRANSACTIONS} transactions")
    if any(inspection.network is not network for inspection in inspections):
        raise ValueError("every inspection must use the graph network")

    transactions = tuple(
        RelationshipTransaction(
            tx_hash=inspection.tx_hash,
            transaction_status=inspection.transaction.status,
            transfer_data_available=inspection.usdt_transfers is not None,
            usdt_event_count=(
                None if inspection.usdt_transfers is None else len(inspection.usdt_transfers)
            ),
        )
        for inspection in inspections
    )
    known_count = sum(transaction.transfer_data_available for transaction in transactions)
    coverage = (
        TransferCoverage.NONE
        if known_count == 0
        else TransferCoverage.COMPLETE
        if known_count == len(transactions)
        else TransferCoverage.PARTIAL
    )
    if known_count == 0:
        return UsdtRelationshipGraph(
            network=network,
            sample_scope="supplied_transactions_only",
            transfer_coverage=coverage,
            transactions=transactions,
            nodes=None,
            edges=None,
            grouped_relationships=None,
            known_total_usdt_amount_atomic=None,
        )

    edges = tuple(
        RelationshipEdge(
            event_id=relationship_event_id(network, inspection.tx_hash, position),
            network=network,
            tx_hash=inspection.tx_hash,
            event_position=position,
            log_index=transfer.log_index,
            from_address=transfer.from_address,
            to_address=transfer.to_address,
            amount_atomic=transfer.amount_atomic,
            token_contract=transfer.token_contract,
        )
        for inspection in inspections
        for position, transfer in enumerate(inspection.usdt_transfers or ())
    )
    nodes = tuple(
        RelationshipNode(address=address)
        for address in sorted(
            {address for edge in edges for address in (edge.from_address, edge.to_address)}
        )
    )
    transaction_order = [transaction.tx_hash for transaction in transactions]
    return UsdtRelationshipGraph(
        network=network,
        sample_scope="supplied_transactions_only",
        transfer_coverage=coverage,
        transactions=transactions,
        nodes=nodes,
        edges=edges,
        grouped_relationships=group_relationship_edges(edges, transaction_order),
        known_total_usdt_amount_atomic=sum(edge.amount_atomic for edge in edges),
    )


class TransactionInspector(Protocol):
    def inspect_transaction(
        self, network: Network | str, tx_hash: str
    ) -> TransactionInspection: ...


def inspect_usdt_relationships(
    service: TransactionInspector, network: Network, tx_hashes: Sequence[str]
) -> UsdtRelationshipGraph:
    """Validate all inputs, inspect in order and fail fast on the first error."""
    hashes = [normalize_transaction_hash(network, value) for value in tx_hashes]
    if not 1 <= len(hashes) <= MAX_RELATIONSHIP_TRANSACTIONS:
        raise ValueError(f"between 1 and {MAX_RELATIONSHIP_TRANSACTIONS} transactions")
    if len(set(hashes)) != len(hashes):
        raise ValueError("duplicate transaction hashes")
    inspections = [service.inspect_transaction(network, tx_hash) for tx_hash in hashes]
    return build_usdt_relationship_graph(network, inspections)
