"""Pure directed path analysis over an existing USDT relationship graph.

Only direct paths and paths through one distinct intermediate address are
considered.  A path is a topological property of relationships observed in
the supplied transactions.  It does not establish chronology, causality,
ownership, or that the same funds moved through both legs.
"""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, model_validator

from app.domain.analysis_input import Network, normalize_transaction_hash
from app.domain.usdt_registry import normalize_contract_address
from app.services.address_investigation import TransferCoverage
from app.services.usdt_relationships import (
    GroupedRelationship,
    RelationshipTransaction,
    UsdtRelationshipGraph,
)

MAX_HOPS = 2
MAX_RETURNED_PATHS = 50

_Count = Annotated[int, Field(ge=0)]
_Amount = Annotated[int, Field(ge=0)]


class ConnectionStatus(StrEnum):
    """Factual status within the supplied sample, never a risk judgement."""

    OBSERVED = "path_observed"
    NOT_OBSERVED_COMPLETE = "no_path_observed_in_supplied_transactions"
    NOT_OBSERVED_PARTIAL = "no_path_observed_in_known_data"
    UNKNOWN = "connectivity_unknown"


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PathLeg(_StrictFrozenModel):
    """One aggregated directed relationship and its observed event provenance."""

    from_address: StrictStr
    to_address: StrictStr
    event_count: Annotated[int, Field(ge=1)]
    total_amount_atomic: _Amount
    tx_hashes: tuple[StrictStr, ...] = Field(min_length=1)
    event_ids: tuple[StrictStr, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_consistency(self) -> "PathLeg":
        if self.from_address == self.to_address:
            raise ValueError("a path leg cannot be a self-loop")
        if len(self.event_ids) != self.event_count or len(set(self.event_ids)) != len(
            self.event_ids
        ):
            raise ValueError("event_ids must uniquely identify every aggregated event")
        if len(set(self.tx_hashes)) != len(self.tx_hashes):
            raise ValueError("tx_hashes must be distinct")
        for event_id in self.event_ids:
            try:
                network, tx_hash, position = event_id.rsplit(":", 2)
            except ValueError:
                raise ValueError("event_ids must use the graph event identifier format") from None
            if network not in {item.value for item in Network} or tx_hash not in self.tx_hashes:
                raise ValueError("event_ids must refer to a leg transaction")
            if not position.isdecimal() or (len(position) > 1 and position.startswith("0")):
                raise ValueError("event_ids must contain a canonical event position")
        return self


class RelationshipPath(_StrictFrozenModel):
    """A direct or two-hop directed path in the observed relationship graph."""

    hop_count: Literal[1, 2]
    addresses: tuple[StrictStr, ...] = Field(min_length=2, max_length=3)
    legs: tuple[PathLeg, ...] = Field(min_length=1, max_length=MAX_HOPS)

    @model_validator(mode="after")
    def _check_consistency(self) -> "RelationshipPath":
        if len(self.legs) != self.hop_count or len(self.addresses) != self.hop_count + 1:
            raise ValueError("hop_count must match addresses and legs")
        if len(set(self.addresses)) != len(self.addresses):
            raise ValueError("path addresses must be distinct")
        for index, leg in enumerate(self.legs):
            if (leg.from_address, leg.to_address) != (
                self.addresses[index],
                self.addresses[index + 1],
            ):
                raise ValueError("legs must connect consecutive path addresses")
        return self


class RelationshipPathAnalysis(_StrictFrozenModel):
    """Bounded path result over the known part of a supplied-transaction graph."""

    network: Network
    source_address: StrictStr
    target_address: StrictStr
    sample_scope: Literal["supplied_transactions_only"]
    transfer_coverage: TransferCoverage
    transactions: tuple[RelationshipTransaction, ...] = Field(min_length=1, max_length=3)
    connection_status: ConnectionStatus
    observed_path_count: _Count | None
    truncated: bool
    paths: tuple[RelationshipPath, ...] | None

    @model_validator(mode="after")
    def _check_consistency(self) -> "RelationshipPathAnalysis":
        for address in (self.source_address, self.target_address):
            if normalize_contract_address(self.network, address) != address:
                raise ValueError("source and target addresses must be canonical")
        if self.source_address == self.target_address:
            raise ValueError("source and target addresses must be distinct")

        hashes = [transaction.tx_hash for transaction in self.transactions]
        if [normalize_transaction_hash(self.network, value) for value in hashes] != hashes:
            raise ValueError("transaction hashes must be canonical")
        if len(set(hashes)) != len(hashes):
            raise ValueError("transaction hashes must be distinct")
        known = sum(transaction.transfer_data_available for transaction in self.transactions)
        expected_coverage = (
            TransferCoverage.NONE
            if known == 0
            else TransferCoverage.COMPLETE
            if known == len(self.transactions)
            else TransferCoverage.PARTIAL
        )
        if self.transfer_coverage is not expected_coverage:
            raise ValueError("transfer_coverage must match the transactions")

        if self.transfer_coverage is TransferCoverage.NONE:
            if (
                self.connection_status is not ConnectionStatus.UNKNOWN
                or self.observed_path_count is not None
                or self.paths is not None
                or self.truncated
            ):
                raise ValueError("connectivity is unknown when no transfer data is known")
            return self

        if self.paths is None or self.observed_path_count is None:
            raise ValueError("known transfer data requires a path result")
        if len(self.paths) > MAX_RETURNED_PATHS:
            raise ValueError("too many returned paths")
        if len(self.paths) != min(self.observed_path_count, MAX_RETURNED_PATHS):
            raise ValueError("paths must contain every result up to the return limit")
        if self.truncated != (self.observed_path_count > len(self.paths)):
            raise ValueError("truncated must report omitted observable paths")
        if self.paths and self.connection_status is not ConnectionStatus.OBSERVED:
            raise ValueError("returned paths require the observed status")
        if not self.paths:
            expected_status = (
                ConnectionStatus.NOT_OBSERVED_COMPLETE
                if self.transfer_coverage is TransferCoverage.COMPLETE
                else ConnectionStatus.NOT_OBSERVED_PARTIAL
            )
            if self.connection_status is not expected_status or self.observed_path_count != 0:
                raise ValueError("empty paths require the coverage-specific absent status")
        for path in self.paths:
            if path.addresses[0] != self.source_address or path.addresses[-1] != self.target_address:
                raise ValueError("every path must connect source to target")
            for address in path.addresses:
                if normalize_contract_address(self.network, address) != address:
                    raise ValueError("every path address must be canonical")
            for leg in path.legs:
                for tx_hash in leg.tx_hashes:
                    if tx_hash not in hashes or normalize_transaction_hash(
                        self.network, tx_hash
                    ) != tx_hash:
                        raise ValueError("every leg transaction must be supplied and canonical")
                if any(
                    not event_id.startswith(f"{self.network.value}:")
                    for event_id in leg.event_ids
                ):
                    raise ValueError("every event_id must use the analysis network")
        if list(self.paths) != sorted(
            self.paths,
            key=lambda path: (path.hop_count, path.addresses[1] if path.hop_count == 2 else ""),
        ):
            raise ValueError("paths must be direct first, then sorted by intermediate address")
        return self


def _path_leg(
    relationship: GroupedRelationship,
    event_ids_by_pair: dict[tuple[str, str], tuple[str, ...]],
) -> PathLeg:
    pair = (relationship.from_address, relationship.to_address)
    return PathLeg(
        from_address=relationship.from_address,
        to_address=relationship.to_address,
        event_count=relationship.event_count,
        total_amount_atomic=relationship.total_amount_atomic,
        tx_hashes=relationship.tx_hashes,
        event_ids=event_ids_by_pair[pair],
    )


def analyze_relationship_paths(
    graph: UsdtRelationshipGraph,
    source_address: str,
    target_address: str,
) -> RelationshipPathAnalysis:
    """Find direct and two-hop paths without I/O or event combinations.

    Runtime is bounded by the existing aggregated relationships and edges.
    At most ``MAX_RETURNED_PATHS`` result models are built, while the total
    observable path count is computed from relation pairs.
    """
    source = normalize_contract_address(graph.network, source_address)
    target = normalize_contract_address(graph.network, target_address)
    if source == target:
        raise ValueError("source and target addresses must be distinct")

    if graph.transfer_coverage is TransferCoverage.NONE:
        return RelationshipPathAnalysis(
            network=graph.network,
            source_address=source,
            target_address=target,
            sample_scope=graph.sample_scope,
            transfer_coverage=graph.transfer_coverage,
            transactions=graph.transactions,
            connection_status=ConnectionStatus.UNKNOWN,
            observed_path_count=None,
            truncated=False,
            paths=None,
        )

    relationships = {
        (relationship.from_address, relationship.to_address): relationship
        for relationship in graph.grouped_relationships or ()
    }
    outgoing = {
        recipient
        for sender, recipient in relationships
        if sender == source and recipient not in (source, target)
    }
    incoming = {
        sender
        for sender, recipient in relationships
        if recipient == target and sender not in (source, target)
    }
    intermediates = sorted(outgoing & incoming)
    direct = relationships.get((source, target))
    observed_path_count = (1 if direct is not None else 0) + len(intermediates)

    event_ids_by_pair: dict[tuple[str, str], list[str]] = {}
    for edge in graph.edges or ():
        event_ids_by_pair.setdefault((edge.from_address, edge.to_address), []).append(
            edge.event_id
        )
    immutable_event_ids = {pair: tuple(ids) for pair, ids in event_ids_by_pair.items()}

    paths: list[RelationshipPath] = []
    if direct is not None:
        paths.append(
            RelationshipPath(
                hop_count=1,
                addresses=(source, target),
                legs=(_path_leg(direct, immutable_event_ids),),
            )
        )
    remaining = MAX_RETURNED_PATHS - len(paths)
    for intermediate in intermediates[:remaining]:
        first = relationships[(source, intermediate)]
        second = relationships[(intermediate, target)]
        paths.append(
            RelationshipPath(
                hop_count=2,
                addresses=(source, intermediate, target),
                legs=(
                    _path_leg(first, immutable_event_ids),
                    _path_leg(second, immutable_event_ids),
                ),
            )
        )

    if paths:
        status = ConnectionStatus.OBSERVED
    elif graph.transfer_coverage is TransferCoverage.COMPLETE:
        status = ConnectionStatus.NOT_OBSERVED_COMPLETE
    else:
        status = ConnectionStatus.NOT_OBSERVED_PARTIAL
    returned = tuple(paths)
    return RelationshipPathAnalysis(
        network=graph.network,
        source_address=source,
        target_address=target,
        sample_scope=graph.sample_scope,
        transfer_coverage=graph.transfer_coverage,
        transactions=graph.transactions,
        connection_status=status,
        observed_path_count=observed_path_count,
        truncated=observed_path_count > len(returned),
        paths=returned,
    )
