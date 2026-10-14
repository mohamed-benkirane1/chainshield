"""Multi-address factual dossier over a shared set of transaction inspections.

Each supplied transaction is inspected once.  The resulting application-level
snapshot is then projected through the existing address-investigation and USDT
relationship-graph builders.  It is not claimed to be an atomic blockchain
snapshot, and no history, ownership, risk or economic payment is inferred.
"""

from collections.abc import Sequence
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, StrictStr, model_validator

from app.domain.analysis_input import Network, normalize_transaction_hash
from app.domain.usdt_registry import normalize_contract_address
from app.services.address_investigation import (
    AddressInvestigation,
    TransferCoverage,
    build_address_investigation,
)
from app.services.transaction_analysis import TransactionInspection
from app.services.usdt_relationships import (
    MAX_RELATIONSHIP_TRANSACTIONS,
    RelationshipTransaction,
    UsdtRelationshipGraph,
    build_usdt_relationship_graph,
)

MIN_DOSSIER_ADDRESSES = 2
MAX_DOSSIER_ADDRESSES = 5

_Count = Annotated[int, Field(ge=0)]
_Amount = Annotated[int, Field(ge=0)]


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SelectedAddressRelationship(_StrictFrozenModel):
    """One known directed USDT relation whose endpoints are both selected."""

    from_address: StrictStr
    to_address: StrictStr
    self_transfer: bool
    event_count: Annotated[int, Field(ge=1)]
    total_amount_atomic: _Amount
    tx_hashes: tuple[StrictStr, ...] = Field(min_length=1)
    event_ids: tuple[StrictStr, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_consistency(self) -> "SelectedAddressRelationship":
        if self.self_transfer != (self.from_address == self.to_address):
            raise ValueError("self_transfer must identify an address self-loop")
        if len(self.event_ids) != self.event_count or len(set(self.event_ids)) != len(
            self.event_ids
        ):
            raise ValueError("event_ids must uniquely identify every aggregated event")
        if len(set(self.tx_hashes)) != len(self.tx_hashes):
            raise ValueError("tx_hashes must be distinct")
        return self


def select_address_relationships(
    graph: UsdtRelationshipGraph, addresses: Sequence[str]
) -> tuple[SelectedAddressRelationship, ...] | None:
    """Filter known graph relationships to selected endpoints. Pure, no I/O."""
    if graph.transfer_coverage is TransferCoverage.NONE:
        return None
    selected = set(addresses)
    event_ids_by_pair: dict[tuple[str, str], list[str]] = {}
    for edge in graph.edges or ():
        pair = (edge.from_address, edge.to_address)
        if edge.from_address in selected and edge.to_address in selected:
            event_ids_by_pair.setdefault(pair, []).append(edge.event_id)

    relationships = []
    for relationship in graph.grouped_relationships or ():
        pair = (relationship.from_address, relationship.to_address)
        if relationship.from_address not in selected or relationship.to_address not in selected:
            continue
        relationships.append(
            SelectedAddressRelationship(
                from_address=relationship.from_address,
                to_address=relationship.to_address,
                self_transfer=relationship.from_address == relationship.to_address,
                event_count=relationship.event_count,
                total_amount_atomic=relationship.total_amount_atomic,
                tx_hashes=relationship.tx_hashes,
                event_ids=tuple(event_ids_by_pair[pair]),
            )
        )
    return tuple(sorted(relationships, key=lambda item: (item.from_address, item.to_address)))


class InvestigationDossier(_StrictFrozenModel):
    """Multi-address findings and selected relationships from one inspection set."""

    network: Network
    sample_scope: Literal["supplied_transactions_only"]
    addresses: tuple[StrictStr, ...] = Field(
        min_length=MIN_DOSSIER_ADDRESSES, max_length=MAX_DOSSIER_ADDRESSES
    )
    transactions: tuple[RelationshipTransaction, ...] = Field(
        min_length=1, max_length=MAX_RELATIONSHIP_TRANSACTIONS
    )
    transfer_coverage: TransferCoverage
    address_findings: tuple[AddressInvestigation, ...] = Field(
        min_length=MIN_DOSSIER_ADDRESSES, max_length=MAX_DOSSIER_ADDRESSES
    )
    selected_address_relationships: tuple[SelectedAddressRelationship, ...] | None
    observed_selected_relationship_count: _Count | None
    # Internal provenance used to make the dossier model self-validating. It
    # is deliberately excluded from dumps and never appears in the public API.
    relationship_graph: UsdtRelationshipGraph = Field(exclude=True, repr=False)

    @model_validator(mode="after")
    def _check_consistency(self) -> "InvestigationDossier":
        normalized = tuple(normalize_contract_address(self.network, value) for value in self.addresses)
        if normalized != self.addresses or len(set(self.addresses)) != len(self.addresses):
            raise ValueError("addresses must be canonical and distinct")

        hashes = [transaction.tx_hash for transaction in self.transactions]
        if [normalize_transaction_hash(self.network, value) for value in hashes] != hashes:
            raise ValueError("transaction hashes must be canonical")
        if len(set(hashes)) != len(hashes):
            raise ValueError("transaction hashes must be distinct")
        graph = self.relationship_graph
        if (
            graph.network is not self.network
            or graph.sample_scope != self.sample_scope
            or graph.transactions != self.transactions
            or graph.transfer_coverage is not self.transfer_coverage
        ):
            raise ValueError("relationship graph must match the dossier snapshot")

        if tuple(finding.address for finding in self.address_findings) != self.addresses:
            raise ValueError("address findings must follow the selected address order")
        for finding in self.address_findings:
            if (
                finding.network is not self.network
                or finding.sample_scope != self.sample_scope
                or finding.summary.transfer_coverage is not self.transfer_coverage
            ):
                raise ValueError("address findings must match the dossier scope and coverage")
            projected = tuple(
                (
                    transaction.tx_hash,
                    transaction.transaction_status,
                    transaction.transfer_data_available,
                )
                for transaction in finding.transactions
            )
            expected = tuple(
                (
                    transaction.tx_hash,
                    transaction.transaction_status,
                    transaction.transfer_data_available,
                )
                for transaction in self.transactions
            )
            if projected != expected:
                raise ValueError("address findings must use the dossier transactions")

        expected_relationships = select_address_relationships(graph, self.addresses)
        if self.selected_address_relationships != expected_relationships:
            raise ValueError("selected relationships must exactly match graph events")
        if expected_relationships is None:
            if self.observed_selected_relationship_count is not None:
                raise ValueError("relationship count is unknown when transfer coverage is none")
        elif self.observed_selected_relationship_count != len(expected_relationships):
            raise ValueError("relationship count must match selected relationships")
        return self


def build_investigation_dossier(
    network: Network,
    addresses: Sequence[str],
    inspections: Sequence[TransactionInspection],
) -> InvestigationDossier:
    """Build all dossier projections from the same already-obtained inspections."""
    canonical_addresses = tuple(normalize_contract_address(network, value) for value in addresses)
    if not MIN_DOSSIER_ADDRESSES <= len(canonical_addresses) <= MAX_DOSSIER_ADDRESSES:
        raise ValueError(
            f"between {MIN_DOSSIER_ADDRESSES} and {MAX_DOSSIER_ADDRESSES} addresses"
        )
    if len(set(canonical_addresses)) != len(canonical_addresses):
        raise ValueError("duplicate addresses")
    if not 1 <= len(inspections) <= MAX_RELATIONSHIP_TRANSACTIONS:
        raise ValueError(f"between 1 and {MAX_RELATIONSHIP_TRANSACTIONS} transactions")
    if any(inspection.network is not network for inspection in inspections):
        raise ValueError("every inspection must use the dossier network")

    snapshot = tuple(inspections)
    graph = build_usdt_relationship_graph(network, snapshot)
    findings = tuple(
        build_address_investigation(network, address, snapshot)
        for address in canonical_addresses
    )
    relationships = select_address_relationships(graph, canonical_addresses)
    return InvestigationDossier(
        network=network,
        sample_scope="supplied_transactions_only",
        addresses=canonical_addresses,
        transactions=graph.transactions,
        transfer_coverage=graph.transfer_coverage,
        address_findings=findings,
        selected_address_relationships=relationships,
        observed_selected_relationship_count=(
            None if relationships is None else len(relationships)
        ),
        relationship_graph=graph,
    )


class TransactionInspector(Protocol):
    def inspect_transaction(
        self, network: Network | str, tx_hash: str
    ) -> TransactionInspection: ...


def investigate_dossier(
    service: TransactionInspector,
    network: Network,
    addresses: Sequence[str],
    tx_hashes: Sequence[str],
) -> InvestigationDossier:
    """Validate every input, inspect each hash once in order, then build the dossier."""
    canonical_addresses = tuple(normalize_contract_address(network, value) for value in addresses)
    hashes = tuple(normalize_transaction_hash(network, value) for value in tx_hashes)
    if not MIN_DOSSIER_ADDRESSES <= len(canonical_addresses) <= MAX_DOSSIER_ADDRESSES:
        raise ValueError(
            f"between {MIN_DOSSIER_ADDRESSES} and {MAX_DOSSIER_ADDRESSES} addresses"
        )
    if not 1 <= len(hashes) <= MAX_RELATIONSHIP_TRANSACTIONS:
        raise ValueError(f"between 1 and {MAX_RELATIONSHIP_TRANSACTIONS} transactions")
    if len(set(canonical_addresses)) != len(canonical_addresses):
        raise ValueError("duplicate addresses")
    if len(set(hashes)) != len(hashes):
        raise ValueError("duplicate transaction hashes")
    inspections = tuple(service.inspect_transaction(network, tx_hash) for tx_hash in hashes)
    return build_investigation_dossier(network, canonical_addresses, inspections)
