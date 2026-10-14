"""Strict public JSON contract for the multi-address investigation dossier."""

from typing import Annotated, Literal

from pydantic import Field, StringConstraints, model_validator

from app.api.address_schemas import (
    AddressActivitySummaryView,
    InvestigatedTransactionView,
)
from app.api.relationship_schemas import (
    RelationshipTransactionView,
    UsdtRelationshipsRequest,
)
from app.api.schemas import DecimalString, SafeInteger, _ResponseModel, _safe_int
from app.domain.analysis_input import Network
from app.domain.usdt_registry import normalize_contract_address
from app.services.address_investigation import AddressInvestigation, AddressPresence, TransferCoverage
from app.services.investigation_dossier import (
    MAX_DOSSIER_ADDRESSES,
    MIN_DOSSIER_ADDRESSES,
    InvestigationDossier,
    SelectedAddressRelationship,
)

_RawAddress = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class InvestigationDossierRequest(UsdtRelationshipsRequest):
    """Two to five addresses and one to three supplied transactions."""

    addresses: list[_RawAddress] = Field(
        min_length=MIN_DOSSIER_ADDRESSES,
        max_length=MAX_DOSSIER_ADDRESSES,
        description="2 to 5 distinct addresses, normalized to canonical form.",
    )

    @model_validator(mode="after")
    def _normalize_addresses(self) -> "InvestigationDossierRequest":
        addresses = [normalize_contract_address(self.network, value) for value in self.addresses]
        if len(set(addresses)) != len(addresses):
            raise ValueError("addresses must be distinct")
        self.addresses = addresses
        return self


class DossierAddressFindingView(_ResponseModel):
    address: str = Field(description="Canonical selected address.")
    presence: AddressPresence = Field(
        description="not_observed means absent from inspectable fields, never unrelated."
    )
    transactions: list[InvestigatedTransactionView] = Field(
        description="Observed roles and official USDT events for each supplied transaction."
    )
    summary: AddressActivitySummaryView

    @classmethod
    def from_domain(cls, finding: AddressInvestigation) -> "DossierAddressFindingView":
        return cls(
            address=finding.address,
            presence=finding.presence,
            transactions=[
                InvestigatedTransactionView.from_domain(transaction)
                for transaction in finding.transactions
            ],
            summary=AddressActivitySummaryView.from_domain(finding.summary),
        )


class SelectedAddressRelationshipView(_ResponseModel):
    from_address: str
    to_address: str
    self_transfer: bool = Field(description="True exactly for an observed A -> A self-loop.")
    event_count: SafeInteger
    total_amount_atomic: DecimalString = Field(
        description="Exact sum of observed event amounts; no netting or deduplication."
    )
    tx_hashes: list[str] = Field(
        min_length=1,
        description="Distinct supplied transactions containing this relation, in input order.",
    )
    event_ids: list[str] = Field(
        min_length=1,
        description="Exact identifiers of every graph edge aggregated into this relation.",
    )

    @classmethod
    def from_domain(
        cls, relationship: SelectedAddressRelationship
    ) -> "SelectedAddressRelationshipView":
        return cls(
            from_address=relationship.from_address,
            to_address=relationship.to_address,
            self_transfer=relationship.self_transfer,
            event_count=_safe_int(relationship.event_count),
            total_amount_atomic=str(relationship.total_amount_atomic),
            tx_hashes=list(relationship.tx_hashes),
            event_ids=list(relationship.event_ids),
        )


class InvestigationDossierResponse(_ResponseModel):
    network: Network
    sample_scope: Literal["supplied_transactions_only"] = Field(
        description="Only supplied transactions were inspected; no history was explored."
    )
    addresses: list[str] = Field(
        min_length=MIN_DOSSIER_ADDRESSES,
        max_length=MAX_DOSSIER_ADDRESSES,
        description="Canonical selected addresses, preserving request order.",
    )
    transactions: list[RelationshipTransactionView] = Field(
        min_length=1,
        max_length=3,
        description="Shared transaction statuses and USDT-data availability.",
    )
    transfer_coverage: TransferCoverage
    address_findings: list[DossierAddressFindingView] = Field(
        min_length=MIN_DOSSIER_ADDRESSES,
        max_length=MAX_DOSSIER_ADDRESSES,
        description="One reused address investigation per selected address, in request order.",
    )
    selected_address_relationships: list[SelectedAddressRelationshipView] | None = Field(
        description=(
            "Known directed USDT relations whose endpoints are both selected, sorted by pair; "
            "null when transfer coverage is none."
        )
    )
    observed_selected_relationship_count: SafeInteger | None = Field(
        description=(
            "Number of known selected directed relationship pairs; null when coverage is none."
        )
    )

    @classmethod
    def from_domain(cls, dossier: InvestigationDossier) -> "InvestigationDossierResponse":
        relationships = dossier.selected_address_relationships
        return cls(
            network=dossier.network,
            sample_scope=dossier.sample_scope,
            addresses=list(dossier.addresses),
            transactions=[
                RelationshipTransactionView.from_domain(transaction)
                for transaction in dossier.transactions
            ],
            transfer_coverage=dossier.transfer_coverage,
            address_findings=[
                DossierAddressFindingView.from_domain(finding)
                for finding in dossier.address_findings
            ],
            selected_address_relationships=(
                None
                if relationships is None
                else [
                    SelectedAddressRelationshipView.from_domain(relationship)
                    for relationship in relationships
                ]
            ),
            observed_selected_relationship_count=_safe_int(
                dossier.observed_selected_relationship_count
            ),
        )
