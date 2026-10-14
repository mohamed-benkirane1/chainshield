"""Public JSON contract of the address investigation endpoint.

The investigation covers only the transactions supplied by the client: it is
not the wallet's history, not a balance and not a fraud verdict. Amounts are
exact decimal strings (sums may exceed uint256); counts are JSON integers
within the safe range (helpers shared with ``app.api.schemas``).
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.api.schemas import DecimalString, SafeInteger, _decimal, _ResponseModel, _safe_int
from app.domain.analysis_input import Network, normalize_transaction_hash
from app.domain.usdt_registry import normalize_contract_address
from app.providers.base import TransactionStatus
from app.risk.address_evidence import ObservedRole
from app.services.address_investigation import (
    MAX_INVESTIGATED_TRANSACTIONS,
    AddressActivitySummary,
    AddressInvestigation,
    AddressPresence,
    AddressUsdtObservation,
    InvestigatedTransaction,
    TransferCoverage,
    UsdtDirection,
)

_RawText = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class AddressInvestigationRequest(BaseModel):
    """An address and 1 to 3 transactions of the same network to inspect."""

    model_config = ConfigDict(extra="forbid")

    network: Network
    address: _RawText = Field(description="EIP-55 or lowercase on Ethereum, Base58Check on TRON.")
    tx_hashes: list[_RawText] = Field(
        min_length=1,
        max_length=MAX_INVESTIGATED_TRANSACTIONS,
        description="1 to 3 distinct transaction hashes; each one uses one quota unit.",
    )

    @model_validator(mode="after")
    def _normalize(self) -> "AddressInvestigationRequest":
        self.address = normalize_contract_address(self.network, self.address)
        hashes = [normalize_transaction_hash(self.network, value) for value in self.tx_hashes]
        if len(set(hashes)) != len(hashes):
            raise ValueError("tx_hashes must be distinct")
        self.tx_hashes = hashes
        return self


class AddressUsdtObservationView(_ResponseModel):
    direction: UsdtDirection = Field(
        description="self_transfer: the address is both sender and recipient."
    )
    counterparty: str | None = Field(
        description="Other party of the event; null for a self-transfer. Not a link of control."
    )
    amount_atomic: DecimalString
    log_index: SafeInteger | None = Field(description="Ethereum log index; null on TRON.")

    @classmethod
    def from_domain(cls, observation: AddressUsdtObservation) -> "AddressUsdtObservationView":
        return cls(
            direction=observation.direction,
            counterparty=observation.counterparty,
            amount_atomic=str(observation.amount_atomic),
            log_index=_safe_int(observation.log_index),
        )


class InvestigatedTransactionView(_ResponseModel):
    tx_hash: str
    transaction_status: TransactionStatus
    presence: AddressPresence = Field(
        description="not_observed: absent from the inspected fields; never 'unrelated' or 'safe'."
    )
    observed_roles: list[ObservedRole]
    transfer_data_available: bool
    usdt_observations: list[AddressUsdtObservationView] | None = Field(
        description=(
            "Official USDT Transfer events involving the address, in event order. [] means "
            "the final transaction has none; null means unknown (pending, unconfirmed or "
            "not found), never zero."
        )
    )

    @classmethod
    def from_domain(cls, transaction: InvestigatedTransaction) -> "InvestigatedTransactionView":
        observations = transaction.usdt_observations
        return cls(
            tx_hash=transaction.tx_hash,
            transaction_status=transaction.transaction_status,
            presence=transaction.presence,
            observed_roles=list(transaction.observed_roles),
            transfer_data_available=transaction.transfer_data_available,
            usdt_observations=(
                None if observations is None
                else [AddressUsdtObservationView.from_domain(o) for o in observations]
            ),
        )


class AddressActivitySummaryView(_ResponseModel):
    transfer_coverage: TransferCoverage = Field(
        description=(
            "complete: USDT events known for every transaction; partial: for some only; "
            "none: for none, so no aggregate is reported."
        )
    )
    inspected_transaction_count: SafeInteger
    transactions_with_transfer_data: SafeInteger
    transactions_with_unknown_transfers: SafeInteger
    transactions_where_observed: SafeInteger
    incoming_usdt_event_count: SafeInteger | None = Field(
        description="Known events received, including self-transfers; null if none is known."
    )
    outgoing_usdt_event_count: SafeInteger | None = Field(
        description="Known events sent, including self-transfers; null if none is known."
    )
    self_transfer_count: SafeInteger | None = Field(
        description="Self-transfers, counted in both directions."
    )
    known_incoming_usdt_amount_atomic: DecimalString | None = Field(
        description="Sum of known incoming event amounts; not a balance or net volume."
    )
    known_outgoing_usdt_amount_atomic: DecimalString | None = Field(
        description="Sum of known outgoing event amounts; not a balance or net volume."
    )
    known_self_transfer_amount_atomic: DecimalString | None = Field(
        description="Part of both sums above that comes from self-transfers."
    )
    counterparties: list[str] | None = Field(
        description="Distinct other parties of the known events; no control is inferred."
    )

    @classmethod
    def from_domain(cls, summary: AddressActivitySummary) -> "AddressActivitySummaryView":
        return cls(
            transfer_coverage=summary.transfer_coverage,
            inspected_transaction_count=_safe_int(summary.inspected_transaction_count),
            transactions_with_transfer_data=_safe_int(summary.transactions_with_transfer_data),
            transactions_with_unknown_transfers=_safe_int(
                summary.transactions_with_unknown_transfers
            ),
            transactions_where_observed=_safe_int(summary.transactions_where_observed),
            incoming_usdt_event_count=_safe_int(summary.incoming_usdt_event_count),
            outgoing_usdt_event_count=_safe_int(summary.outgoing_usdt_event_count),
            self_transfer_count=_safe_int(summary.self_transfer_count),
            known_incoming_usdt_amount_atomic=_decimal(summary.known_incoming_usdt_amount_atomic),
            known_outgoing_usdt_amount_atomic=_decimal(summary.known_outgoing_usdt_amount_atomic),
            known_self_transfer_amount_atomic=_decimal(summary.known_self_transfer_amount_atomic),
            counterparties=None if summary.counterparties is None else list(summary.counterparties),
        )


class AddressInvestigationResponse(_ResponseModel):
    network: Network
    address: str = Field(description="Canonical form of the investigated address.")
    sample_scope: Literal["supplied_transactions_only"] = Field(
        description="Only the supplied transactions were inspected: not the wallet's history."
    )
    presence: AddressPresence
    transactions: list[InvestigatedTransactionView]
    summary: AddressActivitySummaryView

    @classmethod
    def from_domain(cls, investigation: AddressInvestigation) -> "AddressInvestigationResponse":
        return cls(
            network=investigation.network,
            address=investigation.address,
            sample_scope=investigation.sample_scope,
            presence=investigation.presence,
            transactions=[
                InvestigatedTransactionView.from_domain(t) for t in investigation.transactions
            ],
            summary=AddressActivitySummaryView.from_domain(investigation.summary),
        )
