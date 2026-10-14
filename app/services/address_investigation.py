"""Factual summary of one address's activity in a few supplied transactions.

An analyst supplies an address and 1 to 3 transaction hashes of the same
network. Each transaction is inspected with ``TransactionAnalysisService`` and
the address's observed roles and official USDT ``Transfer`` events are
summarized.

Scope: only the supplied transactions. Nothing is discovered: this is not the
wallet's history, not a balance, and the sums are NOT a net or deduplicated
economic volume (the same USDT can appear in several events). Nothing is
inferred about who controls an address.

Unknown is never zero: for a ``pending``, ``unconfirmed`` or ``not_found``
transaction the USDT events are not observable, so its observations are
``None``. Aggregates cover only the transactions whose events are known
(``transfer_coverage``), and are ``None`` when none is known.

A self-transfer (sender and recipient are the address) belongs to both
directions: it is counted in the incoming AND the outgoing counts and known
amounts, and reported separately so it can be subtracted.

``not_observed`` only means that the address does not appear in the fields
that could be inspected; it never means "unrelated" or "safe".

Fail-fast: if any inspection fails, the whole investigation fails with that
error. No partial result is ever returned.
"""

from collections.abc import Iterable, Sequence
from enum import StrEnum
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, StrictStr, model_validator

from app.domain.analysis_input import Network, normalize_transaction_hash
from app.domain.token_transfer import MAX_UINT256
from app.domain.usdt_registry import normalize_contract_address
from app.providers.base import TransactionStatus
from app.risk.address_evidence import ObservedRole, observed_address_roles
from app.services.transaction_analysis import FINAL_STATUSES, TransactionInspection

MAX_INVESTIGATED_TRANSACTIONS = 3

_Count = Annotated[int, Field(ge=0)]
_Amount = Annotated[int, Field(ge=0)]  # a sum of uint256 values may exceed uint256


class AddressPresence(StrEnum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"  # not in the inspected fields; never "unrelated"


class UsdtDirection(StrEnum):
    INCOMING = "incoming"  # the address is the recipient only
    OUTGOING = "outgoing"  # the address is the sender only
    SELF_TRANSFER = "self_transfer"  # the address is both sender and recipient


class TransferCoverage(StrEnum):
    COMPLETE = "complete"  # USDT events known for every inspected transaction
    PARTIAL = "partial"  # known for some transactions only
    NONE = "none"  # known for none of them: no aggregate is reported


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _canonical_roles(roles: Iterable[ObservedRole]) -> tuple[ObservedRole, ...]:
    present = set(roles)
    return tuple(role for role in ObservedRole if role in present)


class AddressUsdtObservation(_StrictFrozenModel):
    """One official USDT Transfer event involving the investigated address."""

    direction: UsdtDirection
    counterparty: StrictStr | None  # the other party; None for a self-transfer
    amount_atomic: Annotated[int, Field(ge=0, le=MAX_UINT256)]
    log_index: Annotated[int, Field(ge=0)] | None  # None on TRON

    @model_validator(mode="after")
    def _check_counterparty(self) -> "AddressUsdtObservation":
        if (self.direction is UsdtDirection.SELF_TRANSFER) != (self.counterparty is None):
            raise ValueError("only a self-transfer has no counterparty")
        return self


class InvestigatedTransaction(_StrictFrozenModel):
    """What one supplied transaction shows about the investigated address."""

    tx_hash: StrictStr
    transaction_status: TransactionStatus
    presence: AddressPresence
    observed_roles: tuple[ObservedRole, ...]
    transfer_data_available: bool
    usdt_observations: tuple[AddressUsdtObservation, ...] | None

    @model_validator(mode="after")
    def _check_consistency(self) -> "InvestigatedTransaction":
        if self.observed_roles != _canonical_roles(self.observed_roles):
            raise ValueError("observed_roles must be unique and in canonical order")
        if (self.presence is AddressPresence.OBSERVED) != bool(self.observed_roles):
            raise ValueError("presence must be observed exactly when a role is observed")
        final = self.transaction_status in FINAL_STATUSES
        if self.transfer_data_available != final or final != (
            self.usdt_observations is not None
        ):
            raise ValueError("USDT observations are known only for a final transaction")
        roles = set(self.observed_roles)
        for observation in self.usdt_observations or ():
            receives = observation.direction is not UsdtDirection.OUTGOING
            sends = observation.direction is not UsdtDirection.INCOMING
            if (receives and ObservedRole.USDT_TRANSFER_RECIPIENT not in roles) or (
                sends and ObservedRole.USDT_TRANSFER_SENDER not in roles
            ):
                raise ValueError("USDT observations must match the observed roles")
        return self


class AddressActivitySummary(_StrictFrozenModel):
    """Aggregates over the supplied sample only.

    Event counts and ``known_*`` amounts cover the transactions whose USDT
    events are known (``transactions_with_transfer_data``); they are ``None``
    when ``transfer_coverage`` is ``none``. Incoming and outgoing include the
    ``self_transfer_count`` self-transfers. Amounts are sums of event amounts,
    not a balance, net flow or deduplicated volume.
    """

    transfer_coverage: TransferCoverage
    inspected_transaction_count: Annotated[int, Field(ge=1, le=MAX_INVESTIGATED_TRANSACTIONS)]
    transactions_with_transfer_data: _Count
    transactions_with_unknown_transfers: _Count
    transactions_where_observed: _Count
    incoming_usdt_event_count: _Count | None
    outgoing_usdt_event_count: _Count | None
    self_transfer_count: _Count | None
    known_incoming_usdt_amount_atomic: _Amount | None
    known_outgoing_usdt_amount_atomic: _Amount | None
    known_self_transfer_amount_atomic: _Amount | None
    counterparties: tuple[StrictStr, ...] | None

    @model_validator(mode="after")
    def _check_consistency(self) -> "AddressActivitySummary":
        known = self.transactions_with_transfer_data
        unknown = self.transactions_with_unknown_transfers
        if known + unknown != self.inspected_transaction_count:
            raise ValueError("every inspected transaction has known or unknown transfers")
        if self.transactions_where_observed > self.inspected_transaction_count:
            raise ValueError("cannot be observed in more transactions than inspected")
        expected = (
            TransferCoverage.NONE if known == 0
            else TransferCoverage.COMPLETE if unknown == 0
            else TransferCoverage.PARTIAL
        )
        if self.transfer_coverage is not expected:
            raise ValueError("transfer_coverage does not match the transaction counts")
        measures = (
            self.incoming_usdt_event_count,
            self.outgoing_usdt_event_count,
            self.self_transfer_count,
            self.known_incoming_usdt_amount_atomic,
            self.known_outgoing_usdt_amount_atomic,
            self.known_self_transfer_amount_atomic,
            self.counterparties,
        )
        if known == 0:
            if any(value is not None for value in measures):
                raise ValueError("no aggregate exists when no transfer data is known")
            return self
        if any(value is None for value in measures):
            raise ValueError("aggregates must be set when transfer data is known")
        if self.self_transfer_count > min(
            self.incoming_usdt_event_count, self.outgoing_usdt_event_count
        ):
            raise ValueError("self-transfers are counted in both directions")
        if self.known_self_transfer_amount_atomic > min(
            self.known_incoming_usdt_amount_atomic, self.known_outgoing_usdt_amount_atomic
        ):
            raise ValueError("self-transfer amounts are counted in both directions")
        if list(self.counterparties) != sorted(set(self.counterparties)):
            raise ValueError("counterparties must be unique and sorted")
        return self


class AddressInvestigation(_StrictFrozenModel):
    """Observed activity of one address in the supplied transactions only."""

    network: Network
    address: StrictStr
    sample_scope: Literal["supplied_transactions_only"]
    presence: AddressPresence
    transactions: tuple[InvestigatedTransaction, ...] = Field(
        min_length=1, max_length=MAX_INVESTIGATED_TRANSACTIONS
    )
    summary: AddressActivitySummary

    @model_validator(mode="after")
    def _check_consistency(self) -> "AddressInvestigation":
        if normalize_contract_address(self.network, self.address) != self.address:
            raise ValueError("address must be in canonical form")
        hashes = [t.tx_hash for t in self.transactions]
        if [normalize_transaction_hash(self.network, h) for h in hashes] != hashes or len(
            set(hashes)
        ) != len(hashes):
            raise ValueError("transaction hashes must be canonical and unique")
        if self.summary != summarize_address_activity(self.transactions):
            raise ValueError("summary must be computed from the transactions")
        observed = self.summary.transactions_where_observed > 0
        if (self.presence is AddressPresence.OBSERVED) != observed:
            raise ValueError("presence must reflect the transactions")
        return self


def observe_address(inspection: TransactionInspection, address: str) -> InvestigatedTransaction:
    """What one inspection shows about ``address`` (canonical). Pure, no I/O."""
    roles = _canonical_roles(observed_address_roles(inspection).get(address, ()))
    observations: tuple[AddressUsdtObservation, ...] | None = None
    if inspection.usdt_transfers is not None:
        found = []
        for transfer in inspection.usdt_transfers:
            sends, receives = transfer.from_address == address, transfer.to_address == address
            if not (sends or receives):
                continue
            if sends and receives:
                direction, counterparty = UsdtDirection.SELF_TRANSFER, None
            elif receives:
                direction, counterparty = UsdtDirection.INCOMING, transfer.from_address
            else:
                direction, counterparty = UsdtDirection.OUTGOING, transfer.to_address
            found.append(
                AddressUsdtObservation(
                    direction=direction,
                    counterparty=counterparty,
                    amount_atomic=transfer.amount_atomic,
                    log_index=transfer.log_index,
                )
            )
        observations = tuple(found)
    return InvestigatedTransaction(
        tx_hash=inspection.tx_hash,
        transaction_status=inspection.transaction.status,
        presence=AddressPresence.OBSERVED if roles else AddressPresence.NOT_OBSERVED,
        observed_roles=roles,
        transfer_data_available=observations is not None,
        usdt_observations=observations,
    )


def summarize_address_activity(
    transactions: Sequence[InvestigatedTransaction],
) -> AddressActivitySummary:
    """Aggregate the sample exactly (integers only). Pure, no I/O."""
    known = [t for t in transactions if t.usdt_observations is not None]
    counts = {
        "transfer_coverage": (
            TransferCoverage.NONE if not known
            else TransferCoverage.COMPLETE if len(known) == len(transactions)
            else TransferCoverage.PARTIAL
        ),
        "inspected_transaction_count": len(transactions),
        "transactions_with_transfer_data": len(known),
        "transactions_with_unknown_transfers": len(transactions) - len(known),
        "transactions_where_observed": sum(
            1 for t in transactions if t.presence is AddressPresence.OBSERVED
        ),
    }
    if not known:
        return AddressActivitySummary(
            **counts,
            incoming_usdt_event_count=None,
            outgoing_usdt_event_count=None,
            self_transfer_count=None,
            known_incoming_usdt_amount_atomic=None,
            known_outgoing_usdt_amount_atomic=None,
            known_self_transfer_amount_atomic=None,
            counterparties=None,
        )
    events = [o for t in known for o in t.usdt_observations]  # type: ignore[union-attr]
    incoming = [o for o in events if o.direction is not UsdtDirection.OUTGOING]
    outgoing = [o for o in events if o.direction is not UsdtDirection.INCOMING]
    selfs = [o for o in events if o.direction is UsdtDirection.SELF_TRANSFER]
    return AddressActivitySummary(
        **counts,
        incoming_usdt_event_count=len(incoming),
        outgoing_usdt_event_count=len(outgoing),
        self_transfer_count=len(selfs),
        known_incoming_usdt_amount_atomic=sum(o.amount_atomic for o in incoming),
        known_outgoing_usdt_amount_atomic=sum(o.amount_atomic for o in outgoing),
        known_self_transfer_amount_atomic=sum(o.amount_atomic for o in selfs),
        counterparties=tuple(
            sorted({o.counterparty for o in events if o.counterparty is not None})
        ),
    )


def build_address_investigation(
    network: Network, address: str, inspections: Sequence[TransactionInspection]
) -> AddressInvestigation:
    """Assemble the investigation of ``address`` from its inspections. Pure."""
    address = normalize_contract_address(network, address)
    if any(inspection.network is not network for inspection in inspections):
        raise ValueError("every inspection must be on the investigated network")
    transactions = tuple(observe_address(inspection, address) for inspection in inspections)
    summary = summarize_address_activity(transactions)
    return AddressInvestigation(
        network=network,
        address=address,
        sample_scope="supplied_transactions_only",
        presence=(
            AddressPresence.OBSERVED if summary.transactions_where_observed
            else AddressPresence.NOT_OBSERVED
        ),
        transactions=transactions,
        summary=summary,
    )


class TransactionInspector(Protocol):
    def inspect_transaction(
        self, network: Network | str, tx_hash: str
    ) -> TransactionInspection: ...


def investigate_address(
    service: TransactionInspector, network: Network, address: str, tx_hashes: Sequence[str]
) -> AddressInvestigation:
    """Inspect each supplied transaction in order, then summarize.

    Inputs are validated before any inspection (``ValueError``: invalid
    address or hash, 0 or more than 3 hashes, duplicates). Fail-fast: the
    first inspection error is raised unchanged and no result is returned.
    """
    address = normalize_contract_address(network, address)
    hashes = [normalize_transaction_hash(network, value) for value in tx_hashes]
    if not 1 <= len(hashes) <= MAX_INVESTIGATED_TRANSACTIONS:
        raise ValueError(f"between 1 and {MAX_INVESTIGATED_TRANSACTIONS} transactions")
    if len(set(hashes)) != len(hashes):
        raise ValueError("duplicate transaction hashes")
    inspections = [service.inspect_transaction(network, tx_hash) for tx_hash in hashes]
    return build_address_investigation(network, address, inspections)
