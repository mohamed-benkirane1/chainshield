"""Factual features of a transaction's official USDT Transfer events.

The features are descriptive only. None of them is, by itself, a sign of
fraud: several transfers, a large amount, a self-transfer or a reverted
execution are all common in legitimate activity. They carry no verdict, no
score and no information about who controls an address.

They cover the official USDT ``Transfer`` events only. Other USDT contract
movements (e.g. ``Issue``, ``Redeem``, blacklisted funds destruction on
Ethereum) are not extracted, so zero transfers does not mean that no USDT
activity happened.

Availability: for a final transaction (``success`` / ``reverted``) the
measures are computed, with 0 for empty counts and ``None`` for a maximum
that does not exist. For a ``pending``, ``unconfirmed`` or ``not_found``
transaction the transfers are not observable, so every measure is ``None``:
unknown is never reported as 0 or False.
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.domain.analysis_input import Network, normalize_transaction_hash
from app.domain.token_transfer import MAX_UINT256
from app.providers.base import TransactionStatus
from app.services.transaction_analysis import FINAL_STATUSES, TransactionInspection

_Count = Annotated[int, Field(ge=0)]

_MEASURES = (
    "usdt_transfer_count",
    "has_usdt_transfers",
    "unique_usdt_senders",
    "unique_usdt_recipients",
    "unique_usdt_participants",
    "self_transfer_count",
    "zero_amount_transfer_count",
    "gross_usdt_event_amount_atomic",
    "max_usdt_transfer_amount_atomic",
)


class TransactionFeatures(BaseModel):
    """Descriptive features of one inspected transaction.

    Counts are over official USDT ``Transfer`` events. Addresses are compared
    in their canonical form (EIP-55 on Ethereum, Base58Check on TRON).

    ``gross_usdt_event_amount_atomic`` is the exact sum of ``amount_atomic``
    over all those events. It is NOT a net amount, a balance change, the
    amount received by the initiator or a deduplicated economic volume: the
    same USDT can appear in several successive events (e.g. a swap routed
    through intermediate contracts), so it is counted once per event. It is
    not capped at uint256, since a sum of uint256 values may exceed it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    network: Network
    tx_hash: str
    transaction_status: TransactionStatus
    transfer_data_available: bool

    usdt_transfer_count: _Count | None = None
    has_usdt_transfers: bool | None = None
    unique_usdt_senders: _Count | None = None
    unique_usdt_recipients: _Count | None = None
    unique_usdt_participants: _Count | None = None
    self_transfer_count: _Count | None = None
    zero_amount_transfer_count: _Count | None = None
    gross_usdt_event_amount_atomic: _Count | None = None
    max_usdt_transfer_amount_atomic: Annotated[int, Field(ge=0, le=MAX_UINT256)] | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> "TransactionFeatures":
        if normalize_transaction_hash(self.network, self.tx_hash) != self.tx_hash:
            raise ValueError("tx_hash must be in canonical form")
        if self.transfer_data_available != (self.transaction_status in FINAL_STATUSES):
            raise ValueError("transfer data is available only for a final transaction")
        measures = [getattr(self, name) for name in _MEASURES]
        if not self.transfer_data_available:
            if any(value is not None for value in measures):
                raise ValueError("measures must be None when transfer data is unavailable")
            return self

        if any(value is None for value in measures[:-1]):
            raise ValueError("measures must be set when transfer data is available")
        count = self.usdt_transfer_count
        if self.transaction_status is TransactionStatus.REVERTED and count:
            raise ValueError("a reverted transaction has no executed transfers")
        if self.has_usdt_transfers != (count > 0):
            raise ValueError("has_usdt_transfers must match usdt_transfer_count")
        if count == 0:
            if self.max_usdt_transfer_amount_atomic is not None or any(
                value != 0 for value in measures[2:8]
            ):
                raise ValueError("an empty transfer list has zero measures and no maximum")
            return self

        senders, recipients = self.unique_usdt_senders, self.unique_usdt_recipients
        maximum = self.max_usdt_transfer_amount_atomic
        if not (1 <= senders <= count and 1 <= recipients <= count):
            raise ValueError("unique senders and recipients must be within 1..count")
        if not max(senders, recipients) <= self.unique_usdt_participants <= senders + recipients:
            raise ValueError("unique participants must combine senders and recipients")
        if self.self_transfer_count > count or self.zero_amount_transfer_count > count:
            raise ValueError("per-event counts cannot exceed the transfer count")
        if maximum is None or not maximum <= self.gross_usdt_event_amount_atomic <= maximum * count:
            raise ValueError("gross amount must lie between the maximum and count * maximum")
        if (self.zero_amount_transfer_count == count) != (maximum == 0):
            raise ValueError("the maximum is 0 exactly when every transfer is zero")
        return self


def extract_transaction_features(inspection: TransactionInspection) -> TransactionFeatures:
    """Compute the features of an inspection. Pure: no I/O, no mutation."""
    identity = {
        "network": inspection.network,
        "tx_hash": inspection.tx_hash,
        "transaction_status": inspection.transaction.status,
    }
    transfers = inspection.usdt_transfers
    if transfers is None:
        return TransactionFeatures(**identity, transfer_data_available=False)

    senders = {transfer.from_address for transfer in transfers}
    recipients = {transfer.to_address for transfer in transfers}
    amounts = [transfer.amount_atomic for transfer in transfers]
    return TransactionFeatures(
        **identity,
        transfer_data_available=True,
        usdt_transfer_count=len(transfers),
        has_usdt_transfers=bool(transfers),
        unique_usdt_senders=len(senders),
        unique_usdt_recipients=len(recipients),
        unique_usdt_participants=len(senders | recipients),
        self_transfer_count=sum(1 for t in transfers if t.from_address == t.to_address),
        zero_amount_transfer_count=sum(1 for amount in amounts if amount == 0),
        gross_usdt_event_amount_atomic=sum(amounts),
        max_usdt_transfer_amount_atomic=max(amounts, default=None),
    )
