"""Public JSON contract of the API, separate from the domain models.

Atomic amounts are decimal strings so that JSON clients that read numbers as
IEEE-754 doubles (JavaScript) never lose precision. Other integers (block
number, timestamp, log index) stay JSON integers but must be within the safe
range 0..2**53-1; a provider value outside it is rejected, never rounded.
"""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.domain.analysis_input import Network
from app.domain.token_transfer import NormalizedTokenTransfer
from app.providers.base import (
    MalformedResponseError,
    NativeUnit,
    NormalizedTransaction,
    TransactionStatus,
)
from app.services.transaction_analysis import TransactionInspection

MAX_SAFE_INTEGER = 2**53 - 1

DecimalString = Annotated[
    str,
    Field(
        pattern=r"^(0|[1-9][0-9]*)$",
        description="Exact non-negative integer as a decimal string.",
        examples=["35000000"],
    ),
]
SafeInteger = Annotated[int, Field(ge=0, le=MAX_SAFE_INTEGER)]


def _safe_int(value: int | None) -> int | None:
    if value is not None and value > MAX_SAFE_INTEGER:
        raise MalformedResponseError("provider returned an integer outside the safe range")
    return value


def _decimal(value: int | None) -> str | None:
    return None if value is None else str(value)


class _ResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TransactionView(_ResponseModel):
    status: TransactionStatus
    from_address: str | None
    to_address: str | None
    native_value_atomic: DecimalString | None = Field(
        description="Native coin amount (wei or sun), not a token amount."
    )
    native_unit: NativeUnit | None
    block_number: SafeInteger | None
    block_timestamp: SafeInteger | None = Field(description="Unix seconds, UTC.")

    @classmethod
    def from_domain(cls, tx: NormalizedTransaction) -> "TransactionView":
        return cls(
            status=tx.status,
            from_address=tx.from_address,
            to_address=tx.to_address,
            native_value_atomic=_decimal(tx.native_value_atomic),
            native_unit=tx.native_unit,
            block_number=_safe_int(tx.block_number),
            block_timestamp=_safe_int(tx.block_timestamp),
        )


class UsdtTransferView(_ResponseModel):
    token_symbol: str
    token_contract: str
    from_address: str
    to_address: str
    amount_atomic: DecimalString
    amount_formatted: str = Field(
        description="Exact decimal amount, e.g. 35.000000.", examples=["35.000000"]
    )
    decimals: int
    log_index: SafeInteger | None = Field(description="Ethereum log index; null on TRON.")

    @classmethod
    def from_domain(cls, transfer: NormalizedTokenTransfer) -> "UsdtTransferView":
        return cls(
            token_symbol=transfer.token_symbol,
            token_contract=transfer.token_contract,
            from_address=transfer.from_address,
            to_address=transfer.to_address,
            amount_atomic=str(transfer.amount_atomic),
            amount_formatted=transfer.format_amount(),
            decimals=transfer.decimals,
            log_index=_safe_int(transfer.log_index),
        )


class TransactionInspectionResponse(_ResponseModel):
    network: Network
    tx_hash: str
    transaction: TransactionView
    usdt_transfers: list[UsdtTransferView] | None = Field(
        description=(
            "Official USDT Transfer events in log order. [] means the final "
            "transaction recorded none; null means not available (pending, "
            "unconfirmed or not found)."
        )
    )

    @classmethod
    def from_inspection(cls, inspection: TransactionInspection) -> "TransactionInspectionResponse":
        transfers = inspection.usdt_transfers
        return cls(
            network=inspection.network,
            tx_hash=inspection.tx_hash,
            transaction=TransactionView.from_domain(inspection.transaction),
            usdt_transfers=(
                None if transfers is None else [UsdtTransferView.from_domain(t) for t in transfers]
            ),
        )


class ErrorDetail(_ResponseModel):
    field: str
    type: str


class ErrorBody(_ResponseModel):
    code: str
    message: str
    details: list[ErrorDetail] | None = None


class ErrorResponse(_ResponseModel):
    error: ErrorBody
