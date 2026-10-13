"""Network-agnostic provider interface, normalized models and errors."""

from enum import StrEnum
from typing import Annotated, Protocol

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from app.domain.analysis_input import Network


class TransactionStatus(StrEnum):
    PENDING = "pending"  # known to the node, not yet included in a block
    # Included in a block but not yet final (e.g. TRON before solidification);
    # its execution outcome is not reported until it is final.
    UNCONFIRMED = "unconfirmed"
    SUCCESS = "success"
    REVERTED = "reverted"  # included in a block, execution failed
    NOT_FOUND = "not_found"  # unknown to the node that was queried


class NativeUnit(StrEnum):
    """Smallest unit of a chain's native coin."""

    WEI = "wei"  # 1 ETH = 10**18 wei
    SUN = "sun"  # 1 TRX = 10**6 sun


NATIVE_UNIT_BY_NETWORK: dict[Network, NativeUnit] = {
    Network.ETHEREUM: NativeUnit.WEI,
    Network.TRON: NativeUnit.SUN,
}

# Strict: rejects floats, bools and numeric strings so amounts stay exact.
_NonNegativeStrictInt = Annotated[StrictInt, Field(ge=0)]


class NormalizedTransaction(BaseModel):
    """Chain-independent view of a transaction lookup.

    Fields the provider could not observe are ``None``; nothing is inferred.

    ``native_value_atomic`` is the amount of the chain's native coin (ETH on
    Ethereum, TRX on TRON) carried by the transaction, as an exact integer in
    ``native_unit`` (wei or sun). It is NOT the amount of a token transfer: a
    USDT transfer usually has a native value of 0, and its token amount lives
    in the call data / logs, which are not decoded here.

    ``block_timestamp`` is in Unix seconds (UTC), whatever the chain's own
    representation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: Network
    tx_hash: str
    status: TransactionStatus
    from_address: str | None = None
    to_address: str | None = None  # None for contract creation or unknown
    native_value_atomic: _NonNegativeStrictInt | None = None
    native_unit: NativeUnit | None = None
    block_number: int | None = Field(default=None, ge=0)
    block_timestamp: _NonNegativeStrictInt | None = None  # Unix seconds, UTC

    @model_validator(mode="after")
    def _check_consistency(self) -> "NormalizedTransaction":
        if (self.native_value_atomic is None) != (self.native_unit is None):
            raise ValueError("native_value_atomic and native_unit go together")
        if (
            self.native_unit is not None
            and self.native_unit is not NATIVE_UNIT_BY_NETWORK[self.network]
        ):
            raise ValueError(
                f"native_unit for {self.network.value} must be "
                f"{NATIVE_UNIT_BY_NETWORK[self.network].value}"
            )
        if self.status is TransactionStatus.NOT_FOUND:
            if any(
                value is not None
                for value in (
                    self.from_address,
                    self.to_address,
                    self.native_value_atomic,
                    self.block_number,
                    self.block_timestamp,
                )
            ):
                raise ValueError("a transaction that was not found carries no data")
            return self
        if self.from_address is None or self.native_value_atomic is None:
            raise ValueError("a found transaction must have a sender and a value")
        mined = self.status in (TransactionStatus.SUCCESS, TransactionStatus.REVERTED)
        has_block = self.block_number is not None
        if mined != has_block or mined != (self.block_timestamp is not None):
            raise ValueError("block data must be present iff the transaction is mined")
        return self


class BlockchainProvider(Protocol):
    """Minimal read-only interface shared by every chain provider."""

    network: Network

    def get_transaction(self, tx_hash: str) -> NormalizedTransaction:
        """Look up a transaction by hash.

        Raises ``ValueError`` for a malformed hash and ``ProviderError`` for
        any failure to obtain a trustworthy answer from the backend.
        """
        ...


class ProviderError(Exception):
    """Base class for provider failures. Messages never contain secrets."""


class ProviderConfigurationError(ProviderError):
    """The provider is missing or has invalid configuration."""


class ProviderTimeoutError(ProviderError):
    """The backend did not answer in time."""


class ProviderUnavailableError(ProviderError):
    """The backend could not be reached or returned an HTTP error."""


class MalformedResponseError(ProviderError):
    """The backend answered with data that is invalid or inconsistent."""


class ReceiptUnavailableError(ProviderError):
    """A mined transaction's receipt is not available from the backend yet.

    Potentially transient (e.g. the node has not indexed the block); the
    caller may retry later. The transaction outcome is unknown: it is neither
    pending nor known to have succeeded or reverted.
    """


class TransactionNotFoundError(ProviderError):
    """The transaction is unknown to the node, so it has no executed effects."""


class TransactionPendingError(ProviderError):
    """The transaction is not yet included in a block, so it has not executed."""


class ExecutionResultUnknownError(ProviderError):
    """The backend data does not establish whether execution succeeded.

    The outcome is neither reported as success nor as reverted.
    """


class UnsupportedTransactionError(ProviderError):
    """The transaction type is not supported by this provider."""


class RpcError(ProviderError):
    """The backend returned a JSON-RPC error object."""

    def __init__(self, method: str, code: object) -> None:
        self.method = method
        self.code = code if isinstance(code, int) else None
        super().__init__(f"JSON-RPC error from {method} (code {self.code})")


class ChainMismatchError(ProviderError):
    """The backend is connected to a different chain than expected."""
