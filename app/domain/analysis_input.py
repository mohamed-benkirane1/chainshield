"""Validation of analysis inputs (addresses, transactions, messages).

This module only checks that inputs are well-formed. It performs no network
calls, no risk scoring, and never logs user-provided content.
"""

import re
from enum import StrEnum
from typing import Annotated, Literal

import base58
from eth_utils import (
    is_checksum_address,
    is_checksum_formatted_address,
    to_checksum_address,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    model_validator,
)

MESSAGE_MAX_LENGTH = 5000

TRON_ADDRESS_PREFIX = 0x41
TRON_ADDRESS_DECODED_LENGTH = 21  # 1-byte prefix + 20-byte account id

_ETH_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_ETH_TX_HASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")
_TRON_TX_HASH_RE = re.compile(r"[0-9a-fA-F]{64}")


class Network(StrEnum):
    ETHEREUM = "ethereum"
    TRON = "tron"


class Language(StrEnum):
    FR = "fr"
    AR = "ar"
    EN = "en"


def normalize_ethereum_address(value: str) -> str:
    """Validate an Ethereum address and return its EIP-55 checksummed form.

    All-lowercase or all-uppercase addresses carry no checksum and are
    accepted; mixed-case addresses must have a valid EIP-55 checksum.
    """
    if not _ETH_ADDRESS_RE.fullmatch(value):
        raise ValueError("Ethereum address must be 0x followed by 40 hex characters")
    if is_checksum_formatted_address(value) and not is_checksum_address(value):
        raise ValueError("Ethereum address has an invalid EIP-55 checksum")
    return to_checksum_address(value)


def validate_tron_address(value: str) -> str:
    """Validate a TRON Base58Check address (0x41 prefix, 21 decoded bytes)."""
    try:
        decoded = base58.b58decode_check(value)
    except ValueError:
        raise ValueError("TRON address is not valid Base58Check") from None
    if len(decoded) != TRON_ADDRESS_DECODED_LENGTH:
        raise ValueError("TRON address has an invalid decoded length")
    if decoded[0] != TRON_ADDRESS_PREFIX:
        raise ValueError("TRON address must use the 0x41 prefix")
    return value


def normalize_transaction_hash(network: Network, value: str) -> str:
    """Validate a transaction hash for the given network and lowercase it."""
    if network is Network.ETHEREUM:
        if not _ETH_TX_HASH_RE.fullmatch(value):
            raise ValueError(
                "Ethereum transaction hash must be 0x followed by 64 hex characters"
            )
    elif not _TRON_TX_HASH_RE.fullmatch(value):
        raise ValueError("TRON transaction hash must be 64 hex characters")
    return value.lower()


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AddressAnalysisRequest(_StrictModel):
    kind: Literal["address"] = "address"
    network: Network
    address: Annotated[str, StringConstraints(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def _check_address(self) -> "AddressAnalysisRequest":
        if self.network is Network.ETHEREUM:
            self.address = normalize_ethereum_address(self.address)
        else:
            self.address = validate_tron_address(self.address)
        return self


class TransactionAnalysisRequest(_StrictModel):
    kind: Literal["transaction"] = "transaction"
    network: Network
    tx_hash: Annotated[str, StringConstraints(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def _check_tx_hash(self) -> "TransactionAnalysisRequest":
        self.tx_hash = normalize_transaction_hash(self.network, self.tx_hash)
        return self


class MessageAnalysisRequest(_StrictModel):
    # Keep user text out of validation error reprs.
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    kind: Literal["message"] = "message"
    text: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True, min_length=1, max_length=MESSAGE_MAX_LENGTH
        ),
    ]
    language: Language | None = None


AnalysisRequest = Annotated[
    AddressAnalysisRequest | TransactionAnalysisRequest | MessageAnalysisRequest,
    Field(discriminator="kind"),
]

# Union-level validation uses the adapter's config, not the member models'.
analysis_request_adapter: TypeAdapter[AnalysisRequest] = TypeAdapter(
    AnalysisRequest, config=ConfigDict(hide_input_in_errors=True)
)
