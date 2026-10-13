"""Normalized token transfer, shared by chain-specific event decoders."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from app.domain.analysis_input import Network, normalize_transaction_hash
from app.domain.usdt_registry import (
    ContractMatch,
    check_usdt_contract,
    get_usdt_contract,
    normalize_contract_address,
)

MAX_UINT256 = 2**256 - 1


class NormalizedTokenTransfer(BaseModel):
    """One token transfer event recorded on chain by the token contract.

    ``amount_atomic`` is the exact integer amount in the token's smallest
    unit: 35_000_000 with 6 decimals is 35 USDT. It is unrelated to the
    transaction's native value (``native_value_atomic`` in wei or sun).

    Only the official USDT contract from the registry can be represented, with
    the registry's decimals; ``token_symbol`` alone is never trusted.

    ``log_index`` is the event's position in its block. It is required on
    Ethereum and may be ``None`` on chains whose APIs do not expose one.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: Network
    tx_hash: str
    token_symbol: Literal["USDT"]
    token_contract: str
    from_address: str
    to_address: str
    amount_atomic: Annotated[StrictInt, Field(ge=0, le=MAX_UINT256)]
    decimals: Annotated[StrictInt, Field(ge=0, le=255)]
    log_index: Annotated[StrictInt, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> "NormalizedTokenTransfer":
        if normalize_transaction_hash(self.network, self.tx_hash) != self.tx_hash:
            raise ValueError("tx_hash must be in canonical form")
        for value in (self.token_contract, self.from_address, self.to_address):
            if normalize_contract_address(self.network, value) != value:
                raise ValueError("addresses must be in canonical form")
        if check_usdt_contract(self.network, self.token_contract) is not ContractMatch.MATCH:
            raise ValueError("token_contract is not the official USDT contract")
        if self.decimals != get_usdt_contract(self.network).decimals:
            raise ValueError("decimals do not match the official USDT contract")
        if self.network is Network.ETHEREUM and self.log_index is None:
            raise ValueError("log_index is required on Ethereum")
        return self

    def format_amount(self) -> str:
        """Exact decimal string without float, e.g. 35000000 -> "35.000000"."""
        whole, fraction = divmod(self.amount_atomic, 10**self.decimals)
        return f"{whole}.{fraction:0{self.decimals}d}"
