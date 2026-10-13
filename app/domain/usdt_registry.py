"""Registry of the official USDT contracts, verified by address only.

Authenticity is decided solely by the contract address on a given network.
A token's ``name`` or ``symbol`` (e.g. "Tether USD" / "USDT") is
self-declared by whoever deploys the contract and is never used here.

Sources checked on 2026-10-12:

* Addresses: Tether, https://tether.to/en/supported-protocols/
  ("USDT contract address", written with the U+20AE sign, for Ethereum and
  for TRC20 via Tron).
* Ethereum decimals: Etherscan token page for
  0xdAC17F958D2ee523a2206206994597C13D831ec7 ("WITH 6 Decimals",
  source code verified).
* TRON decimals: Tronscan public token API
  (apilist.tronscanapi.com/api/token_trc20) for
  TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t (decimals 6). The Tronscan docs page
  https://docs.tronscan.org/en/api/tokens/token-trc20 returned HTTP 403.

A "not_match" result only means the address is not the official USDT
contract on that network; it is not, by itself, evidence of fraud.
"""

from collections.abc import Mapping
from datetime import date
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from app.domain.analysis_input import (
    Network,
    normalize_ethereum_address,
    validate_tron_address,
)

USDT_DECIMALS = 6
TETHER_SUPPORTED_PROTOCOLS_URL = "https://tether.to/en/supported-protocols/"
REGISTRY_CHECKED_ON = date(2026, 10, 12)


class ContractMatch(StrEnum):
    MATCH = "match"
    NOT_MATCH = "not_match"


def normalize_contract_address(network: Network, address: str) -> str:
    """Validate an address for ``network`` and return its canonical form.

    Ethereum: EIP-55 checksummed form (mixed case must have a valid checksum).
    TRON: Base58Check, returned unchanged (Base58 is case-sensitive).
    Raises ``ValueError`` for a malformed address.
    """
    if not isinstance(address, str):
        raise ValueError("contract address must be a string")
    if network is Network.ETHEREUM:
        return normalize_ethereum_address(address)
    return validate_tron_address(address)


class TokenContract(BaseModel):
    """Immutable description of an official token contract on one network."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    network: Network
    token: Literal["USDT"]
    contract_address: str
    decimals: Annotated[StrictInt, Field(ge=0, le=255)]
    official_source_url: str
    checked_on: date

    @model_validator(mode="after")
    def _check_canonical_address(self) -> "TokenContract":
        if normalize_contract_address(self.network, self.contract_address) != (
            self.contract_address
        ):
            raise ValueError("contract_address must be in canonical form")
        return self


_USDT_CONTRACTS: Mapping[Network, TokenContract] = MappingProxyType(
    {
        Network.ETHEREUM: TokenContract(
            network=Network.ETHEREUM,
            token="USDT",
            contract_address="0xdAC17F958D2ee523a2206206994597C13D831ec7",
            decimals=USDT_DECIMALS,
            official_source_url=TETHER_SUPPORTED_PROTOCOLS_URL,
            checked_on=REGISTRY_CHECKED_ON,
        ),
        Network.TRON: TokenContract(
            network=Network.TRON,
            token="USDT",
            contract_address="TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
            decimals=USDT_DECIMALS,
            official_source_url=TETHER_SUPPORTED_PROTOCOLS_URL,
            checked_on=REGISTRY_CHECKED_ON,
        ),
    }
)


def get_usdt_contract(network: Network | str) -> TokenContract:
    """Return the official USDT contract configured for ``network``.

    Raises ``ValueError`` for an unsupported network.
    """
    return _USDT_CONTRACTS[Network(network)]


def check_usdt_contract(network: Network | str, contract_address: str) -> ContractMatch:
    """Check whether ``contract_address`` is the official USDT contract.

    This is the single entry point future ERC-20 / TRC-20 transfer decoders
    should use to decide whether a transfer event concerns official USDT.
    Raises ``ValueError`` if the address is malformed for ``network``
    (including an address from another chain).
    """
    official = get_usdt_contract(network)
    address = normalize_contract_address(official.network, contract_address)
    if address == official.contract_address:
        return ContractMatch.MATCH
    return ContractMatch.NOT_MATCH
