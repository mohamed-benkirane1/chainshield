import inspect
from datetime import date

import base58
import pytest
from pydantic import ValidationError

from app.domain.analysis_input import Network
from app.domain.usdt_registry import (
    REGISTRY_CHECKED_ON,
    TETHER_SUPPORTED_PROTOCOLS_URL,
    USDT_DECIMALS,
    ContractMatch,
    TokenContract,
    check_usdt_contract,
    get_usdt_contract,
)

ETH_USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

# Valid addresses that are not the official USDT contracts.
ETH_OTHER = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
TRON_OTHER = base58.b58encode_check(b"\x41" + bytes(20)).decode()


def swap_case_at(address: str, index: int) -> str:
    return address[:index] + address[index].swapcase() + address[index + 1 :]


# --- Official contracts -----------------------------------------------------


def test_ethereum_official_contract() -> None:
    contract = get_usdt_contract(Network.ETHEREUM)

    assert contract.network is Network.ETHEREUM
    assert contract.token == "USDT"
    assert contract.contract_address == ETH_USDT
    assert check_usdt_contract(Network.ETHEREUM, ETH_USDT) is ContractMatch.MATCH


def test_tron_official_contract() -> None:
    contract = get_usdt_contract(Network.TRON)

    assert contract.network is Network.TRON
    assert contract.token == "USDT"
    assert contract.contract_address == TRON_USDT
    assert check_usdt_contract(Network.TRON, TRON_USDT) is ContractMatch.MATCH


@pytest.mark.parametrize("network", ["ethereum", "tron"])
def test_network_can_be_given_as_string(network: str) -> None:
    assert get_usdt_contract(network) is get_usdt_contract(Network(network))


@pytest.mark.parametrize("network", ["bitcoin", "Ethereum", "", "TRON"])
def test_unsupported_network_is_rejected(network: str) -> None:
    with pytest.raises(ValueError):
        get_usdt_contract(network)
    with pytest.raises(ValueError):
        check_usdt_contract(network, ETH_USDT)


# --- Ethereum normalization and checksum -----------------------------------


@pytest.mark.parametrize(
    "address",
    [ETH_USDT.lower(), "0x" + ETH_USDT[2:].upper(), ETH_USDT],
    ids=["lowercase", "uppercase", "checksummed"],
)
def test_ethereum_address_is_normalized_before_comparison(address: str) -> None:
    assert check_usdt_contract(Network.ETHEREUM, address) is ContractMatch.MATCH


def test_ethereum_official_address_with_bad_checksum_is_rejected() -> None:
    # Flip the case of one letter: mixed case with an invalid EIP-55 checksum.
    index = next(i for i in range(2, len(ETH_USDT)) if ETH_USDT[i].isalpha())
    bad = swap_case_at(ETH_USDT, index)

    with pytest.raises(ValueError, match="checksum"):
        check_usdt_contract(Network.ETHEREUM, bad)


# --- Valid non-official addresses ------------------------------------------


@pytest.mark.parametrize(
    ("network", "address"),
    [
        (Network.ETHEREUM, ETH_OTHER),
        (Network.ETHEREUM, ETH_OTHER.lower()),
        (Network.ETHEREUM, "0x" + "00" * 20),
        (Network.TRON, TRON_OTHER),
        (Network.TRON, base58.b58encode_check(b"\x41" + b"\xff" * 20).decode()),
    ],
)
def test_valid_non_official_address_does_not_match(network: Network, address: str) -> None:
    result = check_usdt_contract(network, address)

    assert result is ContractMatch.NOT_MATCH
    assert result.value == "not_match"


def test_contract_differing_by_one_byte_does_not_match() -> None:
    raw = bytearray(base58.b58decode_check(TRON_USDT))
    raw[-1] ^= 0x01
    lookalike = base58.b58encode_check(bytes(raw)).decode()

    assert check_usdt_contract(Network.TRON, lookalike) is ContractMatch.NOT_MATCH


# --- Malformed addresses ---------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "",
        ETH_USDT[2:],  # missing 0x
        ETH_USDT[:-1],
        ETH_USDT + "0",
        " " + ETH_USDT,
        ETH_USDT + "\n",
        "0x" + "g" * 40,
    ],
)
def test_malformed_ethereum_address_is_rejected(address: str) -> None:
    with pytest.raises(ValueError):
        check_usdt_contract(Network.ETHEREUM, address)


@pytest.mark.parametrize(
    "address",
    [
        "",
        TRON_USDT[:-1],
        TRON_USDT[:-1] + ("u" if TRON_USDT[-1] != "u" else "v"),  # bad checksum
        TRON_USDT.lower(),  # Base58 is case-sensitive
        " " + TRON_USDT,
        "T0O" + TRON_USDT[3:],
        base58.b58encode_check(b"\x42" + bytes(20)).decode(),  # wrong prefix
    ],
)
def test_malformed_tron_address_is_rejected(address: str) -> None:
    with pytest.raises(ValueError):
        check_usdt_contract(Network.TRON, address)


@pytest.mark.parametrize("address", [None, 123, b"TR7N"])
@pytest.mark.parametrize("network", [Network.ETHEREUM, Network.TRON])
def test_non_string_address_is_rejected(network: Network, address: object) -> None:
    with pytest.raises(ValueError):
        check_usdt_contract(network, address)  # type: ignore[arg-type]


# --- Cross-network ---------------------------------------------------------


def test_tron_contract_checked_on_ethereum_is_rejected() -> None:
    with pytest.raises(ValueError):
        check_usdt_contract(Network.ETHEREUM, TRON_USDT)


def test_ethereum_contract_checked_on_tron_is_rejected() -> None:
    with pytest.raises(ValueError):
        check_usdt_contract(Network.TRON, ETH_USDT)


def test_tron_hex_form_of_official_contract_is_not_accepted_as_ethereum() -> None:
    # The 20-byte body of the TRON USDT contract, written as an Ethereum
    # address, is a different account on a different chain.
    body = base58.b58decode_check(TRON_USDT)[1:].hex()

    assert check_usdt_contract(Network.ETHEREUM, "0x" + body) is ContractMatch.NOT_MATCH


# --- Decimals, metadata and sources ----------------------------------------


@pytest.mark.parametrize("network", list(Network))
def test_decimals_are_exactly_six(network: Network) -> None:
    decimals = get_usdt_contract(network).decimals

    assert USDT_DECIMALS == 6
    assert type(decimals) is int
    assert decimals == 6


@pytest.mark.parametrize("network", list(Network))
def test_metadata_and_sources(network: Network) -> None:
    contract = get_usdt_contract(network)

    assert contract.official_source_url == TETHER_SUPPORTED_PROTOCOLS_URL
    assert contract.official_source_url.startswith("https://tether.to/")
    assert contract.checked_on == REGISTRY_CHECKED_ON == date(2026, 10, 12)
    assert set(TokenContract.model_fields) == {
        "network",
        "token",
        "contract_address",
        "decimals",
        "official_source_url",
        "checked_on",
    }


def test_every_network_has_exactly_one_usdt_contract() -> None:
    contracts = [get_usdt_contract(network) for network in Network]

    assert [c.network for c in contracts] == list(Network)
    assert len({c.contract_address for c in contracts}) == len(contracts)


def test_check_does_not_accept_name_or_symbol() -> None:
    assert list(inspect.signature(check_usdt_contract).parameters) == [
        "network",
        "contract_address",
    ]
    with pytest.raises(TypeError):
        check_usdt_contract(  # type: ignore[call-arg]
            Network.ETHEREUM, ETH_OTHER, name="Tether USD", symbol="USDT"
        )


# --- Immutability -----------------------------------------------------------


@pytest.mark.parametrize("field", ["contract_address", "decimals", "network", "token"])
def test_contract_configuration_is_immutable(field: str) -> None:
    contract = get_usdt_contract(Network.ETHEREUM)

    with pytest.raises(ValidationError):
        setattr(contract, field, ETH_OTHER if field == "contract_address" else 18)


def test_registry_mapping_cannot_be_modified() -> None:
    from app.domain import usdt_registry

    with pytest.raises(TypeError):
        usdt_registry._USDT_CONTRACTS[Network.ETHEREUM] = None  # type: ignore[index]

    assert get_usdt_contract(Network.ETHEREUM).contract_address == ETH_USDT


# --- Model validation -------------------------------------------------------


def _contract(**overrides: object) -> TokenContract:
    fields: dict[str, object] = {
        "network": "ethereum",
        "token": "USDT",
        "contract_address": ETH_USDT,
        "decimals": 6,
        "official_source_url": TETHER_SUPPORTED_PROTOCOLS_URL,
        "checked_on": REGISTRY_CHECKED_ON,
    }
    fields.update(overrides)
    return TokenContract(**fields)


@pytest.mark.parametrize(
    "overrides",
    [
        {"contract_address": ETH_USDT.lower()},  # not canonical
        {"contract_address": TRON_USDT},  # wrong network
        {"network": "tron"},  # Ethereum address on TRON
        {"token": "USDC"},
        {"decimals": 6.0},
        {"decimals": "6"},
        {"decimals": -1},
        {"extra": "field"},
    ],
)
def test_invalid_token_contract_is_rejected(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        _contract(**overrides)
