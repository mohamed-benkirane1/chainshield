import base58
import pytest
from pydantic import ValidationError

from app.domain.analysis_input import (
    MESSAGE_MAX_LENGTH,
    AddressAnalysisRequest,
    Language,
    MessageAnalysisRequest,
    Network,
    TransactionAnalysisRequest,
    analysis_request_adapter,
)

# EIP-55 reference vectors.
ETH_CHECKSUMMED = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
ETH_USDT_CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

# USDT TRC-20 contract address on TRON mainnet.
TRON_USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

ETH_TX_HASH = "0x" + "ab" * 32
TRON_TX_HASH = "cd" * 32


def tron_address(payload: bytes) -> str:
    return base58.b58encode_check(payload).decode()


def swap_last_letter_case(address: str) -> str:
    for i in range(len(address) - 1, 1, -1):
        if address[i].isalpha():
            return address[:i] + address[i].swapcase() + address[i + 1 :]
    raise AssertionError("no letter to swap")


# --- Ethereum addresses -----------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        ETH_CHECKSUMMED,
        ETH_USDT_CONTRACT,
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ],
)
def test_ethereum_checksummed_address_is_accepted(address: str) -> None:
    request = AddressAnalysisRequest(network="ethereum", address=address)

    assert request.address == address
    assert request.network is Network.ETHEREUM


@pytest.mark.parametrize(
    "address", [ETH_CHECKSUMMED.lower(), "0x" + ETH_CHECKSUMMED[2:].upper()]
)
def test_ethereum_single_case_address_is_normalized_to_checksum(address: str) -> None:
    request = AddressAnalysisRequest(network="ethereum", address=address)

    assert request.address == ETH_CHECKSUMMED


def test_ethereum_address_with_bad_checksum_is_rejected() -> None:
    with pytest.raises(ValidationError, match="checksum"):
        AddressAnalysisRequest(
            network="ethereum", address=swap_last_letter_case(ETH_CHECKSUMMED)
        )


@pytest.mark.parametrize(
    "address",
    [
        ETH_CHECKSUMMED[2:],  # missing 0x
        ETH_CHECKSUMMED[:-1],  # 39 hex chars
        ETH_CHECKSUMMED + "a",  # 41 hex chars
        "0x" + "g" * 40,  # non-hex
        "0X" + ETH_CHECKSUMMED[2:],  # uppercase prefix
        " " + ETH_CHECKSUMMED,
        ETH_CHECKSUMMED + "\n",
        "",
        TRON_USDT_CONTRACT,
    ],
)
def test_malformed_ethereum_address_is_rejected(address: str) -> None:
    with pytest.raises(ValidationError):
        AddressAnalysisRequest(network="ethereum", address=address)


# --- TRON addresses ---------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        TRON_USDT_CONTRACT,
        tron_address(b"\x41" + bytes(20)),
        tron_address(b"\x41" + b"\xff" * 20),
    ],
)
def test_valid_tron_address_is_accepted(address: str) -> None:
    request = AddressAnalysisRequest(network="tron", address=address)

    assert request.address == address
    assert request.network is Network.TRON


def test_tron_address_with_bad_checksum_is_rejected() -> None:
    last = "u" if TRON_USDT_CONTRACT[-1] != "u" else "v"
    corrupted = TRON_USDT_CONTRACT[:-1] + last
    with pytest.raises(ValidationError, match="Base58Check"):
        AddressAnalysisRequest(network="tron", address=corrupted)


def test_tron_address_with_wrong_prefix_is_rejected() -> None:
    with pytest.raises(ValidationError, match="0x41"):
        AddressAnalysisRequest(
            network="tron", address=tron_address(b"\x42" + bytes(20))
        )


@pytest.mark.parametrize("payload_length", [19, 21])
def test_tron_address_with_wrong_decoded_length_is_rejected(
    payload_length: int,
) -> None:
    address = tron_address(b"\x41" + bytes(payload_length))
    with pytest.raises(ValidationError, match="decoded length"):
        AddressAnalysisRequest(network="tron", address=address)


@pytest.mark.parametrize(
    "address",
    [
        "T0O" + TRON_USDT_CONTRACT[3:],  # characters outside Base58 alphabet
        "",
        ETH_CHECKSUMMED,
        "T" * 129,  # above max length
    ],
)
def test_malformed_tron_address_is_rejected(address: str) -> None:
    with pytest.raises(ValidationError):
        AddressAnalysisRequest(network="tron", address=address)


# --- Transaction hashes -----------------------------------------------------


def test_ethereum_transaction_hash_is_accepted_and_lowercased() -> None:
    request = TransactionAnalysisRequest(
        network="ethereum", tx_hash="0x" + ETH_TX_HASH[2:].upper()
    )

    assert request.tx_hash == ETH_TX_HASH


def test_tron_transaction_hash_is_accepted_and_lowercased() -> None:
    request = TransactionAnalysisRequest(network="tron", tx_hash=TRON_TX_HASH.upper())

    assert request.tx_hash == TRON_TX_HASH


@pytest.mark.parametrize(
    "tx_hash",
    [
        TRON_TX_HASH,  # missing 0x
        "0x" + "a" * 63,
        "0x" + "a" * 65,
        "0x" + "z" * 64,
        "0X" + "a" * 64,
        ETH_TX_HASH + "\n",
        "",
    ],
)
def test_invalid_ethereum_transaction_hash_is_rejected(tx_hash: str) -> None:
    with pytest.raises(ValidationError):
        TransactionAnalysisRequest(network="ethereum", tx_hash=tx_hash)


@pytest.mark.parametrize(
    "tx_hash",
    [
        ETH_TX_HASH,  # 0x prefix not allowed on TRON
        "a" * 63,
        "a" * 65,
        "z" * 64,
        " " + TRON_TX_HASH,
        "",
    ],
)
def test_invalid_tron_transaction_hash_is_rejected(tx_hash: str) -> None:
    with pytest.raises(ValidationError):
        TransactionAnalysisRequest(network="tron", tx_hash=tx_hash)


# --- Network ----------------------------------------------------------------


def test_network_is_required_for_address() -> None:
    with pytest.raises(ValidationError, match="network"):
        AddressAnalysisRequest(address=ETH_CHECKSUMMED)


def test_network_is_required_for_transaction() -> None:
    with pytest.raises(ValidationError, match="network"):
        TransactionAnalysisRequest(tx_hash=ETH_TX_HASH)


@pytest.mark.parametrize("network", ["bitcoin", "Ethereum", "TRON", "", None])
def test_unsupported_network_is_rejected(network: object) -> None:
    with pytest.raises(ValidationError):
        AddressAnalysisRequest(network=network, address=ETH_CHECKSUMMED)


# --- Messages ---------------------------------------------------------------


def test_message_is_trimmed() -> None:
    request = MessageAnalysisRequest(text="  Send USDT now  \n")

    assert request.text == "Send USDT now"
    assert request.language is None


@pytest.mark.parametrize("language", ["fr", "ar", "en"])
def test_message_accepts_supported_languages(language: str) -> None:
    request = MessageAnalysisRequest(text="hello", language=language)

    assert request.language is Language(language)


def test_message_accepts_arabic_text() -> None:
    text = "أرسل USDT الآن"
    request = MessageAnalysisRequest(text=text, language="ar")

    assert request.text == text


@pytest.mark.parametrize("language", ["de", "FR", "", "english"])
def test_message_rejects_unsupported_language(language: str) -> None:
    with pytest.raises(ValidationError):
        MessageAnalysisRequest(text="hello", language=language)


@pytest.mark.parametrize("text", ["", "   ", "\n\t  "])
def test_blank_message_is_rejected(text: str) -> None:
    with pytest.raises(ValidationError):
        MessageAnalysisRequest(text=text)


def test_message_at_max_length_is_accepted() -> None:
    request = MessageAnalysisRequest(text="a" * MESSAGE_MAX_LENGTH)

    assert len(request.text) == MESSAGE_MAX_LENGTH


def test_message_above_max_length_is_rejected() -> None:
    with pytest.raises(ValidationError):
        MessageAnalysisRequest(text="a" * (MESSAGE_MAX_LENGTH + 1))


def test_message_length_is_checked_after_trim() -> None:
    request = MessageAnalysisRequest(text="  " + "a" * MESSAGE_MAX_LENGTH + "  ")

    assert len(request.text) == MESSAGE_MAX_LENGTH


PRIVATE_TEXT = "my seed phrase " + "x" * MESSAGE_MAX_LENGTH


def test_message_text_is_not_exposed_in_model_errors() -> None:
    with pytest.raises(ValidationError) as exc_info:
        MessageAnalysisRequest(text=PRIVATE_TEXT)

    assert "seed phrase" not in str(exc_info.value)


def test_message_text_is_not_exposed_in_union_errors() -> None:
    with pytest.raises(ValidationError) as exc_info:
        analysis_request_adapter.validate_python(
            {"kind": "message", "text": PRIVATE_TEXT}
        )

    assert "seed phrase" not in str(exc_info.value)


# --- Extra fields -----------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "address", "network": "ethereum", "address": ETH_CHECKSUMMED},
        {"kind": "transaction", "network": "tron", "tx_hash": TRON_TX_HASH},
        {"kind": "message", "text": "hello"},
    ],
)
def test_unexpected_fields_are_rejected(payload: dict) -> None:
    with pytest.raises(ValidationError, match="extra"):
        analysis_request_adapter.validate_python({**payload, "score": 99})


# --- Discriminated union ----------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "expected_type"),
    [
        (
            {"kind": "address", "network": "tron", "address": TRON_USDT_CONTRACT},
            AddressAnalysisRequest,
        ),
        (
            {"kind": "transaction", "network": "ethereum", "tx_hash": ETH_TX_HASH},
            TransactionAnalysisRequest,
        ),
        ({"kind": "message", "text": "hello", "language": "fr"}, MessageAnalysisRequest),
    ],
)
def test_union_dispatches_on_kind(payload: dict, expected_type: type) -> None:
    request = analysis_request_adapter.validate_python(payload)

    assert isinstance(request, expected_type)


def test_union_parses_json() -> None:
    raw = (
        '{"kind": "address", "network": "ethereum", '
        f'"address": "{ETH_CHECKSUMMED.lower()}"}}'
    )
    request = analysis_request_adapter.validate_json(raw)

    assert isinstance(request, AddressAnalysisRequest)
    assert request.address == ETH_CHECKSUMMED


@pytest.mark.parametrize(
    "payload",
    [
        {"network": "ethereum", "address": ETH_CHECKSUMMED},  # missing kind
        {"kind": "wallet", "network": "ethereum", "address": ETH_CHECKSUMMED},
        {"kind": "address", "network": "ethereum", "tx_hash": ETH_TX_HASH},
    ],
)
def test_union_rejects_invalid_kind_or_shape(payload: dict) -> None:
    with pytest.raises(ValidationError):
        analysis_request_adapter.validate_python(payload)
