import copy
import json
import socket
from typing import Any

import base58
import pytest
from pydantic import ValidationError

from app.domain.analysis_input import Network
from app.domain.token_transfer import MAX_UINT256, NormalizedTokenTransfer
from app.providers.base import (
    ExecutionResultUnknownError,
    MalformedResponseError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    ReceiptUnavailableError,
    TransactionNotFoundError,
    TransactionUnconfirmedError,
    UnsupportedTransactionError,
)
from app.providers.ethereum import ERC20_TRANSFER_TOPIC
from app.providers.tron import (
    GET_SOLID_TRANSACTION_INFO_PATH,
    GET_SOLID_TRANSACTION_PATH,
    GET_TRANSACTION_PATH,
    TRC20_TRANSFER_TOPIC,
    TronApiError,
    TronProvider,
    decode_usdt_transfer_logs,
)

SECRET = "sk-tron-0123456789abcdef"
API_KEY = "a1b2c3d4-e5f6-7890-abcd-ef0123456789"
BASE_URL = f"https://tron.example.invalid/{SECRET}"

TX_HASH = "ab" * 32
OTHER_HASH = "ef" * 32

USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def b58(body20: bytes) -> str:
    return base58.b58encode_check(b"\x41" + body20).decode()


def body_hex(address: str) -> str:
    """20-byte hex body of a TRON address (no 41 prefix), as in event logs."""
    return base58.b58decode_check(address)[1:].hex()


ALICE = b58(bytes(range(1, 21)))
BOB = b58(bytes(range(21, 41)))
CAROL = b58(bytes(range(41, 61)))
DEX = b58(bytes(range(61, 81)))
FAKE_USDT = b58(b"\x11" * 20)  # any contract can call itself "Tether USD" / "USDT"
APPROVAL_TOPIC = "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("tests must not open network connections")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


def topic_address(address: str) -> str:
    return "0" * 24 + body_hex(address)


def transfer_log(
    sender: str = ALICE,
    recipient: str = BOB,
    amount: int = 35_000_000,
    emitter: str = USDT,
    **overrides: Any,
) -> dict[str, Any]:
    log = {
        "address": body_hex(emitter),
        "topics": [TRC20_TRANSFER_TOPIC, topic_address(sender), topic_address(recipient)],
        "data": format(amount, "064x"),
    }
    log.update(overrides)
    return log


def trigger_tx(contract: str = USDT, contract_ret: str = "SUCCESS") -> dict[str, Any]:
    return {
        "ret": [{"contractRet": contract_ret}],
        "txID": TX_HASH,
        "raw_data": {
            "contract": [
                {
                    "parameter": {
                        "value": {
                            "data": "a9059cbb" + topic_address(BOB) + format(35_000_000, "064x"),
                            "owner_address": "41" + body_hex(ALICE),
                            "contract_address": "41" + body_hex(contract),
                        },
                        "type_url": "type.googleapis.com/protocol.TriggerSmartContract",
                    },
                    "type": "TriggerSmartContract",
                }
            ],
            "timestamp": 1_705_000_000_000,
        },
    }


def transfer_tx() -> dict[str, Any]:
    return {
        "ret": [{"contractRet": "SUCCESS"}],
        "txID": TX_HASH,
        "raw_data": {
            "contract": [
                {
                    "parameter": {
                        "value": {
                            "amount": 5_072_200,
                            "owner_address": "41" + body_hex(ALICE),
                            "to_address": "41" + body_hex(BOB),
                        },
                        "type_url": "type.googleapis.com/protocol.TransferContract",
                    },
                    "type": "TransferContract",
                }
            ],
        },
    }


def tx_info(logs: Any = None, receipt_result: str | None = "SUCCESS", **overrides: Any) -> dict:
    info: dict[str, Any] = {
        "id": TX_HASH,
        "blockNumber": 60_000_000,
        "blockTimeStamp": 1_705_000_002_000,
        "receipt": {"net_usage": 345},
        "log": [transfer_log()] if logs is None else logs,
    }
    if receipt_result is not None:
        info["receipt"]["result"] = receipt_result
    info.update(overrides)
    return info


class FakeTransport:
    """Answers TRON HTTP API calls by path, without network."""

    def __init__(self, tx: Any = None, solid_tx: Any = None, info: Any = None) -> None:
        tx = trigger_tx() if tx is None else tx
        self.responses: dict[str, Any] = {
            GET_TRANSACTION_PATH: tx,
            GET_SOLID_TRANSACTION_PATH: copy.deepcopy(tx) if solid_tx is None else solid_tx,
            GET_SOLID_TRANSACTION_INFO_PATH: tx_info() if info is None else info,
        }
        self.raises: dict[str, Exception] = {}
        self.calls: list[str] = []

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        timeout: float,
        headers: dict[str, str] | None = None,
    ) -> Any:
        path = next(p for p in self.responses if url.endswith(p))
        self.calls.append(path)
        if path in self.raises:
            raise self.raises[path]
        return copy.deepcopy(self.responses[path])


def transfers_for(transport: FakeTransport, tx_hash: str = TX_HASH) -> list:
    return TronProvider(BASE_URL, transport=transport).get_usdt_transfers(tx_hash)


def with_logs(*logs: Any) -> FakeTransport:
    return FakeTransport(info=tx_info(logs=list(logs)))


def expected(sender: str, recipient: str, amount: int) -> NormalizedTokenTransfer:
    return NormalizedTokenTransfer(
        network=Network.TRON,
        tx_hash=TX_HASH,
        token_symbol="USDT",
        token_contract=USDT,
        from_address=sender,
        to_address=recipient,
        amount_atomic=amount,
        decimals=6,
        log_index=None,
    )


# --- Decoding ----------------------------------------------------------------


def test_transfer_topic_is_keccak_of_canonical_signature() -> None:
    assert TRC20_TRANSFER_TOPIC == (
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )
    assert "0x" + TRC20_TRANSFER_TOPIC == ERC20_TRANSFER_TOPIC


def test_single_usdt_transfer() -> None:
    transport = FakeTransport()

    transfers = transfers_for(transport)

    assert transfers == [expected(ALICE, BOB, 35_000_000)]
    assert transfers[0].format_amount() == "35.000000"
    assert transfers[0].log_index is None
    assert transport.calls == [
        GET_TRANSACTION_PATH,
        GET_SOLID_TRANSACTION_PATH,
        GET_SOLID_TRANSACTION_INFO_PATH,
    ]


def test_official_documentation_example_log() -> None:
    # Log example from https://developers.tron.network/docs/event
    log = {
        "address": "a614f803b6fd780986a42c78ec9c7f77e6ded13c",
        "topics": [
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "00000000000000000000000079309abcff2cf531070ca9222a1f72c4a5136874",
            "00000000000000000000000081b64b1c09d448d25c9eeb3ee3b8f3348a694c96",
        ],
        "data": "00000000000000000000000000000000000000000000000000000000b2d05e00",
    }

    transfers = decode_usdt_transfer_logs([log], TX_HASH)

    assert transfers == [
        expected(
            b58(bytes.fromhex("79309abcff2cf531070ca9222a1f72c4a5136874")),
            b58(bytes.fromhex("81b64b1c09d448d25c9eeb3ee3b8f3348a694c96")),
            3_000_000_000,
        )
    ]
    assert transfers[0].format_amount() == "3000.000000"


def test_multiple_transfers_keep_exact_emission_order_and_are_not_summed() -> None:
    transport = with_logs(
        transfer_log(ALICE, DEX, 105_000_000),
        transfer_log(DEX, BOB, 104_685_000),
        transfer_log(BOB, CAROL, 104_685_000),
    )

    assert transfers_for(transport) == [
        expected(ALICE, DEX, 105_000_000),
        expected(DEX, BOB, 104_685_000),
        expected(BOB, CAROL, 104_685_000),
    ]


def test_other_contracts_and_events_are_ignored() -> None:
    transport = FakeTransport(
        tx=trigger_tx(contract=DEX),  # called contract is not USDT
        info=tx_info(
            logs=[
                transfer_log(ALICE, DEX, 5, emitter=FAKE_USDT),
                transfer_log(ALICE, DEX, 6),
                transfer_log(ALICE, DEX, 7, topics=[APPROVAL_TOPIC, topic_address(ALICE),
                                                   topic_address(DEX)]),
                {"address": body_hex(DEX), "topics": [], "data": ""},
                {"address": body_hex(DEX), "data": "00"},  # proto3: topics omitted
                transfer_log(DEX, BOB, 8),
            ]
        ),
    )

    assert transfers_for(transport) == [expected(ALICE, DEX, 6), expected(DEX, BOB, 8)]


def test_fake_usdt_is_ignored() -> None:
    assert transfers_for(with_logs(transfer_log(emitter=FAKE_USDT, amount=10**12))) == []


def test_model_rejects_fake_usdt_contract() -> None:
    with pytest.raises(ValidationError, match="official USDT"):
        NormalizedTokenTransfer(
            **{**expected(ALICE, BOB, 1).model_dump(), "token_contract": FAKE_USDT}
        )


def test_usdt_log_with_other_signature_is_ignored() -> None:
    log = transfer_log(topics=["12" * 32, topic_address(ALICE), topic_address(BOB)])

    assert transfers_for(with_logs(log)) == []


def test_usdt_log_without_topics_is_ignored() -> None:
    log = transfer_log()
    del log["topics"]

    assert transfers_for(with_logs(log, transfer_log(topics=[]))) == []


def test_uppercase_hex_is_accepted_and_normalized() -> None:
    log = transfer_log(
        address=body_hex(USDT).upper(),
        topics=[t.upper() for t in transfer_log()["topics"]],
        data=format(35_000_000, "064X"),
    )

    assert transfers_for(with_logs(log)) == [expected(ALICE, BOB, 35_000_000)]


# --- Addresses ---------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "41" + body_hex(USDT),  # 21-byte form with prefix
        "0x" + body_hex(USDT),
        body_hex(USDT)[:-2],  # 19 bytes
        body_hex(USDT) + "00",  # 21 bytes
        "zz" * 20,
        USDT,  # Base58 instead of hex
        "",
        None,
        41,
    ],
)
def test_invalid_log_address_is_malformed(address: object) -> None:
    with pytest.raises(MalformedResponseError, match="log address"):
        transfers_for(with_logs(transfer_log(address=address)))


def test_log_address_gets_the_tron_prefix_before_base58check() -> None:
    # Treating the 20-byte body as a full 21-byte address would not give USDT.
    assert transfers_for(with_logs(transfer_log()))[0].token_contract == USDT


@pytest.mark.parametrize("position", [1, 2])
@pytest.mark.parametrize(
    "padding",
    ["00" * 11 + "41", "01" + "00" * 11, "00" * 11 + "ff", "80" + "00" * 11],
    ids=["tron-41-form", "high-byte", "low-byte", "sign-bit"],
)
def test_indexed_address_with_bad_padding_is_malformed(position: int, padding: str) -> None:
    topics = [TRC20_TRANSFER_TOPIC, topic_address(ALICE), topic_address(BOB)]
    topics[position] = padding + topics[position][24:]

    with pytest.raises(MalformedResponseError, match="zero-padded"):
        transfers_for(with_logs(transfer_log(topics=topics)))


# --- Topics and data ---------------------------------------------------------


@pytest.mark.parametrize(
    "topics",
    [
        [TRC20_TRANSFER_TOPIC],
        [TRC20_TRANSFER_TOPIC, topic_address(ALICE)],
        [TRC20_TRANSFER_TOPIC, topic_address(ALICE), topic_address(BOB), "00" * 32],
    ],
    ids=["1-topic", "2-topics", "4-topics"],
)
def test_wrong_topic_count_is_malformed(topics: list[str]) -> None:
    with pytest.raises(MalformedResponseError, match="3 topics"):
        transfers_for(with_logs(transfer_log(topics=topics)))


@pytest.mark.parametrize(
    "bad",
    ["00" * 31, "00" * 33, "0x" + "00" * 32, "zz" * 32, "", None, 7],
    ids=["31-bytes", "33-bytes", "0x-prefix", "non-hex", "empty", "null", "number"],
)
def test_malformed_topic_is_rejected(bad: object) -> None:
    log = transfer_log(topics=[TRC20_TRANSFER_TOPIC, bad, topic_address(BOB)])

    with pytest.raises(MalformedResponseError, match="topic"):
        transfers_for(with_logs(log))


@pytest.mark.parametrize("topics", ["ddf252ad", {"0": TRC20_TRANSFER_TOPIC}, 0])
def test_non_list_topics_is_malformed(topics: object) -> None:
    with pytest.raises(MalformedResponseError, match="topics"):
        transfers_for(with_logs(transfer_log(topics=topics)))


@pytest.mark.parametrize(
    "data",
    ["", "00" * 31, "00" * 33, "00" * 64, "0x" + "00" * 32, "zz" * 32, None, 35_000_000],
    ids=["empty", "31", "33", "two-words", "0x", "non-hex", "null", "number"],
)
def test_invalid_data_is_malformed(data: object) -> None:
    with pytest.raises(MalformedResponseError, match="data"):
        transfers_for(with_logs(transfer_log(data=data)))


@pytest.mark.parametrize("log", ["not a log", None, [], 3])
def test_non_object_log_is_malformed(log: object) -> None:
    with pytest.raises(MalformedResponseError, match="log"):
        transfers_for(with_logs(log))


def test_malformed_usdt_event_among_valid_ones_fails_whole_receipt() -> None:
    transport = with_logs(transfer_log(), transfer_log(data="00"), transfer_log())

    with pytest.raises(MalformedResponseError):
        transfers_for(transport)


# --- Amounts -----------------------------------------------------------------


def test_zero_amount_is_kept() -> None:
    transfers = transfers_for(with_logs(transfer_log(amount=0)))

    assert transfers == [expected(ALICE, BOB, 0)]
    assert transfers[0].format_amount() == "0.000000"


def test_max_uint256_is_exact() -> None:
    transfer = transfers_for(with_logs(transfer_log(amount=MAX_UINT256)))[0]

    assert type(transfer.amount_atomic) is int
    assert transfer.amount_atomic == 2**256 - 1
    whole, fraction = divmod(MAX_UINT256, 10**6)
    assert transfer.format_amount() == f"{whole}.{fraction:06d}"


@pytest.mark.parametrize(
    ("atomic", "text"),
    [(1, "0.000001"), (999_999, "0.999999"), (35_000_000, "35.000000"), (10**12, "1000000.000000")],
)
def test_format_amount_is_exact(atomic: int, text: str) -> None:
    assert expected(ALICE, BOB, atomic).format_amount() == text


def test_token_amount_is_not_the_native_trx_value() -> None:
    tx = trigger_tx()
    tx["raw_data"]["contract"][0]["parameter"]["value"]["call_value"] = 7_000_000
    transport = FakeTransport(tx=tx)

    transfers = transfers_for(transport)
    native = TronProvider(BASE_URL, transport=FakeTransport(tx=tx)).get_transaction(TX_HASH)

    assert transfers[0].amount_atomic == 35_000_000
    assert native.native_value_atomic == 7_000_000


# --- Receipts without USDT events -------------------------------------------


def test_receipt_without_log_field_returns_empty_list() -> None:
    info = tx_info()
    del info["log"]

    assert transfers_for(FakeTransport(info=info)) == []


def test_receipt_with_empty_logs_returns_empty_list() -> None:
    assert transfers_for(with_logs()) == []


def test_native_trx_transfer_has_no_usdt_transfer() -> None:
    info = tx_info(receipt_result=None)
    del info["log"]

    assert transfers_for(FakeTransport(tx=transfer_tx(), info=info)) == []


def test_contract_call_parameters_are_not_turned_into_a_transfer() -> None:
    # The call data encodes transfer(BOB, 35 USDT) but no Transfer was emitted.
    transport = FakeTransport(info=tx_info(logs=[]))

    assert transfers_for(transport) == []


@pytest.mark.parametrize("logs", ["[]", {}, 0], ids=["string", "object", "number"])
def test_invalid_log_container_is_malformed(logs: object) -> None:
    with pytest.raises(MalformedResponseError, match="logs"):
        transfers_for(FakeTransport(info=tx_info(logs=logs)))


# --- Statuses ----------------------------------------------------------------


def test_reverted_transaction_has_no_transfer() -> None:
    info = tx_info(logs=[], receipt_result="REVERT", result="FAILED")
    del info["log"]
    transport = FakeTransport(tx=trigger_tx(contract_ret="REVERT"), info=info)

    assert transfers_for(transport) == []


def test_reverted_receipt_with_logs_is_malformed() -> None:
    info = tx_info(receipt_result="REVERT", result="FAILED")
    transport = FakeTransport(tx=trigger_tx(contract_ret="REVERT"), info=info)

    with pytest.raises(MalformedResponseError, match="reverted"):
        transfers_for(transport)


def test_unconfirmed_transaction_is_an_explicit_error() -> None:
    transport = FakeTransport(solid_tx={})

    with pytest.raises(TransactionUnconfirmedError):
        transfers_for(transport)
    assert GET_SOLID_TRANSACTION_INFO_PATH not in transport.calls


def test_unknown_transaction_raises_not_found() -> None:
    transport = FakeTransport(tx={})

    with pytest.raises(TransactionNotFoundError):
        transfers_for(transport)
    assert transport.calls == [GET_TRANSACTION_PATH]


def test_unavailable_receipt_is_reported() -> None:
    with pytest.raises(ReceiptUnavailableError, match="retry later"):
        transfers_for(FakeTransport(info={}))


@pytest.mark.parametrize(
    ("tx", "info"),
    [
        (trigger_tx(contract_ret="UNKNOWN"), tx_info(receipt_result="UNKNOWN")),
        (trigger_tx(), tx_info(receipt_result=None)),  # contract call without result
    ],
    ids=["unknown-ret", "missing-receipt-result"],
)
def test_unknown_execution_result_never_yields_transfers(tx: dict, info: dict) -> None:
    with pytest.raises(ExecutionResultUnknownError):
        transfers_for(FakeTransport(tx=tx, info=info))


def test_unsupported_contract_type_keeps_existing_policy() -> None:
    tx = trigger_tx()
    tx["raw_data"]["contract"][0]["type"] = "TransferAssetContract"

    with pytest.raises(UnsupportedTransactionError):
        transfers_for(FakeTransport(tx=tx))


# --- API errors and consistency ---------------------------------------------


@pytest.mark.parametrize(
    ("path", "response"),
    [
        (GET_SOLID_TRANSACTION_INFO_PATH, []),
        (GET_SOLID_TRANSACTION_INFO_PATH, None),
        (GET_TRANSACTION_PATH, "ok"),
    ],
)
def test_malformed_api_response(path: str, response: object) -> None:
    transport = FakeTransport()
    transport.responses[path] = response

    with pytest.raises(MalformedResponseError):
        transfers_for(transport)


def test_tron_error_payload_is_reported() -> None:
    transport = FakeTransport()
    transport.responses[GET_SOLID_TRANSACTION_INFO_PATH] = {"Error": f"boom {SECRET}"}

    with pytest.raises(TronApiError) as exc_info:
        transfers_for(transport)
    assert SECRET not in str(exc_info.value)


@pytest.mark.parametrize(
    ("path", "change"),
    [
        (GET_TRANSACTION_PATH, {"txID": OTHER_HASH}),
        (GET_SOLID_TRANSACTION_PATH, {"txID": OTHER_HASH}),
        (GET_SOLID_TRANSACTION_INFO_PATH, {"id": OTHER_HASH}),
        (GET_SOLID_TRANSACTION_INFO_PATH, {"id": None}),
    ],
)
def test_transaction_id_mismatch_is_malformed(path: str, change: dict) -> None:
    transport = FakeTransport()
    transport.responses[path] = {**transport.responses[path], **change}

    with pytest.raises(MalformedResponseError):
        transfers_for(transport)


@pytest.mark.parametrize(
    "error",
    [
        ProviderUnavailableError("RPC endpoint returned HTTP 429"),
        ProviderTimeoutError("RPC request timed out"),
    ],
    ids=["http-429", "timeout"],
)
@pytest.mark.parametrize("path", [GET_TRANSACTION_PATH, GET_SOLID_TRANSACTION_INFO_PATH])
def test_transport_failures_propagate(path: str, error: ProviderError) -> None:
    transport = FakeTransport()
    transport.raises[path] = error

    with pytest.raises(type(error)):
        transfers_for(transport)


@pytest.mark.parametrize("tx_hash", ["", "0x" + "ab" * 32, "ab" * 31, "zz" * 32])
def test_invalid_hash_is_rejected_without_request(tx_hash: str) -> None:
    transport = FakeTransport()

    with pytest.raises(ValueError):
        transfers_for(transport, tx_hash)
    assert transport.calls == []


def test_get_transaction_is_unchanged_by_the_shared_lookup() -> None:
    transport = FakeTransport()
    provider = TronProvider(BASE_URL, transport=transport)

    tx = provider.get_transaction(TX_HASH)

    assert tx.status.value == "success"
    assert tx.to_address == USDT
    assert tx.native_value_atomic == 0
    assert len(transport.calls) == 3


# --- Secrets -----------------------------------------------------------------


def _failing_transports() -> list[FakeTransport]:
    api_error = FakeTransport()
    api_error.responses[GET_SOLID_TRANSACTION_INFO_PATH] = {"Error": f"{API_KEY} {BASE_URL}"}
    return [
        api_error,
        FakeTransport(tx={}),
        FakeTransport(solid_tx={}),
        FakeTransport(info={}),
        with_logs(transfer_log(data="00")),
    ]


@pytest.mark.parametrize(
    "transport",
    _failing_transports(),
    ids=["api-error", "not-found", "unconfirmed", "receipt-unavailable", "malformed"],
)
def test_errors_do_not_expose_secrets(transport: FakeTransport) -> None:
    provider = TronProvider(BASE_URL, api_key=API_KEY, transport=transport)

    with pytest.raises(ProviderError) as exc_info:
        provider.get_usdt_transfers(TX_HASH)

    for secret in (SECRET, API_KEY):
        assert secret not in str(exc_info.value)
        assert secret not in repr(exc_info.value)
        assert secret not in repr(provider)


# --- Model -------------------------------------------------------------------


def test_transfer_model_is_immutable() -> None:
    transfer = expected(ALICE, BOB, 1)

    with pytest.raises(ValidationError):
        transfer.to_address = CAROL  # type: ignore[misc]


def test_large_amount_survives_json_round_trip() -> None:
    transfer = expected(ALICE, BOB, MAX_UINT256)

    dumped = transfer.model_dump_json()

    assert json.loads(dumped)["amount_atomic"] == MAX_UINT256
    assert NormalizedTokenTransfer.model_validate_json(dumped) == transfer


def test_tron_and_ethereum_transfers_share_the_same_model() -> None:
    tron = expected(ALICE, BOB, 35_000_000)
    ethereum = NormalizedTokenTransfer(
        network=Network.ETHEREUM,
        tx_hash="0x" + "ab" * 32,
        token_symbol="USDT",
        token_contract="0xdAC17F958D2ee523a2206206994597C13D831ec7",
        from_address="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        to_address="0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        amount_atomic=35_000_000,
        decimals=6,
        log_index=4,
    )

    assert type(tron) is type(ethereum)
    assert set(tron.model_dump()) == set(ethereum.model_dump())
    assert tron.format_amount() == ethereum.format_amount() == "35.000000"


@pytest.mark.parametrize(
    "overrides",
    [
        {"token_contract": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u"},  # bad checksum
        {"from_address": "41" + body_hex(ALICE)},  # hex, not Base58Check
        {"to_address": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"},
        {"tx_hash": "0x" + TX_HASH},
        {"decimals": 18},
        {"amount_atomic": 1.0},
        {"log_index": -1},
    ],
)
def test_tron_transfer_model_rejects_invalid_values(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        NormalizedTokenTransfer(**{**expected(ALICE, BOB, 1).model_dump(), **overrides})


# --- No network --------------------------------------------------------------


def test_default_transport_cannot_reach_network_in_tests() -> None:
    provider = TronProvider(BASE_URL)  # real UrllibTransport

    with pytest.raises((AssertionError, ProviderError)):
        provider.get_usdt_transfers(TX_HASH)
