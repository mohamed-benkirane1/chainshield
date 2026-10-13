import json
import socket
from typing import Any

import pytest
from pydantic import ValidationError

from app.domain.analysis_input import Network
from app.domain.token_transfer import MAX_UINT256, NormalizedTokenTransfer
from app.domain.usdt_registry import get_usdt_contract
from app.providers.base import (
    ChainMismatchError,
    ExecutionResultUnknownError,
    MalformedResponseError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    ReceiptUnavailableError,
    RpcError,
    TransactionNotFoundError,
    TransactionPendingError,
)
from app.providers.ethereum import (
    ERC20_TRANSFER_TOPIC,
    EthereumProvider,
    decode_usdt_transfer_logs,
)

SECRET = "sk-test-0123456789abcdef"
RPC_URL = f"https://rpc.example.invalid/v3/{SECRET}"

TX_HASH = "0x" + "ab" * 32
OTHER_HASH = "0x" + "ef" * 32
BLOCK_HASH = "0x" + "cd" * 32
BLOCK_NUMBER = 19_000_000

USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
BOB = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
CAROL = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
DEX_ROUTER = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
FAKE_USDT = "0x" + "11" * 20  # any contract can call itself "Tether USD" / "USDT"

APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("tests must not open network connections")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


def topic_address(address: str) -> str:
    return "0x" + "0" * 24 + address[2:].lower()


def transfer_log(
    sender: str = ALICE,
    recipient: str = BOB,
    amount: int = 35_000_000,
    log_index: int = 0,
    emitter: str = USDT,
    **overrides: Any,
) -> dict[str, Any]:
    log = {
        "address": emitter.lower(),
        "topics": [ERC20_TRANSFER_TOPIC, topic_address(sender), topic_address(recipient)],
        "data": "0x" + format(amount, "064x"),
        "blockNumber": hex(BLOCK_NUMBER),
        "blockHash": BLOCK_HASH,
        "transactionHash": TX_HASH,
        "transactionIndex": "0x5",
        "logIndex": hex(log_index),
        "removed": False,
    }
    log.update(overrides)
    return log


def rpc_tx(**overrides: Any) -> dict[str, Any]:
    tx = {
        "hash": TX_HASH,
        "from": ALICE.lower(),
        "to": USDT.lower(),
        "value": "0x0",
        "blockNumber": hex(BLOCK_NUMBER),
        "blockHash": BLOCK_HASH,
    }
    tx.update(overrides)
    return tx


def rpc_receipt(logs: Any = None, **overrides: Any) -> dict[str, Any]:
    receipt = {
        "transactionHash": TX_HASH,
        "blockHash": BLOCK_HASH,
        "blockNumber": hex(BLOCK_NUMBER),
        "status": "0x1",
        "logs": [transfer_log()] if logs is None else logs,
    }
    receipt.update(overrides)
    return receipt


class FakeTransport:
    """Answers JSON-RPC calls from a method -> result table, without network."""

    def __init__(self, results: dict[str, Any] | None = None) -> None:
        self.results = {
            "eth_chainId": "0x1",
            "eth_getTransactionByHash": rpc_tx(),
            "eth_getTransactionReceipt": rpc_receipt(),
        }
        self.results.update(results or {})
        self.envelopes: dict[str, Any] = {}
        self.raises: dict[str, Exception] = {}
        self.calls: list[tuple[str, list[Any]]] = []

    def post_json(self, url: str, payload: dict[str, Any], timeout: float) -> Any:
        method = payload["method"]
        self.calls.append((method, payload["params"]))
        if method in self.raises:
            raise self.raises[method]
        if method in self.envelopes:
            return self.envelopes[method](payload)
        return {"jsonrpc": "2.0", "id": payload["id"], "result": self.results[method]}

    @property
    def methods(self) -> list[str]:
        return [method for method, _ in self.calls]


def transfers_for(transport: FakeTransport, tx_hash: str = TX_HASH) -> list:
    return EthereumProvider(RPC_URL, transport=transport).get_usdt_transfers(tx_hash)


def with_logs(*logs: dict[str, Any]) -> FakeTransport:
    return FakeTransport({"eth_getTransactionReceipt": rpc_receipt(logs=list(logs))})


def expected(sender: str, recipient: str, amount: int, log_index: int) -> NormalizedTokenTransfer:
    return NormalizedTokenTransfer(
        network=Network.ETHEREUM,
        tx_hash=TX_HASH,
        token_symbol="USDT",
        token_contract=USDT,
        from_address=sender,
        to_address=recipient,
        amount_atomic=amount,
        decimals=6,
        log_index=log_index,
    )


# --- 1-3, 19-20: decoding --------------------------------------------------


def test_transfer_topic_is_keccak_of_canonical_signature() -> None:
    assert ERC20_TRANSFER_TOPIC == (
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )


def test_single_usdt_transfer() -> None:
    transport = FakeTransport()

    transfers = transfers_for(transport)

    assert transfers == [expected(ALICE, BOB, 35_000_000, 0)]
    assert transfers[0].format_amount() == "35.000000"
    assert transport.methods == [
        "eth_chainId",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
    ]


def test_multiple_usdt_transfers_are_kept_in_order_and_not_summed() -> None:
    transport = with_logs(
        transfer_log(ALICE, BOB, 1_000_000, log_index=7),
        transfer_log(BOB, CAROL, 2_500_000, log_index=8),
        transfer_log(CAROL, ALICE, 1_000_000, log_index=9),
    )

    assert transfers_for(transport) == [
        expected(ALICE, BOB, 1_000_000, 7),
        expected(BOB, CAROL, 2_500_000, 8),
        expected(CAROL, ALICE, 1_000_000, 9),
    ]


def test_transfer_through_intermediate_contract() -> None:
    # The user calls a DEX router; the router moves USDT. tx.to is not USDT.
    transport = FakeTransport(
        {
            "eth_getTransactionByHash": rpc_tx(to=DEX_ROUTER.lower(), value="0x16345785d8a0000"),
            "eth_getTransactionReceipt": rpc_receipt(
                logs=[
                    transfer_log(ALICE, DEX_ROUTER, 10**18, 0, emitter=FAKE_USDT),
                    transfer_log(DEX_ROUTER, ALICE, 99_000_000, 1),
                ]
            ),
        }
    )

    transfers = transfers_for(transport)

    assert transfers == [expected(DEX_ROUTER, ALICE, 99_000_000, 1)]
    assert transfers[0].to_address == ALICE  # from the event, not from tx.to


def test_logs_from_several_contracts_keep_only_usdt_transfers() -> None:
    transport = with_logs(
        transfer_log(ALICE, BOB, 5, 3),
        transfer_log(ALICE, BOB, 6, 4, emitter=FAKE_USDT),
        transfer_log(ALICE, BOB, 7, 5, topics=[APPROVAL_TOPIC, topic_address(ALICE),
                                             topic_address(BOB)]),  # USDT Approval
        {**transfer_log(log_index=6, emitter=DEX_ROUTER), "topics": [], "data": "0x"},
        transfer_log(BOB, CAROL, 8, 7),
    )

    assert transfers_for(transport) == [
        expected(ALICE, BOB, 5, 3),
        expected(BOB, CAROL, 8, 7),
    ]


def test_successful_transaction_without_usdt_transfer_returns_empty_list() -> None:
    assert transfers_for(with_logs()) == []
    assert transfers_for(with_logs(transfer_log(emitter=FAKE_USDT))) == []


# --- 4-5: token identification ----------------------------------------------


def test_transfer_from_wrong_contract_is_ignored() -> None:
    transport = with_logs(transfer_log(emitter=DEX_ROUTER))

    assert transfers_for(transport) == []


def test_fake_token_with_usdt_symbol_is_ignored() -> None:
    # Name/symbol never reach the decoder: only the emitting address counts.
    transport = with_logs(transfer_log(emitter=FAKE_USDT, amount=10**12))

    assert transfers_for(transport) == []


def test_model_rejects_a_fake_usdt_contract() -> None:
    with pytest.raises(ValidationError, match="official USDT"):
        NormalizedTokenTransfer(
            **{**expected(ALICE, BOB, 1, 0).model_dump(), "token_contract": FAKE_USDT}
        )


# --- 6-9: malformed official events -----------------------------------------


def test_usdt_log_with_another_topic0_is_ignored() -> None:
    log = transfer_log(topics=["0x" + "12" * 32, topic_address(ALICE), topic_address(BOB)])

    assert transfers_for(with_logs(log)) == []


def test_usdt_log_without_topics_is_ignored() -> None:
    assert transfers_for(with_logs(transfer_log(topics=[]))) == []


@pytest.mark.parametrize(
    "topics",
    [
        [ERC20_TRANSFER_TOPIC],
        [ERC20_TRANSFER_TOPIC, topic_address(ALICE)],
        [ERC20_TRANSFER_TOPIC, topic_address(ALICE), topic_address(BOB), "0x" + "00" * 32],
    ],
    ids=["1-topic", "2-topics", "4-topics"],
)
def test_usdt_transfer_with_wrong_topic_count_is_malformed(topics: list[str]) -> None:
    with pytest.raises(MalformedResponseError, match="3 topics"):
        transfers_for(with_logs(transfer_log(topics=topics)))


@pytest.mark.parametrize(
    "bad_topic",
    [
        "0x" + "00" * 31,  # 31 bytes
        "0x" + "00" * 33,  # 33 bytes
        "00" * 32,  # no 0x
        "0x" + "zz" * 32,
        None,
        42,
    ],
)
def test_usdt_log_with_invalid_topic_format_is_malformed(bad_topic: object) -> None:
    log = transfer_log(topics=[ERC20_TRANSFER_TOPIC, bad_topic, topic_address(BOB)])

    with pytest.raises(MalformedResponseError, match="topic"):
        transfers_for(with_logs(log))


@pytest.mark.parametrize("position", [1, 2])
@pytest.mark.parametrize("padding", ["01" + "00" * 11, "00" * 11 + "ff", "80" + "00" * 11])
def test_indexed_address_with_bad_padding_is_malformed(position: int, padding: str) -> None:
    topics = [ERC20_TRANSFER_TOPIC, topic_address(ALICE), topic_address(BOB)]
    topics[position] = "0x" + padding + topics[position][26:]

    with pytest.raises(MalformedResponseError, match="zero-padded"):
        transfers_for(with_logs(transfer_log(topics=topics)))


@pytest.mark.parametrize(
    "data",
    [
        "0x",
        "0x" + "00" * 31,
        "0x" + "00" * 33,
        "0x" + "00" * 64,  # two words: not a single uint256
        "0x" + "zz" * 32,
        "00" * 32,
        None,
        35_000_000,
    ],
)
def test_usdt_transfer_with_invalid_data_is_malformed(data: object) -> None:
    with pytest.raises(MalformedResponseError, match="data"):
        transfers_for(with_logs(transfer_log(data=data)))


def test_uppercase_hex_is_accepted_and_normalized() -> None:
    log = transfer_log(
        address="0x" + USDT[2:].upper(),
        topics=["0x" + t[2:].upper() for t in transfer_log()["topics"]],
        data="0x" + format(35_000_000, "064X"),
    )

    assert transfers_for(with_logs(log)) == [expected(ALICE, BOB, 35_000_000, 0)]


# --- 10-11: amounts ---------------------------------------------------------


def test_zero_amount_transfer_is_kept() -> None:
    transfers = transfers_for(with_logs(transfer_log(amount=0)))

    assert transfers == [expected(ALICE, BOB, 0, 0)]
    assert transfers[0].format_amount() == "0.000000"


def test_max_uint256_amount_is_exact() -> None:
    transfers = transfers_for(with_logs(transfer_log(amount=MAX_UINT256)))

    assert type(transfers[0].amount_atomic) is int
    assert transfers[0].amount_atomic == 2**256 - 1
    whole, fraction = divmod(2**256 - 1, 10**6)
    assert transfers[0].format_amount() == f"{whole}.{fraction:06d}"


def test_amount_is_not_the_native_value() -> None:
    transport = FakeTransport({"eth_getTransactionByHash": rpc_tx(value=hex(10**18))})

    assert transfers_for(transport)[0].amount_atomic == 35_000_000


@pytest.mark.parametrize(
    ("atomic", "text"),
    [(1, "0.000001"), (999_999, "0.999999"), (1_000_000, "1.000000"), (35_000_000, "35.000000")],
)
def test_format_amount_is_exact(atomic: int, text: str) -> None:
    assert expected(ALICE, BOB, atomic, 0).format_amount() == text


# --- 12-13, 21-22: log metadata ----------------------------------------------


@pytest.mark.parametrize("log_index", [None, 3, "3", "0x", "0xZ", -1])
def test_invalid_log_index_is_malformed(log_index: object) -> None:
    log = transfer_log()
    log["logIndex"] = log_index

    with pytest.raises(MalformedResponseError, match="log index"):
        transfers_for(with_logs(log))


@pytest.mark.parametrize(
    "indexes", [(5, 4), (5, 5), (2, 9, 3)], ids=["decreasing", "duplicate", "unsorted"]
)
def test_out_of_order_logs_are_malformed(indexes: tuple[int, ...]) -> None:
    logs = [transfer_log(log_index=i) for i in indexes]

    with pytest.raises(MalformedResponseError, match="order"):
        transfers_for(with_logs(*logs))


@pytest.mark.parametrize("emitter", [USDT, DEX_ROUTER], ids=["usdt-log", "other-log"])
@pytest.mark.parametrize(
    "overrides",
    [
        {"transactionHash": OTHER_HASH},
        {"blockHash": OTHER_HASH},
        {"blockNumber": hex(BLOCK_NUMBER + 1)},
    ],
    ids=["tx-hash", "block-hash", "block-number"],
)
def test_log_inconsistent_with_transaction_is_malformed(emitter: str, overrides: dict) -> None:
    with pytest.raises(MalformedResponseError, match="does not match"):
        transfers_for(with_logs(transfer_log(emitter=emitter, **overrides)))


@pytest.mark.parametrize(
    "overrides",
    [{"transactionHash": None}, {"blockHash": "0x12"}, {"blockNumber": None}],
)
def test_log_with_missing_metadata_is_malformed(overrides: dict) -> None:
    with pytest.raises(MalformedResponseError):
        transfers_for(with_logs(transfer_log(**overrides)))


@pytest.mark.parametrize(
    "overrides",
    [
        {"blockHash": OTHER_HASH},
        {"blockNumber": hex(BLOCK_NUMBER - 1)},
        {"transactionHash": OTHER_HASH},
    ],
)
def test_receipt_inconsistent_with_transaction_is_malformed(overrides: dict) -> None:
    transport = FakeTransport({"eth_getTransactionReceipt": rpc_receipt(**overrides)})

    with pytest.raises(MalformedResponseError, match="receipt does not match"):
        transfers_for(transport)


@pytest.mark.parametrize("removed", [True, "false", 0, None])
def test_removed_or_invalid_removed_flag_is_rejected(removed: object) -> None:
    with pytest.raises(MalformedResponseError, match="removed"):
        transfers_for(with_logs(transfer_log(removed=removed)))


def test_missing_removed_flag_is_accepted() -> None:
    log = transfer_log()
    del log["removed"]

    assert transfers_for(with_logs(log)) == [expected(ALICE, BOB, 35_000_000, 0)]


@pytest.mark.parametrize(
    "log",
    [
        "not a log",
        transfer_log(address="0x1234"),
        transfer_log(address=None),
        transfer_log(topics=None),
        transfer_log(topics="0xddf2"),
    ],
)
def test_structurally_invalid_log_is_malformed(log: object) -> None:
    with pytest.raises(MalformedResponseError):
        transfers_for(with_logs(log))  # type: ignore[arg-type]


@pytest.mark.parametrize("logs", ["[]", {}, 0], ids=["string", "object", "number"])
def test_invalid_receipt_logs_container_is_malformed(logs: object) -> None:
    transport = FakeTransport({"eth_getTransactionReceipt": rpc_receipt(logs=logs)})

    with pytest.raises(MalformedResponseError, match="logs"):
        transfers_for(transport)


def test_missing_receipt_logs_is_malformed() -> None:
    receipt = rpc_receipt()
    del receipt["logs"]

    with pytest.raises(MalformedResponseError, match="logs"):
        transfers_for(FakeTransport({"eth_getTransactionReceipt": receipt}))


# --- 14-18: transaction status ----------------------------------------------


def test_reverted_transaction_has_no_transfers() -> None:
    transport = FakeTransport({"eth_getTransactionReceipt": rpc_receipt(status="0x0", logs=[])})

    assert transfers_for(transport) == []


def test_reverted_receipt_with_logs_is_malformed() -> None:
    transport = FakeTransport({"eth_getTransactionReceipt": rpc_receipt(status="0x0")})

    with pytest.raises(MalformedResponseError, match="reverted"):
        transfers_for(transport)


def test_pending_transaction_is_an_explicit_error() -> None:
    transport = FakeTransport(
        {"eth_getTransactionByHash": rpc_tx(blockNumber=None, blockHash=None)}
    )

    with pytest.raises(TransactionPendingError):
        transfers_for(transport)
    assert "eth_getTransactionReceipt" not in transport.methods


def test_unknown_transaction_is_an_explicit_error() -> None:
    transport = FakeTransport({"eth_getTransactionByHash": None})

    with pytest.raises(TransactionNotFoundError):
        transfers_for(transport)
    assert "eth_getTransactionReceipt" not in transport.methods


def test_unavailable_receipt_is_reported() -> None:
    transport = FakeTransport({"eth_getTransactionReceipt": None})

    with pytest.raises(ReceiptUnavailableError, match="retry later"):
        transfers_for(transport)


@pytest.mark.parametrize("status", [None, "missing"])
def test_unknown_execution_status_is_never_success(status: object) -> None:
    receipt = rpc_receipt(status=status)
    if status == "missing":
        del receipt["status"]

    with pytest.raises(ExecutionResultUnknownError):
        transfers_for(FakeTransport({"eth_getTransactionReceipt": receipt}))


@pytest.mark.parametrize("status", ["0x2", "0x", "1", 1])
def test_invalid_execution_status_is_malformed(status: object) -> None:
    transport = FakeTransport({"eth_getTransactionReceipt": rpc_receipt(status=status)})

    with pytest.raises(MalformedResponseError, match="status"):
        transfers_for(transport)


def test_transaction_hash_mismatch_is_malformed() -> None:
    transport = FakeTransport({"eth_getTransactionByHash": rpc_tx(hash=OTHER_HASH)})

    with pytest.raises(MalformedResponseError, match="different transaction"):
        transfers_for(transport)


@pytest.mark.parametrize("tx_hash", ["", "0x1234", "ab" * 32])
def test_invalid_hash_is_rejected_without_rpc_call(tx_hash: str) -> None:
    transport = FakeTransport()

    with pytest.raises(ValueError):
        transfers_for(transport, tx_hash)
    assert transport.calls == []


# --- 23-24: chain and RPC failures ------------------------------------------


@pytest.mark.parametrize("chain_id", ["0x5", "0xaa36a7", "0x38"])
def test_wrong_chain_id_is_rejected_before_lookup(chain_id: str) -> None:
    transport = FakeTransport({"eth_chainId": chain_id})

    with pytest.raises(ChainMismatchError):
        transfers_for(transport)
    assert transport.methods == ["eth_chainId"]


@pytest.mark.parametrize(
    "error",
    [
        ProviderTimeoutError("RPC request timed out"),
        ProviderUnavailableError("RPC endpoint returned HTTP 429"),
    ],
    ids=["timeout", "http-429"],
)
@pytest.mark.parametrize("method", ["eth_getTransactionByHash", "eth_getTransactionReceipt"])
def test_transport_failures_propagate(method: str, error: ProviderError) -> None:
    transport = FakeTransport()
    transport.raises[method] = error

    with pytest.raises(type(error)):
        transfers_for(transport)


@pytest.mark.parametrize(
    "method", ["eth_chainId", "eth_getTransactionByHash", "eth_getTransactionReceipt"]
)
def test_rpc_error_is_raised(method: str) -> None:
    transport = FakeTransport()
    transport.envelopes[method] = lambda payload: {
        "jsonrpc": "2.0",
        "id": payload["id"],
        "error": {"code": -32000, "message": "missing trie node"},
    }

    with pytest.raises(RpcError) as exc_info:
        transfers_for(transport)
    assert exc_info.value.method == method


# --- 25: secrets -------------------------------------------------------------


def _failing_transports() -> list[FakeTransport]:
    rpc_error = FakeTransport()
    rpc_error.envelopes["eth_getTransactionReceipt"] = lambda payload: {
        "jsonrpc": "2.0",
        "id": payload["id"],
        "error": {"code": -32001, "message": f"bad key {SECRET} for {RPC_URL}"},
    }
    return [
        rpc_error,
        FakeTransport({"eth_chainId": "0x5"}),
        FakeTransport({"eth_getTransactionByHash": None}),
        FakeTransport({"eth_getTransactionReceipt": None}),
        with_logs(transfer_log(data="0x12")),
    ]


@pytest.mark.parametrize(
    "transport",
    _failing_transports(),
    ids=["rpc-error", "wrong-chain", "not-found", "receipt-unavailable", "malformed"],
)
def test_errors_do_not_expose_secrets(transport: FakeTransport) -> None:
    provider = EthereumProvider(RPC_URL, transport=transport)

    with pytest.raises(ProviderError) as exc_info:
        provider.get_usdt_transfers(TX_HASH)

    assert SECRET not in str(exc_info.value)
    assert SECRET not in repr(exc_info.value)
    assert SECRET not in repr(provider)


# --- 26-27: model -----------------------------------------------------------


def test_transfer_model_is_immutable() -> None:
    transfer = expected(ALICE, BOB, 1, 0)

    with pytest.raises(ValidationError):
        transfer.amount_atomic = 2  # type: ignore[misc]


def test_large_amount_survives_json_round_trip() -> None:
    transfer = expected(ALICE, BOB, MAX_UINT256, 0)

    dumped = transfer.model_dump_json()

    assert json.loads(dumped)["amount_atomic"] == MAX_UINT256
    assert str(MAX_UINT256) in dumped
    assert NormalizedTokenTransfer.model_validate_json(dumped) == transfer


def _fields(**overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "network": Network.ETHEREUM,
        "tx_hash": TX_HASH,
        "token_symbol": "USDT",
        "token_contract": USDT,
        "from_address": ALICE,
        "to_address": BOB,
        "amount_atomic": 1,
        "decimals": 6,
        "log_index": 0,
    }
    fields.update(overrides)
    return fields


@pytest.mark.parametrize(
    "overrides",
    [
        {"amount_atomic": 1.0},
        {"amount_atomic": "1"},
        {"amount_atomic": True},
        {"amount_atomic": -1},
        {"amount_atomic": MAX_UINT256 + 1},
        {"decimals": 18},
        {"decimals": 6.0},
        {"log_index": None},
        {"log_index": -1},
        {"log_index": 1.0},
        {"token_symbol": "USDC"},
        {"token_contract": USDT.lower()},  # not canonical
        {"from_address": ALICE.lower()},
        {"to_address": "0x1234"},
        {"tx_hash": TX_HASH.upper().replace("0X", "0x")},
        {"tx_hash": "ab" * 32},
        {"network": Network.TRON},  # Ethereum contract on TRON
        {"extra": "field"},
    ],
)
def test_transfer_model_rejects_invalid_values(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        NormalizedTokenTransfer(**_fields(**overrides))


def test_transfer_model_supports_tron_without_log_index() -> None:
    tron_usdt = get_usdt_contract(Network.TRON).contract_address
    transfer = NormalizedTokenTransfer(
        network=Network.TRON,
        tx_hash="cd" * 32,
        token_symbol="USDT",
        token_contract=tron_usdt,
        from_address=tron_usdt,
        to_address=tron_usdt,
        amount_atomic=35_000_000,
        decimals=6,
    )

    assert transfer.log_index is None
    assert transfer.format_amount() == "35.000000"


# --- 28: no network ---------------------------------------------------------


def test_default_transport_cannot_reach_network_in_tests() -> None:
    provider = EthereumProvider(RPC_URL)  # real UrllibTransport

    with pytest.raises((AssertionError, ProviderError)):
        provider.get_usdt_transfers(TX_HASH)


def test_decoder_is_pure_and_needs_no_transport() -> None:
    transfers = decode_usdt_transfer_logs([transfer_log()], TX_HASH, BLOCK_NUMBER, BLOCK_HASH)

    assert transfers == [expected(ALICE, BOB, 35_000_000, 0)]
