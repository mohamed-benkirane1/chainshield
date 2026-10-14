"""End-to-end functional tests of the analysis API, network layer simulated.

Chain under test: HTTP -> body limit -> authentication -> concurrency slot ->
rate limit -> real ``get_transaction_analysis_service`` (built from the
environment) -> real ``TransactionAnalysisService`` -> real Ethereum / TRON
providers -> simulated node -> USDT extraction -> features -> address
evidence -> risk assessment -> JSON response.

Only the network is replaced: the providers' default transport is swapped for
an in-memory node that checks each request like a node would and answers with
representative JSON-RPC / java-tron payloads. This is NOT a validation against
real public nodes: the fixtures are hand-written, Ethereum "final" only means
mined with a receipt (no consensus finality), and the TRON provider does not
verify that its endpoint serves mainnet.

Every address, hash, report, URL and key below is FICTIONAL test data (EIP-55
test vectors or synthetic values) and says nothing about real owners.
"""

import copy
import json
import socket
from collections.abc import Callable, Iterator
from typing import Any

import base58
import pytest
from eth_utils import to_checksum_address
from fastapi.testclient import TestClient

import app.providers.ethereum as ethereum_module
import app.providers.tron as tron_module
from app.api.assessment_schemas import TransactionAssessmentResponse
from app.api.auth import API_TOKEN_ENV_VAR
from app.api.body_limit import MAX_BODY_BYTES
from app.api.errors import ERROR_MAPPING
from app.api.concurrency_limit import ConcurrencyLimiter, get_concurrency_limiter
from app.api.rate_limit import SlidingWindowRateLimiter, get_rate_limiter
from app.api.schemas import MAX_SAFE_INTEGER, TransactionInspectionResponse
from app.api.transactions import get_transaction_analysis_service
from app.domain.token_transfer import MAX_UINT256
from app.main import app
from app.providers.base import ProviderTimeoutError, ProviderUnavailableError
from app.providers.ethereum import ERC20_TRANSFER_TOPIC
from app.providers.tron import (
    GET_SOLID_TRANSACTION_INFO_PATH,
    GET_SOLID_TRANSACTION_PATH,
    GET_TRANSACTION_PATH,
    TRC20_TRANSFER_TOPIC,
)

INSPECT = "/api/v1/transactions/inspect"
ASSESS = "/api/v1/transactions/assess"
ROUTES = (INSPECT, ASSESS)

TOKEN = "fictional-test-token-not-a-secret-0123456789"
RPC_SECRET = "fictional-rpc-key-0f1e2d3c4b5a"
TRON_KEY = "fictional-tron-key-9a8b7c6d"
ETH_RPC_URL = f"https://eth.example.invalid/v3/{RPC_SECRET}"
TRON_URL = "https://tron.example.invalid"
SECRETS = (TOKEN, RPC_SECRET, TRON_KEY)
FIXED_MESSAGES = {code: message for _, _, code, message in ERROR_MAPPING}

# --- Ethereum fixtures ---------------------------------------------------------------------------

ALICE = to_checksum_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
BOB = to_checksum_address("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359")
CAROL = to_checksum_address("0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb")  # router contract
DAVE = to_checksum_address("0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb")  # look-alike token
ETH_USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

NATIVE_HASH = "0x" + "a1" * 32
USDT_HASH = "0x" + "b2" * 32
SWAP_HASH = "0x" + "c3" * 32
REVERTED_HASH = "0x" + "d4" * 32
PENDING_HASH = "0x" + "e5" * 32
UNKNOWN_HASH = "0x" + "f6" * 32
BLOCK = 19_000_000
BLOCK_TIME = 1_705_000_000

# --- TRON fixtures -------------------------------------------------------------------------------


def tron_address(seed: int) -> str:
    return base58.b58encode_check(b"\x41" + bytes(range(seed, seed + 20))).decode()


def tron_hex(address: str) -> str:
    return base58.b58decode_check(address).hex()  # 41 + 20 bytes


TRON_ALICE, TRON_BOB, TRON_CAROL = tron_address(1), tron_address(21), tron_address(41)
TRON_FAKE_TOKEN = tron_address(61)
TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRX_HASH = "1a" * 32
TRC20_HASH = "2b" * 32
UNCONFIRMED_HASH = "3c" * 32
FAILED_HASH = "4d" * 32
TRON_UNKNOWN_HASH = "5e" * 32
TRON_BLOCK = 60_000_000
TRON_BLOCK_TIME_MS = 1_705_000_002_999  # milliseconds, truncated to seconds


# --- Simulated nodes -----------------------------------------------------------------------------


def _answer(store: dict[str, Any], key: str, default: Any) -> Any:
    """A stored answer; a list holds successive answers, the last one repeats."""
    value = store.get(key, default)
    if isinstance(value, list):
        value = value.pop(0) if len(value) > 1 else value[0]
    return copy.deepcopy(value)


class EthereumNode:
    """In-memory Ethereum JSON-RPC node (mainnet unless ``chain_id`` is changed)."""

    def __init__(self) -> None:
        self.chain_id = "0x1"
        self.transactions: dict[str, Any] = {}
        self.receipts: dict[str, Any] = {}
        self.blocks: dict[int, Any] = {}
        self.failures: dict[str, Any] = {}  # method -> exception, JSON-RPC error or "bad-id"
        self.calls: list[str] = []

    def post_json(
        self, url: str, payload: dict[str, Any], timeout: float, headers: Any = None
    ) -> Any:
        assert url == ETH_RPC_URL and timeout > 0
        assert set(payload) == {"jsonrpc", "id", "method", "params"}
        assert payload["jsonrpc"] == "2.0" and type(payload["id"]) is int
        method, params = payload["method"], payload["params"]
        self.calls.append(method)
        envelope = {"jsonrpc": "2.0", "id": payload["id"]}
        failure = self.failures.get(method)
        if isinstance(failure, Exception):
            raise failure
        if failure == "bad-id":
            return {**envelope, "id": payload["id"] + 1, "result": None}
        if failure is not None:
            return {**envelope, "error": failure}
        if method == "eth_chainId":
            assert params == []
            result = self.chain_id
        elif method == "eth_getTransactionByHash":
            result = _answer(self.transactions, params[0], None)
        elif method == "eth_getTransactionReceipt":
            result = _answer(self.receipts, params[0], None)
        elif method == "eth_getBlockByNumber":
            assert params[1] is False
            result = _answer(self.blocks, int(params[0], 16), None)
        else:
            raise AssertionError(f"unexpected JSON-RPC method {method}")
        return {**envelope, "result": result}


def block_hash(number: int) -> str:
    return "0x" + format(number, "064x")


def eth_tx(tx_hash: str, sender: str, to: str | None, value: int, block: int | None) -> dict:
    return {
        "hash": tx_hash,
        "from": sender.lower(),
        "to": None if to is None else to.lower(),
        "value": hex(value),
        "nonce": "0x2a",
        "gas": "0x186a0",
        "gasPrice": "0x4a817c800",
        "input": "0x",
        "type": "0x2",
        "chainId": "0x1",
        "transactionIndex": None if block is None else "0x5",
        "blockNumber": None if block is None else hex(block),
        "blockHash": None if block is None else block_hash(block),
    }


def transfer_log(
    tx_hash: str, index: int, sender: str, recipient: str, amount: int,
    contract: str = ETH_USDT, topic0: str = ERC20_TRANSFER_TOPIC,
) -> dict:
    return {
        "address": contract.lower(),
        "topics": [
            topic0,
            "0x" + "0" * 24 + sender[2:].lower(),
            "0x" + "0" * 24 + recipient[2:].lower(),
        ],
        "data": "0x" + format(amount, "064x"),
        "blockNumber": hex(BLOCK),
        "blockHash": block_hash(BLOCK),
        "transactionHash": tx_hash,
        "transactionIndex": "0x5",
        "logIndex": hex(index),
        "removed": False,
    }


def mine(
    node: EthereumNode, tx_hash: str, sender: str, to: str | None, value: int,
    *, status: int = 1, logs: tuple[dict, ...] = (),
) -> None:
    node.transactions[tx_hash] = eth_tx(tx_hash, sender, to, value, BLOCK)
    node.receipts[tx_hash] = {
        "transactionHash": tx_hash,
        "transactionIndex": "0x5",
        "blockHash": block_hash(BLOCK),
        "blockNumber": hex(BLOCK),
        "from": sender.lower(),
        "to": None if to is None else to.lower(),
        "cumulativeGasUsed": "0x1b4d2",
        "gasUsed": "0xb411",
        "effectiveGasPrice": "0x4a817c800",
        "contractAddress": None,
        "logsBloom": "0x" + "00" * 256,
        "type": "0x2",
        "status": hex(status),
        "logs": list(logs),
    }
    node.blocks[BLOCK] = {
        "hash": block_hash(BLOCK),
        "number": hex(BLOCK),
        "timestamp": hex(BLOCK_TIME),
        "parentHash": block_hash(BLOCK - 1),
    }


class TronNode:
    """In-memory java-tron HTTP API (full node and solidity node)."""

    def __init__(self) -> None:
        self.stores: dict[str, dict[str, Any]] = {
            GET_TRANSACTION_PATH: {},
            GET_SOLID_TRANSACTION_PATH: {},
            GET_SOLID_TRANSACTION_INFO_PATH: {},
        }
        self.failures: dict[str, Any] = {}  # path -> exception or error payload
        self.calls: list[str] = []
        self.headers: list[dict[str, str]] = []

    def post_json(
        self, url: str, payload: dict[str, Any], timeout: float, headers: Any = None
    ) -> Any:
        assert url.startswith(TRON_URL + "/") and timeout > 0
        path = url[len(TRON_URL):]
        assert path in self.stores
        assert set(payload) == {"value", "visible"} and payload["visible"] is False
        self.calls.append(path)
        self.headers.append(dict(headers or {}))
        failure = self.failures.get(path)
        if isinstance(failure, Exception):
            raise failure
        if failure is not None:
            return copy.deepcopy(failure)
        return _answer(self.stores[path], payload["value"], {})  # {} = unknown


def tron_tx(txid: str, contract_type: str, value: dict, ret: str | None = "SUCCESS") -> dict:
    tx = {
        "visible": False,
        "txID": txid,
        "raw_data": {
            "contract": [
                {
                    "parameter": {
                        "value": value,
                        "type_url": f"type.googleapis.com/protocol.{contract_type}",
                    },
                    "type": contract_type,
                }
            ],
            "ref_block_bytes": "a1b2",
            "ref_block_hash": "0011223344556677",
            "expiration": 1_705_000_060_000,
            "timestamp": 1_704_999_999_000,  # set by the sender, never used as block time
        },
        "raw_data_hex": "0a02a1b2",
        "signature": ["00" * 65],
    }
    if ret is not None:
        tx["ret"] = [{"contractRet": ret}]
    return tx


def trx_transfer(txid: str, sender: str, recipient: str, amount: int, ret: str = "SUCCESS") -> dict:
    value = {
        "owner_address": tron_hex(sender),
        "to_address": tron_hex(recipient),
        "amount": amount,
    }
    return tron_tx(txid, "TransferContract", value, ret)


def trc20_call(txid: str, sender: str, contract: str = TRON_USDT, ret: str = "SUCCESS") -> dict:
    value = {
        "owner_address": tron_hex(sender),
        "contract_address": tron_hex(contract),
        "data": "a9059cbb" + "00" * 64,
    }
    return tron_tx(txid, "TriggerSmartContract", value, ret)


def tron_log(sender: str, recipient: str, amount: int, contract: str = TRON_USDT,
             topic0: str = TRC20_TRANSFER_TOPIC) -> dict:
    return {
        "address": tron_hex(contract)[2:],
        "topics": [topic0, "0" * 24 + tron_hex(sender)[2:], "0" * 24 + tron_hex(recipient)[2:]],
        "data": format(amount, "064x"),
    }


def tron_info(txid: str, *, receipt_result: str | None = None, failed: bool = False,
              logs: tuple[dict, ...] = ()) -> dict:
    receipt: dict[str, Any] = {"net_usage": 345}
    if receipt_result is not None:
        receipt.update(energy_usage_total=64_285, result=receipt_result)
    info: dict[str, Any] = {
        "id": txid,
        "fee": 345_000,
        "blockNumber": TRON_BLOCK,
        "blockTimeStamp": TRON_BLOCK_TIME_MS,
        "contractResult": [""],
        "receipt": receipt,
    }
    if failed:
        info["result"] = "FAILED"
    if logs:
        info["log"] = list(logs)
    return info


def solidify(node: TronNode, tx: dict, info: dict) -> None:
    node.stores[GET_TRANSACTION_PATH][tx["txID"]] = tx
    node.stores[GET_SOLID_TRANSACTION_PATH][tx["txID"]] = copy.deepcopy(tx)
    node.stores[GET_SOLID_TRANSACTION_INFO_PATH][tx["txID"]] = info


# --- Fixtures ------------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    # TestClient's event loop uses a loopback socket pair on Windows.
    real_connect = socket.socket.connect

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("tests must not open network connections")

    def loopback_only(sock: socket.socket, address: Any) -> Any:
        host = address[0] if isinstance(address, tuple) else address
        if host in ("127.0.0.1", "::1"):
            return real_connect(sock, address)
        raise AssertionError("tests must not open network connections")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", loopback_only)


@pytest.fixture
def eth() -> EthereumNode:
    return EthereumNode()


@pytest.fixture
def tron() -> TronNode:
    return TronNode()


@pytest.fixture(autouse=True)
def _environment(
    monkeypatch: pytest.MonkeyPatch, eth: EthereumNode, tron: TronNode
) -> Iterator[None]:
    # The real dependency builds the real providers from these variables; only
    # their default transport (urllib) is replaced by the simulated nodes.
    monkeypatch.setenv(API_TOKEN_ENV_VAR, TOKEN)
    monkeypatch.setenv("CHAINSHIELD_ETHEREUM_RPC_URL", ETH_RPC_URL)
    monkeypatch.setenv("CHAINSHIELD_TRON_RPC_URL", TRON_URL)
    monkeypatch.setenv("CHAINSHIELD_TRON_API_KEY", TRON_KEY)
    monkeypatch.setattr(ethereum_module, "UrllibTransport", lambda: eth)
    monkeypatch.setattr(tron_module, "UrllibTransport", lambda: tron)
    get_transaction_analysis_service.cache_clear()
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()
    get_transaction_analysis_service.cache_clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, headers={"Authorization": f"Bearer {TOKEN}"})


def call(client: TestClient, path: str, body: dict | None = None, **kwargs: Any) -> Any:
    """POST through the whole stack; every response is checked for secret leaks."""
    if body is not None:
        kwargs["json"] = body
    response = client.post(path, **kwargs)
    raw = response.text + json.dumps(dict(response.headers))
    for secret in SECRETS:
        assert secret not in raw
    assert "example.invalid" not in raw
    return response


def ok(client: TestClient, path: str, body: dict) -> dict:
    response = call(client, path, body)
    assert response.status_code == 200, response.text
    data = response.json()
    model = TransactionInspectionResponse if path == INSPECT else TransactionAssessmentResponse
    model.model_validate(data)  # matches the declared OpenAPI contract, no extra field
    return data


def inspection_of(data: dict, path: str) -> dict:
    return data if path == INSPECT else data["inspection"]


def eth_body(tx_hash: str, reports: list | None = None) -> dict:
    body: dict[str, Any] = {"network": "ethereum", "tx_hash": tx_hash}
    if reports is not None:
        body["reports"] = reports
    return body


def tron_body(tx_hash: str, reports: list | None = None) -> dict:
    return {**eth_body(tx_hash, reports), "network": "tron"}


def report(network: str, address: str, source_id: str = "fictional-source-a",
           report_id: str = "R-1", **extra: Any) -> dict:
    return {
        "network": network,
        "address": address,
        "source_id": source_id,
        "report_id": report_id,
        "source_type": "community_report",
        "claim_category": "scam_allegation",
        "reported_at": "2026-05-01T12:00:00+00:00",
        **extra,
    }


def walk_numbers(value: Any) -> Iterator[Any]:
    if isinstance(value, dict):
        for item in value.values():
            yield from walk_numbers(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_numbers(item)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield value


USDT_SINGLE = 625_000_000  # 625 USDT


def eth_usdt(node: EthereumNode) -> None:
    mine(node, USDT_HASH, ALICE, ETH_USDT, 0,
         logs=(transfer_log(USDT_HASH, 316, ALICE, BOB, USDT_SINGLE),))


def eth_swap(node: EthereumNode) -> None:
    """A routed swap: USDT events, plus an Approval and a look-alike token to ignore."""
    mine(node, SWAP_HASH, ALICE, CAROL, 0, logs=(
        transfer_log(SWAP_HASH, 5, ALICE, CAROL, MAX_UINT256),
        transfer_log(SWAP_HASH, 6, ALICE, CAROL, 1, topic0=APPROVAL_TOPIC),
        transfer_log(SWAP_HASH, 7, ALICE, BOB, 999, contract=DAVE),
        transfer_log(SWAP_HASH, 8, CAROL, BOB, MAX_UINT256),
        transfer_log(SWAP_HASH, 9, CAROL, CAROL, 0),
    ))


def tron_usdt(node: TronNode) -> None:
    solidify(node, trc20_call(TRC20_HASH, TRON_ALICE), tron_info(
        TRC20_HASH, receipt_result="SUCCESS", logs=(
            tron_log(TRON_ALICE, TRON_BOB, 10_000_000_000),
            tron_log(TRON_ALICE, TRON_BOB, 7, contract=TRON_FAKE_TOKEN),  # ignored
            tron_log(TRON_BOB, TRON_CAROL, 1),
        ),
    ))


# --- Ethereum ------------------------------------------------------------------------------------


EXPECTED_ETH_CALLS = [
    "eth_chainId",
    "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getBlockByNumber",
    "eth_getTransactionByHash", "eth_getTransactionReceipt",
    "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getBlockByNumber",
]


@pytest.mark.parametrize("path", ROUTES)
def test_eth_native_transfer(client: TestClient, eth: EthereumNode, path: str) -> None:
    mine(eth, NATIVE_HASH, ALICE, BOB, 1_500_000_000_000_000_000)  # 1.5 ETH

    data = ok(client, path, eth_body(NATIVE_HASH.upper().replace("0X", "0x")))

    assert inspection_of(data, path) == {
        "network": "ethereum",
        "tx_hash": NATIVE_HASH,
        "transaction": {
            "status": "success",
            "from_address": ALICE,
            "to_address": BOB,
            "native_value_atomic": "1500000000000000000",
            "native_unit": "wei",
            "block_number": BLOCK,
            "block_timestamp": BLOCK_TIME,
        },
        "usdt_transfers": [],
    }
    assert eth.calls == EXPECTED_ETH_CALLS  # chain checked once, then three consistent reads


def test_eth_usdt_transfer_through_both_routes(client: TestClient, eth: EthereumNode) -> None:
    eth_usdt(eth)

    inspected = ok(client, INSPECT, eth_body(USDT_HASH))
    assessed = ok(client, ASSESS, eth_body(USDT_HASH))

    assert inspected == assessed["inspection"]
    assert inspected["transaction"]["to_address"] == ETH_USDT
    assert inspected["transaction"]["native_value_atomic"] == "0"  # token amount is not native
    assert inspected["usdt_transfers"] == [{
        "token_symbol": "USDT",
        "token_contract": ETH_USDT,
        "from_address": ALICE,
        "to_address": BOB,
        "amount_atomic": "625000000",
        "amount_formatted": "625.000000",
        "decimals": 6,
        "log_index": 316,
    }]
    features = assessed["assessment"]["features"]
    assert features == {
        "transfer_data_available": True,
        "usdt_transfer_count": 1,
        "has_usdt_transfers": True,
        "unique_usdt_senders": 1,
        "unique_usdt_recipients": 1,
        "unique_usdt_participants": 2,
        "self_transfer_count": 0,
        "zero_amount_transfer_count": 0,
        "gross_usdt_event_amount_atomic": "625000000",
        "max_usdt_transfer_amount_atomic": "625000000",
    }
    assert eth.calls.count("eth_chainId") == 1  # provider reused across requests


def test_eth_multiple_transfer_events_are_exact_and_ordered(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_swap(eth)

    data = ok(client, ASSESS, eth_body(SWAP_HASH))

    transfers = data["inspection"]["usdt_transfers"]
    assert [(t["log_index"], t["from_address"], t["to_address"], t["amount_atomic"])
            for t in transfers] == [
        (5, ALICE, CAROL, str(MAX_UINT256)),
        (8, CAROL, BOB, str(MAX_UINT256)),
        (9, CAROL, CAROL, "0"),
    ]  # Approval and the look-alike token are ignored; nothing is summed
    features = data["assessment"]["features"]
    assert features["usdt_transfer_count"] == 3
    assert (features["unique_usdt_senders"], features["unique_usdt_recipients"]) == (2, 2)
    assert features["unique_usdt_participants"] == 3
    assert (features["self_transfer_count"], features["zero_amount_transfer_count"]) == (1, 1)
    assert features["gross_usdt_event_amount_atomic"] == str(2 * MAX_UINT256)  # above uint256
    assert features["max_usdt_transfer_amount_atomic"] == str(MAX_UINT256)


@pytest.mark.parametrize("path", ROUTES)
def test_eth_reverted_transaction(client: TestClient, eth: EthereumNode, path: str) -> None:
    mine(eth, REVERTED_HASH, ALICE, ETH_USDT, 0, status=0)

    data = ok(client, path, eth_body(REVERTED_HASH))

    inspection = inspection_of(data, path)
    assert inspection["transaction"]["status"] == "reverted"
    assert inspection["transaction"]["block_number"] == BLOCK
    assert inspection["usdt_transfers"] == []  # a reverted execution transferred nothing
    if path == ASSESS:
        assert data["assessment"]["transaction_status"] == "reverted"
        assert data["assessment"]["features"]["usdt_transfer_count"] == 0


@pytest.mark.parametrize("path", ROUTES)
def test_eth_pending_transaction(client: TestClient, eth: EthereumNode, path: str) -> None:
    eth.transactions[PENDING_HASH] = eth_tx(PENDING_HASH, ALICE, BOB, 42, None)

    data = ok(client, path, eth_body(PENDING_HASH))

    assert inspection_of(data, path)["transaction"] == {
        "status": "pending",
        "from_address": ALICE,
        "to_address": BOB,
        "native_value_atomic": "42",
        "native_unit": "wei",
        "block_number": None,
        "block_timestamp": None,
    }
    assert inspection_of(data, path)["usdt_transfers"] is None  # unknown, not empty
    assert eth.calls == ["eth_chainId", "eth_getTransactionByHash"]
    if path == ASSESS:
        features = data["assessment"]["features"]
        assert features["transfer_data_available"] is False
        assert all(v is None for k, v in features.items() if k != "transfer_data_available")


@pytest.mark.parametrize("path", ROUTES)
def test_eth_unknown_transaction(client: TestClient, eth: EthereumNode, path: str) -> None:
    data = ok(client, path, eth_body(UNKNOWN_HASH, [report("ethereum", ALICE)])
              if path == ASSESS else eth_body(UNKNOWN_HASH))

    inspection = inspection_of(data, path)
    assert inspection["transaction"]["status"] == "not_found"
    assert set(inspection["transaction"].values()) == {"not_found", None}
    assert inspection["usdt_transfers"] is None
    if path == ASSESS:
        evidence = data["assessment"]["address_evidence"]
        assert evidence["evaluation_status"] == "no_observable_addresses"
        assert data["assessment"]["manual_review_recommended"] is False


def _set(container: Callable[[EthereumNode], dict], key: Any, value: Any) -> Callable:
    def apply(node: EthereumNode) -> None:
        container(node)[key] = value
    return apply


def _drop_receipt_status(node: EthereumNode) -> None:
    del node.receipts[USDT_HASH]["status"]


def _remove_log(node: EthereumNode) -> None:
    node.receipts[USDT_HASH]["logs"][0]["removed"] = True


def _becomes_pending(node: EthereumNode) -> None:
    mined = node.transactions[USDT_HASH]
    node.transactions[USDT_HASH] = [mined, eth_tx(USDT_HASH, ALICE, ETH_USDT, 0, None)]


def _wrong_chain(node: EthereumNode) -> None:
    node.chain_id = "0x5"


ETH_FAILURES = {
    "wrong-chain": (_wrong_chain, 502, "provider_wrong_network"),
    "receipt-of-another-block": (
        _set(lambda n: n.receipts[USDT_HASH], "blockHash", block_hash(BLOCK + 1)),
        502, "provider_malformed_response",
    ),
    "receipt-missing": (_set(lambda n: n.receipts, USDT_HASH, None), 503, "receipt_unavailable"),
    "receipt-without-status": (_drop_receipt_status, 502, "provider_malformed_response"),
    "log-removed-by-reorg": (_remove_log, 502, "provider_malformed_response"),
    "timestamp-beyond-json-safe": (
        _set(lambda n: n.blocks[BLOCK], "timestamp", hex(MAX_SAFE_INTEGER + 1)),
        502, "provider_malformed_response",
    ),
    "json-rpc-error": (
        _set(lambda n: n.failures, "eth_getTransactionByHash",
             {"code": -32005, "message": f"daily limit reached for {RPC_SECRET}"}),
        502, "provider_rpc_error",
    ),
    "bad-envelope": (
        _set(lambda n: n.failures, "eth_getBlockByNumber", "bad-id"),
        502, "provider_malformed_response",
    ),
    "timeout": (
        _set(lambda n: n.failures, "eth_getTransactionReceipt",
             ProviderTimeoutError("RPC request timed out")),
        504, "provider_timeout",
    ),
    "unavailable": (
        _set(lambda n: n.failures, "eth_chainId",
             ProviderUnavailableError("RPC endpoint returned HTTP 429")),
        503, "provider_unavailable",
    ),
    "changed-between-reads": (_becomes_pending, 502, "inconsistent_provider_data"),
}


@pytest.mark.parametrize("path", ROUTES)
@pytest.mark.parametrize("case", list(ETH_FAILURES))
def test_eth_node_failures_are_mapped_to_safe_errors(
    client: TestClient, eth: EthereumNode, case: str, path: str
) -> None:
    eth_usdt(eth)
    breaks, status, code = ETH_FAILURES[case]
    breaks(eth)

    reports = [report("ethereum", BOB)] if path == ASSESS else None
    response = call(client, path, eth_body(USDT_HASH, reports))

    assert response.status_code == status
    assert response.json() == {"error": {"code": code, "message": FIXED_MESSAGES[code]}}


# --- TRON ----------------------------------------------------------------------------------------


EXPECTED_TRON_CALLS = [
    GET_TRANSACTION_PATH, GET_SOLID_TRANSACTION_PATH, GET_SOLID_TRANSACTION_INFO_PATH,
] * 3


@pytest.mark.parametrize("path", ROUTES)
def test_tron_native_trx_transfer_solidified(
    client: TestClient, tron: TronNode, path: str
) -> None:
    solidify(tron, trx_transfer(TRX_HASH, TRON_ALICE, TRON_BOB, 2_500_000), tron_info(TRX_HASH))

    data = ok(client, path, tron_body(TRX_HASH.upper()))

    assert inspection_of(data, path) == {
        "network": "tron",
        "tx_hash": TRX_HASH,
        "transaction": {
            "status": "success",
            "from_address": TRON_ALICE,  # hex 41... converted to Base58Check
            "to_address": TRON_BOB,
            "native_value_atomic": "2500000",
            "native_unit": "sun",
            "block_number": TRON_BLOCK,
            "block_timestamp": TRON_BLOCK_TIME_MS // 1000,  # block time, not raw_data
        },
        "usdt_transfers": [],
    }
    assert tron.calls == EXPECTED_TRON_CALLS
    assert all(headers == {"TRON-PRO-API-KEY": TRON_KEY} for headers in tron.headers)


def test_tron_usdt_trc20_transfer_through_both_routes(client: TestClient, tron: TronNode) -> None:
    tron_usdt(tron)

    inspected = ok(client, INSPECT, tron_body(TRC20_HASH))
    assessed = ok(client, ASSESS, tron_body(TRC20_HASH))

    assert inspected == assessed["inspection"]
    assert inspected["transaction"]["to_address"] == TRON_USDT
    assert inspected["transaction"]["native_value_atomic"] == "0"  # call_value omitted = 0
    assert inspected["usdt_transfers"] == [
        {
            "token_symbol": "USDT",
            "token_contract": TRON_USDT,
            "from_address": TRON_ALICE,
            "to_address": TRON_BOB,
            "amount_atomic": "10000000000",
            "amount_formatted": "10000.000000",
            "decimals": 6,
            "log_index": None,
        },
        {
            "token_symbol": "USDT",
            "token_contract": TRON_USDT,
            "from_address": TRON_BOB,
            "to_address": TRON_CAROL,
            "amount_atomic": "1",
            "amount_formatted": "0.000001",
            "decimals": 6,
            "log_index": None,
        },
    ]  # emission order kept, look-alike token ignored
    features = assessed["assessment"]["features"]
    assert features["usdt_transfer_count"] == 2
    assert features["unique_usdt_participants"] == 3
    assert features["gross_usdt_event_amount_atomic"] == "10000000001"


@pytest.mark.parametrize("path", ROUTES)
def test_tron_unconfirmed_transaction(client: TestClient, tron: TronNode, path: str) -> None:
    tron.stores[GET_TRANSACTION_PATH][UNCONFIRMED_HASH] = trc20_call(
        UNCONFIRMED_HASH, TRON_ALICE
    )

    data = ok(client, path, tron_body(UNCONFIRMED_HASH))

    inspection = inspection_of(data, path)
    assert inspection["transaction"]["status"] == "unconfirmed"
    assert inspection["transaction"]["from_address"] == TRON_ALICE
    assert inspection["transaction"]["block_number"] is None
    assert inspection["usdt_transfers"] is None  # outcome not reported before solidification
    assert tron.calls == [GET_TRANSACTION_PATH, GET_SOLID_TRANSACTION_PATH]
    if path == ASSESS:
        assert data["assessment"]["features"]["transfer_data_available"] is False


@pytest.mark.parametrize("path", ROUTES)
def test_tron_failed_execution(client: TestClient, tron: TronNode, path: str) -> None:
    solidify(
        tron,
        trc20_call(FAILED_HASH, TRON_ALICE, ret="OUT_OF_ENERGY"),
        tron_info(FAILED_HASH, receipt_result="OUT_OF_ENERGY", failed=True),
    )

    data = ok(client, path, tron_body(FAILED_HASH))

    inspection = inspection_of(data, path)
    assert inspection["transaction"]["status"] == "reverted"
    assert inspection["usdt_transfers"] == []


@pytest.mark.parametrize("path", ROUTES)
def test_tron_unknown_transaction(client: TestClient, tron: TronNode, path: str) -> None:
    data = ok(client, path, tron_body(TRON_UNKNOWN_HASH))

    assert inspection_of(data, path)["transaction"]["status"] == "not_found"
    assert inspection_of(data, path)["usdt_transfers"] is None
    assert tron.calls == [GET_TRANSACTION_PATH]


def _tron_set(path: str, key: str | None, value: Any) -> Callable[[TronNode], None]:
    def apply(node: TronNode) -> None:
        if key is None:
            node.failures[path] = value
        else:
            node.stores[path][TRC20_HASH] = value(node.stores[path][TRC20_HASH])
    return apply


def _with(**changes: Any) -> Callable[[dict], dict]:
    def change(document: dict) -> dict:
        for dotted, value in changes.items():
            target = document
            *parents, last = dotted.split("__")
            for parent in parents:
                target = target[parent]
            if value is None:
                target.pop(last, None)
            else:
                target[last] = value
        return document
    return change


def _execution_default(node: TronNode) -> None:
    # Consistent but unestablished: DEFAULT result and no receipt result.
    node.stores[GET_SOLID_TRANSACTION_PATH][TRC20_HASH]["ret"] = [{"contractRet": "DEFAULT"}]
    del node.stores[GET_SOLID_TRANSACTION_INFO_PATH][TRC20_HASH]["receipt"]["result"]


def _solid_disappears(node: TronNode) -> None:
    solid = node.stores[GET_SOLID_TRANSACTION_PATH][TRC20_HASH]
    node.stores[GET_SOLID_TRANSACTION_PATH][TRC20_HASH] = [solid, {}]


def _unsupported(node: TronNode) -> None:
    for path in (GET_TRANSACTION_PATH, GET_SOLID_TRANSACTION_PATH):
        contract = node.stores[path][TRC20_HASH]["raw_data"]["contract"][0]
        contract["type"] = "FreezeBalanceV2Contract"
        contract["parameter"]["type_url"] = "type.googleapis.com/protocol.FreezeBalanceV2Contract"


TRON_FAILURES = {
    "node-error-payload": (
        _tron_set(GET_TRANSACTION_PATH, None,
                  {"Error": f"class org.tron.core.exception: bad key {TRON_KEY}"}),
        502, "provider_api_error",
    ),
    "full-and-solidity-disagree": (
        _tron_set(GET_SOLID_TRANSACTION_PATH, "tx", _with(raw_data__expiration=1)),
        502, "provider_malformed_response",
    ),
    "unknown-execution-result": (_execution_default, 502, "execution_result_unknown"),
    "contract-call-without-receipt-result": (
        _tron_set(GET_SOLID_TRANSACTION_INFO_PATH, "info", _with(receipt__result=None)),
        502, "execution_result_unknown",
    ),
    "info-for-another-transaction": (
        _tron_set(GET_SOLID_TRANSACTION_INFO_PATH, "info", _with(id="9f" * 32)),
        502, "provider_malformed_response",
    ),
    "execution-info-missing": (
        _tron_set(GET_SOLID_TRANSACTION_INFO_PATH, "info", lambda _: {}),
        503, "receipt_unavailable",
    ),
    "unsupported-contract": (_unsupported, 422, "unsupported_transaction"),
    "timeout": (
        _tron_set(GET_SOLID_TRANSACTION_INFO_PATH, None,
                  ProviderTimeoutError("RPC request timed out")),
        504, "provider_timeout",
    ),
    "changed-between-reads": (_solid_disappears, 502, "inconsistent_provider_data"),
}


@pytest.mark.parametrize("path", ROUTES)
@pytest.mark.parametrize("case", list(TRON_FAILURES))
def test_tron_node_failures_are_mapped_to_safe_errors(
    client: TestClient, tron: TronNode, case: str, path: str
) -> None:
    tron_usdt(tron)
    breaks, status, code = TRON_FAILURES[case]
    breaks(tron)

    reports = [report("tron", TRON_BOB)] if path == ASSESS else None
    response = call(client, path, tron_body(TRC20_HASH, reports))

    assert response.status_code == status
    assert response.json() == {"error": {"code": code, "message": FIXED_MESSAGES[code]}}
    assert "org.tron" not in response.text  # the node's message is never echoed


# --- Risk assessment -----------------------------------------------------------------------------


def assessment(client: TestClient, body: dict) -> dict:
    data = ok(client, ASSESS, body)
    assert data["report_origin"] == "client_supplied_unverified"
    result = data["assessment"]
    assert result["risk_determination"] == "indeterminate"
    assert result["determination_basis"] == "no_verified_evidence"
    assert result["manual_review_recommended"] is bool(result["signals"])
    return result


def test_assessment_without_report_source(client: TestClient, eth: EthereumNode) -> None:
    eth_swap(eth)

    result = assessment(client, eth_body(SWAP_HASH))

    assert result["address_evidence"] == {
        "evaluation_status": "no_report_source",
        "supplied_report_count": None,
        "observed_address_count": 3,  # ALICE, CAROL, BOB; the ignored token is not observed
        "matches": [],
    }
    assert result["signals"] == [] and result["manual_review_recommended"] is False


def test_assessment_with_an_empty_report_source(client: TestClient, eth: EthereumNode) -> None:
    eth_swap(eth)

    result = assessment(client, eth_body(SWAP_HASH, []))

    assert result["address_evidence"]["evaluation_status"] == "empty_report_source"
    assert result["address_evidence"]["supplied_report_count"] == 0
    assert result["manual_review_recommended"] is False


def test_matching_report_is_a_traceable_unverified_signal(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_usdt(eth)
    supplied = report("ethereum", BOB.lower(), source_type="public_authority",
                      claim_category="phishing_allegation",
                      source_reference="https://reports.example.invalid/R-1")

    result = assessment(client, eth_body(USDT_HASH, [supplied]))

    assert result["address_evidence"]["evaluation_status"] == "matches_found"
    assert result["address_evidence"]["matches"] == [{
        "address": BOB,  # lowercase report address matched in canonical EIP-55 form
        "observed_roles": ["usdt_transfer_recipient"],
        "source_id": "fictional-source-a",
        "report_id": "R-1",
        "source_type": "public_authority",
        "claim_category": "phishing_allegation",
        "reported_at": "2026-05-01T12:00:00Z",
        "allegation_verified": False,
    }]
    assert result["signals"] == [{
        "signal_code": "unverified_address_allegation_match",
        "address": BOB,
        "observed_roles": ["usdt_transfer_recipient"],
        "source_id": "fictional-source-a",
        "report_id": "R-1",
        "source_type": "public_authority",
        "claim_category": "phishing_allegation",
        "reported_at": "2026-05-01T12:00:00Z",
        "evidence_status": "unverified",  # even a declared public authority
    }]
    assert result["manual_review_recommended"] is True


def test_several_reports_keep_their_provenance(client: TestClient, eth: EthereumNode) -> None:
    eth_swap(eth)
    reports = [
        report("ethereum", BOB, "fictional-source-b", "B-7", source_type="security_vendor"),
        report("ethereum", BOB, "fictional-source-a", "A-1"),
        report("ethereum", ALICE, "fictional-source-a", "A-2", claim_category="theft_allegation"),
        report("ethereum", BOB, "fictional-source-a", "A-1"),  # identical duplicate, merged
    ]

    result = assessment(client, eth_body(SWAP_HASH, reports))

    evidence = result["address_evidence"]
    assert evidence["supplied_report_count"] == 3
    assert [(m["address"], m["source_id"], m["report_id"], m["observed_roles"])
            for m in evidence["matches"]] == [
        (ALICE, "fictional-source-a", "A-2", ["transaction_sender", "usdt_transfer_sender"]),
        (BOB, "fictional-source-a", "A-1", ["usdt_transfer_recipient"]),
        (BOB, "fictional-source-b", "B-7", ["usdt_transfer_recipient"]),
    ]  # each allegation stays separate: nothing is merged into a stronger claim
    assert [(s["address"], s["source_id"], s["report_id"], s["claim_category"])
            for s in result["signals"]] == [
        (ALICE, "fictional-source-a", "A-2", "theft_allegation"),
        (BOB, "fictional-source-a", "A-1", "scam_allegation"),
        (BOB, "fictional-source-b", "B-7", "scam_allegation"),
    ]
    assert all(m["allegation_verified"] is False for m in evidence["matches"])
    assert all(s["evidence_status"] == "unverified" for s in result["signals"])


def test_reports_without_correspondence(client: TestClient, eth: EthereumNode) -> None:
    eth_swap(eth)
    reports = [
        report("ethereum", DAVE, report_id="R-1"),  # only the ignored look-alike token
        report("tron", TRON_ALICE, report_id="R-2"),  # another network
    ]

    result = assessment(client, eth_body(SWAP_HASH, reports))

    assert result["address_evidence"]["evaluation_status"] == "no_match_in_supplied_reports"
    assert result["address_evidence"]["supplied_report_count"] == 2
    assert result["signals"] == [] and result["manual_review_recommended"] is False


def test_reverted_transaction_matches_the_called_contract_only(
    client: TestClient, eth: EthereumNode
) -> None:
    mine(eth, REVERTED_HASH, ALICE, CAROL, 0, status=0)

    result = assessment(client, eth_body(REVERTED_HASH, [report("ethereum", CAROL)]))

    assert result["address_evidence"]["matches"][0]["observed_roles"] == [
        "transaction_recipient"
    ]  # no USDT role: a reverted execution transferred nothing


def test_contradictory_reports_are_refused(client: TestClient, eth: EthereumNode) -> None:
    eth_usdt(eth)
    reports = [
        report("ethereum", BOB, claim_category="scam_allegation"),
        report("ethereum", BOB, claim_category="theft_allegation"),  # same ids, other content
    ]

    response = call(client, ASSESS, eth_body(USDT_HASH, reports))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "conflicting_reports"
    assert "fictional-source-a" not in response.text


def test_tron_report_matches_a_normalized_transfer_address(
    client: TestClient, tron: TronNode
) -> None:
    tron_usdt(tron)

    result = assessment(client, tron_body(TRC20_HASH, [report("tron", TRON_BOB)]))

    assert result["address_evidence"]["matches"][0]["address"] == TRON_BOB
    assert result["address_evidence"]["matches"][0]["observed_roles"] == [
        "usdt_transfer_sender", "usdt_transfer_recipient"
    ]


def test_unconfirmed_tron_sender_can_match_without_any_transfer_data(
    client: TestClient, tron: TronNode
) -> None:
    tron.stores[GET_TRANSACTION_PATH][UNCONFIRMED_HASH] = trc20_call(
        UNCONFIRMED_HASH, TRON_ALICE
    )

    result = assessment(client, tron_body(UNCONFIRMED_HASH, [report("tron", TRON_ALICE)]))

    assert result["features"]["transfer_data_available"] is False
    assert result["address_evidence"]["matches"][0]["observed_roles"] == ["transaction_sender"]
    assert result["manual_review_recommended"] is True


# --- API protections around the real chain -------------------------------------------------------


def test_authentication_failures_never_reach_a_node(
    eth: EthereumNode, tron: TronNode, monkeypatch: pytest.MonkeyPatch
) -> None:
    eth_usdt(eth)
    anonymous = TestClient(app)

    for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {TOKEN}"}):
        assert call(anonymous, INSPECT, eth_body(USDT_HASH), headers=headers).status_code == 401
    monkeypatch.delenv(API_TOKEN_ENV_VAR)
    response = call(anonymous, ASSESS, eth_body(USDT_HASH), headers={"Authorization": "Bearer x"})
    assert response.json()["error"]["code"] == "auth_not_configured"

    assert eth.calls == [] and tron.calls == []
    assert get_transaction_analysis_service.cache_info().currsize == 0


def test_oversized_body_never_reaches_a_node(client: TestClient, eth: EthereumNode) -> None:
    eth_usdt(eth)
    body = json.dumps(eth_body(USDT_HASH)).encode() + b" " * MAX_BODY_BYTES

    response = call(client, ASSESS, content=body, headers={"Content-Type": "application/json"})

    assert response.status_code == 413
    assert eth.calls == []


def test_rate_limited_request_never_reaches_a_node(client: TestClient, eth: EthereumNode) -> None:
    eth_usdt(eth)
    limiter = SlidingWindowRateLimiter(clock=lambda: 1_000.0)  # frozen clock
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    for _ in range(30):
        ok(client, INSPECT, eth_body(USDT_HASH))
    calls_before = len(eth.calls)

    response = call(client, ASSESS, eth_body(USDT_HASH))

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limited"
    assert len(eth.calls) == calls_before


def test_busy_service_never_reaches_a_node(client: TestClient, eth: EthereumNode) -> None:
    eth_usdt(eth)
    limiter = ConcurrencyLimiter()
    app.dependency_overrides[get_concurrency_limiter] = lambda: limiter
    for _ in range(limiter.max_concurrent):
        assert limiter.try_acquire()

    response = call(client, INSPECT, eth_body(USDT_HASH))

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_busy"
    assert eth.calls == []
    for _ in range(limiter.max_concurrent):
        limiter.release()
    assert ok(client, INSPECT, eth_body(USDT_HASH))["usdt_transfers"]  # then served normally


def test_large_numbers_are_exact_strings_and_json_numbers_stay_safe(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_swap(eth)
    mine(eth, NATIVE_HASH, ALICE, BOB, 10**30)  # far above 2**53 wei

    native = ok(client, INSPECT, eth_body(NATIVE_HASH))
    swap = ok(client, ASSESS, eth_body(SWAP_HASH))

    assert native["transaction"]["native_value_atomic"] == "1" + "0" * 30
    for data in (native, swap):
        numbers = list(walk_numbers(data))
        assert all(isinstance(n, int) and 0 <= n <= MAX_SAFE_INTEGER for n in numbers)
    assert '"amount_atomic":"' + str(MAX_UINT256) + '"' in json.dumps(swap, separators=(",", ":"))


def test_openapi_describes_the_routes_exercised_here(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    for path, schema in ((INSPECT, "TransactionInspectionResponse"),
                         (ASSESS, "TransactionAssessmentResponse")):
        operation = spec["paths"][path]["post"]
        success = operation["responses"]["200"]["content"]["application/json"]["schema"]
        assert success["$ref"] == f"#/components/schemas/{schema}"
        assert operation["security"] == [{"HTTPBearer": []}]
        assert {"401", "413", "422", "429", "502", "503", "504"} <= set(operation["responses"])
    text = json.dumps(spec)
    assert all(secret not in text for secret in SECRETS)
