"""USDT Relationship Graph v1, including HTTP-to-simulated-node coverage.

Only the network boundary is simulated in end-to-end tests.  Production
authentication, quota, concurrency, services, providers and decoders run.
All addresses, hashes, URLs and credentials are fictional test data.
"""

import json
import socket
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.providers.ethereum as ethereum_module
import app.providers.tron as tron_module
from app.api.auth import API_TOKEN_ENV_VAR
from app.api.body_limit import MAX_BODY_BYTES
from app.api.concurrency_limit import ConcurrencyLimiter, get_concurrency_limiter
from app.api.rate_limit import RateLimitExceededError, SlidingWindowRateLimiter, get_rate_limiter
from app.api.relationship_schemas import UsdtRelationshipGraphResponse
from app.api.schemas import MAX_SAFE_INTEGER
from app.api.transactions import get_transaction_analysis_service
from app.domain.analysis_input import Network
from app.domain.token_transfer import MAX_UINT256, NormalizedTokenTransfer
from app.domain.usdt_registry import get_usdt_contract
from app.main import app
from app.providers.base import (
    NativeUnit,
    NormalizedTransaction,
    ProviderTimeoutError,
    TransactionStatus,
)
from app.providers.tron import GET_TRANSACTION_PATH
from app.services.address_investigation import TransferCoverage
from app.services.transaction_analysis import TransactionInspection
from app.services.usdt_relationships import (
    GroupedRelationship,
    RelationshipEdge,
    UsdtRelationshipGraph,
    build_usdt_relationship_graph,
    inspect_usdt_relationships,
    relationship_event_id,
)
from test_e2e_api import (  # noqa: E402
    ALICE,
    BOB,
    CAROL,
    DAVE,
    ETH_RPC_URL,
    ETH_USDT,
    NATIVE_HASH,
    PENDING_HASH,
    RPC_SECRET,
    SECRETS,
    SWAP_HASH,
    TOKEN,
    TRC20_HASH,
    TRON_ALICE,
    TRON_BOB,
    TRON_CAROL,
    TRON_URL,
    UNCONFIRMED_HASH,
    UNKNOWN_HASH,
    USDT_HASH,
    EthereumNode,
    TronNode,
    eth_swap,
    eth_tx,
    eth_usdt,
    mine,
    trc20_call,
    tron_usdt,
)

URL = "/api/v1/relationships/usdt"
INSPECT = "/api/v1/transactions/inspect"
ASSESS = "/api/v1/transactions/assess"
INVESTIGATE = "/api/v1/addresses/investigate"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
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


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def _environment(
    monkeypatch: pytest.MonkeyPatch, eth: EthereumNode, tron: TronNode
) -> Iterator[None]:
    monkeypatch.setenv(API_TOKEN_ENV_VAR, TOKEN)
    monkeypatch.setenv("CHAINSHIELD_ETHEREUM_RPC_URL", ETH_RPC_URL)
    monkeypatch.setenv("CHAINSHIELD_TRON_RPC_URL", TRON_URL)
    monkeypatch.delenv("CHAINSHIELD_TRON_API_KEY", raising=False)
    monkeypatch.setattr(ethereum_module, "UrllibTransport", lambda: eth)
    monkeypatch.setattr(tron_module, "UrllibTransport", lambda: tron)
    get_transaction_analysis_service.cache_clear()
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()
    get_transaction_analysis_service.cache_clear()


@pytest.fixture(autouse=True)
def quota(_environment: None) -> SlidingWindowRateLimiter:
    limiter = SlidingWindowRateLimiter(clock=FakeClock())
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    return limiter


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, headers=AUTH)


def call(client: TestClient, body: Any = None, path: str = URL, **kwargs: Any) -> Any:
    if body is not None:
        kwargs["json"] = body
    response = client.post(path, **kwargs)
    raw = response.text + json.dumps(dict(response.headers))
    assert all(secret not in raw for secret in SECRETS)
    assert "example.invalid" not in raw
    return response


def graph(client: TestClient, network: str, hashes: list[str]) -> dict[str, Any]:
    response = call(client, {"network": network, "tx_hashes": hashes})
    assert response.status_code == 200, response.text
    data = response.json()
    UsdtRelationshipGraphResponse.model_validate(data)
    return data


def units_left(limiter: SlidingWindowRateLimiter) -> int:
    for cost in range(limiter.max_requests, 0, -1):
        try:
            limiter.acquire(cost)
        except RateLimitExceededError:
            continue
        for _ in range(cost):
            limiter._admissions.pop()
        return cost
    return 0


def walk_numbers(value: Any) -> Iterator[int | float]:
    if isinstance(value, dict):
        for item in value.values():
            yield from walk_numbers(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_numbers(item)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield value


# --- Pure graph construction --------------------------------------------------------------------

H1, H2, H3, H4 = ("0x" + character * 64 for character in "1234")
ETH_USDT_CANONICAL = get_usdt_contract(Network.ETHEREUM).contract_address
TRON_USDT = get_usdt_contract(Network.TRON).contract_address


def transfer(
    tx_hash: str,
    sender: str,
    recipient: str,
    amount: int,
    log_index: int,
) -> NormalizedTokenTransfer:
    return NormalizedTokenTransfer(
        network=Network.ETHEREUM,
        tx_hash=tx_hash,
        token_symbol="USDT",
        token_contract=ETH_USDT_CANONICAL,
        from_address=sender,
        to_address=recipient,
        amount_atomic=amount,
        decimals=6,
        log_index=log_index,
    )


def inspection(
    tx_hash: str,
    *,
    status: TransactionStatus = TransactionStatus.SUCCESS,
    transfers: tuple[NormalizedTokenTransfer, ...] | None = (),
) -> TransactionInspection:
    found = status is not TransactionStatus.NOT_FOUND
    final = status in (TransactionStatus.SUCCESS, TransactionStatus.REVERTED)
    return TransactionInspection(
        network=Network.ETHEREUM,
        tx_hash=tx_hash,
        transaction=NormalizedTransaction(
            network=Network.ETHEREUM,
            tx_hash=tx_hash,
            status=status,
            from_address=ALICE if found else None,
            to_address=BOB if found else None,
            native_value_atomic=0 if found else None,
            native_unit=NativeUnit.WEI if found else None,
            block_number=1 if final else None,
            block_timestamp=2 if final else None,
        ),
        usdt_transfers=transfers if final else None,
    )


def test_graph_preserves_events_directions_self_loops_and_exact_aggregates() -> None:
    huge = MAX_UINT256
    first = inspection(
        H1,
        transfers=(
            transfer(H1, ALICE, BOB, huge, 91),
            transfer(H1, ALICE, BOB, huge, 92),  # same pair/amount, still a distinct event
            transfer(H1, BOB, ALICE, 7, 93),  # opposite direction, never netted
            transfer(H1, CAROL, CAROL, 0, 94),  # self-loop
        ),
    )
    second = inspection(H2, transfers=(transfer(H2, ALICE, BOB, 11, 3),))

    result = build_usdt_relationship_graph(Network.ETHEREUM, [first, second])

    assert result.sample_scope == "supplied_transactions_only"
    assert result.transfer_coverage is TransferCoverage.COMPLETE
    assert [node.address for node in result.nodes or ()] == sorted([ALICE, BOB, CAROL])
    edges = result.edges or ()
    assert len(edges) == 5
    assert [edge.event_id for edge in edges] == [
        relationship_event_id(Network.ETHEREUM, H1, position) for position in range(4)
    ] + [relationship_event_id(Network.ETHEREUM, H2, 0)]
    assert [edge.event_position for edge in edges] == [0, 1, 2, 3, 0]
    assert [edge.log_index for edge in edges] == [91, 92, 93, 94, 3]
    assert all(edge.token_contract == ETH_USDT_CANONICAL for edge in edges)
    assert edges[3].from_address == edges[3].to_address == CAROL

    groups = result.grouped_relationships or ()
    assert [(group.from_address, group.to_address) for group in groups] == sorted(
        [(ALICE, BOB), (BOB, ALICE), (CAROL, CAROL)]
    )
    repeated = next(group for group in groups if (group.from_address, group.to_address) == (ALICE, BOB))
    assert repeated == GroupedRelationship(
        from_address=ALICE,
        to_address=BOB,
        event_count=3,
        total_amount_atomic=huge * 2 + 11,  # deliberately above uint256
        tx_hashes=(H1, H2),
    )
    reverse = next(group for group in groups if group.from_address == BOB)
    assert (reverse.event_count, reverse.total_amount_atomic, reverse.tx_hashes) == (1, 7, (H1,))
    assert result.known_total_usdt_amount_atomic == huge * 2 + 18


def test_final_transactions_with_no_events_are_known_empty_not_unknown() -> None:
    result = build_usdt_relationship_graph(
        Network.ETHEREUM,
        [inspection(H1), inspection(H2, status=TransactionStatus.REVERTED)],
    )

    assert result.transfer_coverage is TransferCoverage.COMPLETE
    assert result.nodes == result.edges == result.grouped_relationships == ()
    assert result.known_total_usdt_amount_atomic == 0
    assert [transaction.usdt_event_count for transaction in result.transactions] == [0, 0]


def test_partial_coverage_keeps_known_empty_data_explicit() -> None:
    result = build_usdt_relationship_graph(
        Network.ETHEREUM,
        [inspection(H1), inspection(H2, status=TransactionStatus.PENDING)],
    )

    assert result.transfer_coverage is TransferCoverage.PARTIAL
    assert result.nodes == result.edges == result.grouped_relationships == ()
    assert result.known_total_usdt_amount_atomic == 0
    assert result.transactions[0].usdt_event_count == 0
    assert result.transactions[1].usdt_event_count is None


@pytest.mark.parametrize("statuses", [
    (TransactionStatus.PENDING,),
    (TransactionStatus.NOT_FOUND,),
    (TransactionStatus.PENDING, TransactionStatus.NOT_FOUND),
])
def test_no_known_transaction_means_no_graph_and_no_false_zero(
    statuses: tuple[TransactionStatus, ...],
) -> None:
    result = build_usdt_relationship_graph(
        Network.ETHEREUM,
        [inspection(hash_value, status=status) for hash_value, status in zip((H1, H2), statuses)],
    )

    assert result.transfer_coverage is TransferCoverage.NONE
    assert result.nodes is result.edges is result.grouped_relationships is None
    assert result.known_total_usdt_amount_atomic is None
    assert all(transaction.usdt_event_count is None for transaction in result.transactions)


def test_domain_models_reject_tampered_provenance_and_aggregates() -> None:
    valid = build_usdt_relationship_graph(
        Network.ETHEREUM, [inspection(H1, transfers=(transfer(H1, ALICE, BOB, 1, 9),))]
    )
    edge = (valid.edges or ())[0]

    with pytest.raises(ValidationError):
        RelationshipEdge(**{**edge.model_dump(), "event_id": "invented"})
    with pytest.raises(ValidationError):
        UsdtRelationshipGraph(
            **{**valid.model_dump(), "known_total_usdt_amount_atomic": 2}
        )
    with pytest.raises(ValidationError):
        UsdtRelationshipGraph(
            **{**valid.model_dump(), "nodes": []}
        )


class RecordingInspector:
    def __init__(self, fail_on: str | None = None) -> None:
        self.calls: list[str] = []
        self.fail_on = fail_on

    def inspect_transaction(self, network: Any, tx_hash: str) -> TransactionInspection:
        self.calls.append(tx_hash)
        if tx_hash == self.fail_on:
            raise ProviderTimeoutError("internal marker that must not be returned")
        return inspection(tx_hash)


@pytest.mark.parametrize(
    "hashes",
    [[], [H1, H2, H3, H4], [H1, H1.upper().replace("0X", "0x")], ["0x12"], ["ab" * 32]],
    ids=["none", "four", "duplicate-normalized", "malformed", "wrong-chain"],
)
def test_service_validates_every_input_before_inspection(hashes: list[str]) -> None:
    service = RecordingInspector()

    with pytest.raises(ValueError):
        inspect_usdt_relationships(service, Network.ETHEREUM, hashes)
    assert service.calls == []


def test_service_is_ordered_and_fail_fast() -> None:
    service = RecordingInspector(fail_on=H2)

    with pytest.raises(ProviderTimeoutError):
        inspect_usdt_relationships(service, Network.ETHEREUM, [H1, H2, H3])
    assert service.calls == [H1, H2]


# --- Request validation -------------------------------------------------------------------------

VALID_ETH = {"network": "ethereum", "tx_hashes": [USDT_HASH]}


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"network": "ethereum"},
        {"tx_hashes": [USDT_HASH]},
        {**VALID_ETH, "tx_hashes": []},
        {**VALID_ETH, "tx_hashes": [USDT_HASH, SWAP_HASH, NATIVE_HASH, PENDING_HASH]},
        {**VALID_ETH, "tx_hashes": [USDT_HASH, USDT_HASH.upper().replace("0X", "0x")]},
        {**VALID_ETH, "tx_hashes": ["0x1234"]},
        {**VALID_ETH, "tx_hashes": [TRC20_HASH]},
        {**VALID_ETH, "tx_hashes": USDT_HASH},
        {**VALID_ETH, "tx_hashes": [123]},
        {**VALID_ETH, "network": "Ethereum"},
        {**VALID_ETH, "network": "bitcoin"},
        {"network": "tron", "tx_hashes": [USDT_HASH]},
        {**VALID_ETH, "extra": True},
        [VALID_ETH],
    ],
)
def test_invalid_request_is_422_without_rpc_or_quota(
    client: TestClient,
    eth: EthereumNode,
    tron: TronNode,
    quota: SlidingWindowRateLimiter,
    body: Any,
) -> None:
    response = call(client, body)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"
    assert eth.calls == [] and tron.calls == []
    assert units_left(quota) == 30


def test_validation_error_does_not_echo_inputs_or_unknown_field(client: TestClient) -> None:
    marker = "0x" + "z" * 64

    response = call(client, {"network": "ethereum", "tx_hashes": [marker], TOKEN[:8]: 1})

    assert response.status_code == 422
    assert marker not in response.text and TOKEN[:8] not in response.text


# --- End to end through real providers and simulated nodes --------------------------------------


def test_ethereum_graph_is_exact_ordered_and_auditable(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_usdt(eth)
    eth_swap(eth)
    mine(eth, NATIVE_HASH, ALICE, BOB, 10**30)

    data = graph(client, "ethereum", [USDT_HASH.upper().replace("0X", "0x"), SWAP_HASH, NATIVE_HASH])

    assert data["network"] == "ethereum"
    assert data["sample_scope"] == "supplied_transactions_only"
    assert data["transfer_coverage"] == "complete"
    assert data["transactions"] == [
        {"tx_hash": USDT_HASH, "transaction_status": "success",
         "transfer_data_available": True, "usdt_event_count": 1},
        {"tx_hash": SWAP_HASH, "transaction_status": "success",
         "transfer_data_available": True, "usdt_event_count": 3},
        {"tx_hash": NATIVE_HASH, "transaction_status": "success",
         "transfer_data_available": True, "usdt_event_count": 0},
    ]
    assert [node["address"] for node in data["nodes"]] == sorted([ALICE, BOB, CAROL])
    assert [(edge["tx_hash"], edge["event_position"], edge["log_index"]) for edge in data["edges"]] == [
        (USDT_HASH, 0, 316),
        (SWAP_HASH, 0, 5),
        (SWAP_HASH, 1, 8),
        (SWAP_HASH, 2, 9),
    ]
    assert [edge["amount_atomic"] for edge in data["edges"]] == [
        "625000000", str(MAX_UINT256), str(MAX_UINT256), "0"
    ]
    assert data["edges"][0]["event_id"] == f"ethereum:{USDT_HASH}:0"
    assert all(edge["token_contract"] == ETH_USDT for edge in data["edges"])
    assert data["known_total_usdt_amount_atomic"] == str(625_000_000 + 2 * MAX_UINT256)
    assert all(isinstance(number, int) and number <= MAX_SAFE_INTEGER for number in walk_numbers(data))


def test_tron_uses_filtered_event_position_and_never_invents_log_index(
    client: TestClient, tron: TronNode
) -> None:
    tron_usdt(tron)  # contains official event, ignored look-alike event, official event

    data = graph(client, "tron", [TRC20_HASH.upper()])

    assert data["transactions"][0]["usdt_event_count"] == 2
    assert [(edge["event_position"], edge["log_index"]) for edge in data["edges"]] == [
        (0, None), (1, None)
    ]
    assert [(edge["from_address"], edge["to_address"], edge["amount_atomic"])
            for edge in data["edges"]] == [
        (TRON_ALICE, TRON_BOB, "10000000000"),
        (TRON_BOB, TRON_CAROL, "1"),
    ]
    assert all(edge["token_contract"] == TRON_USDT for edge in data["edges"])


def test_partial_coverage_keeps_known_edges_and_marks_unknown(
    client: TestClient, tron: TronNode
) -> None:
    tron_usdt(tron)
    tron.stores[GET_TRANSACTION_PATH][UNCONFIRMED_HASH] = trc20_call(
        UNCONFIRMED_HASH, TRON_ALICE
    )

    data = graph(client, "tron", [TRC20_HASH, UNCONFIRMED_HASH])

    assert data["transfer_coverage"] == "partial"
    assert data["transactions"][1] == {
        "tx_hash": UNCONFIRMED_HASH,
        "transaction_status": "unconfirmed",
        "transfer_data_available": False,
        "usdt_event_count": None,
    }
    assert len(data["edges"]) == 2
    assert data["known_total_usdt_amount_atomic"] == "10000000001"


def test_pending_and_not_found_produce_no_false_graph(
    client: TestClient, eth: EthereumNode
) -> None:
    eth.transactions[PENDING_HASH] = eth_tx(PENDING_HASH, ALICE, BOB, 1, None)

    data = graph(client, "ethereum", [PENDING_HASH, UNKNOWN_HASH])

    assert [transaction["transaction_status"] for transaction in data["transactions"]] == [
        "pending", "not_found"
    ]
    assert [transaction["usdt_event_count"] for transaction in data["transactions"]] == [
        None, None
    ]
    assert data["transfer_coverage"] == "none"
    assert data["nodes"] is data["edges"] is data["grouped_relationships"] is None
    assert data["known_total_usdt_amount_atomic"] is None


def test_final_transaction_without_usdt_returns_empty_graph(
    client: TestClient, eth: EthereumNode
) -> None:
    mine(eth, NATIVE_HASH, ALICE, BOB, 1)

    data = graph(client, "ethereum", [NATIVE_HASH])

    assert data["transfer_coverage"] == "complete"
    assert data["transactions"][0]["usdt_event_count"] == 0
    assert data["nodes"] == data["edges"] == data["grouped_relationships"] == []
    assert data["known_total_usdt_amount_atomic"] == "0"


def test_fail_fast_returns_safe_error_without_inspecting_next_hash(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_usdt(eth)
    eth_swap(eth)
    mine(eth, NATIVE_HASH, ALICE, BOB, 1)
    eth.receipts[SWAP_HASH] = None

    response = call(client, {"network": "ethereum", "tx_hashes": [USDT_HASH, SWAP_HASH, NATIVE_HASH]})

    assert response.status_code == 503
    assert response.json() == {"error": {
        "code": "receipt_unavailable",
        "message": "The transaction execution data is not available yet. Retry later.",
    }}
    assert eth.calls.count("eth_getTransactionByHash") == 4


def test_provider_failure_does_not_leak_secrets_or_exception_text(
    client: TestClient, eth: EthereumNode
) -> None:
    eth.failures["eth_chainId"] = ProviderTimeoutError(
        f"private {RPC_SECRET} at {ETH_RPC_URL}"
    )

    response = call(client, VALID_ETH)

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "provider_timeout"
    assert "private" not in response.text


# --- Authentication, capacity, body limit and shared weighted quota -----------------------------


def test_bearer_authentication_is_required_before_rpc_and_quota(
    eth: EthereumNode, quota: SlidingWindowRateLimiter, monkeypatch: pytest.MonkeyPatch
) -> None:
    anonymous = TestClient(app)
    for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {TOKEN}"}):
        response = call(anonymous, VALID_ETH, headers=headers)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
    monkeypatch.delenv(API_TOKEN_ENV_VAR)
    assert call(anonymous, VALID_ETH, headers=AUTH).json()["error"]["code"] == "auth_not_configured"
    assert eth.calls == [] and units_left(quota) == 30


def test_body_limit_rejects_before_rpc_and_quota(
    client: TestClient, eth: EthereumNode, quota: SlidingWindowRateLimiter
) -> None:
    body = json.dumps(VALID_ETH).encode() + b" " * MAX_BODY_BYTES

    response = call(client, content=body, headers={"Content-Type": "application/json"})

    assert response.status_code == 413
    assert eth.calls == [] and units_left(quota) == 30


def test_busy_service_rejects_before_rpc_and_quota(
    client: TestClient, eth: EthereumNode, quota: SlidingWindowRateLimiter
) -> None:
    slots = ConcurrencyLimiter()
    app.dependency_overrides[get_concurrency_limiter] = lambda: slots
    for _ in range(slots.max_concurrent):
        assert slots.try_acquire()

    try:
        response = call(client, VALID_ETH)
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "service_busy"
        assert response.headers["retry-after"] == "1"
        assert eth.calls == [] and units_left(quota) == 30
    finally:
        for _ in range(slots.max_concurrent):
            slots.release()


class EmptyService:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def inspect_transaction(self, network: Network, tx_hash: str) -> TransactionInspection:
        self.calls.append(tx_hash)
        return inspection(tx_hash)


def test_weighted_quota_is_atomic_and_shared_with_all_analysis_routes(
    client: TestClient, quota: SlidingWindowRateLimiter
) -> None:
    service = EmptyService()
    app.dependency_overrides[get_transaction_analysis_service] = lambda: service
    assess_body = {"network": "ethereum", "tx_hash": H1}
    address_body = {"network": "ethereum", "address": ALICE, "tx_hashes": [H1, H2]}

    assert call(client, assess_body, path=INSPECT).status_code == 200  # 1 unit
    assert call(client, assess_body, path=ASSESS).status_code == 200  # 1 unit
    assert call(client, address_body, path=INVESTIGATE).status_code == 200  # 2 units
    for _ in range(8):
        assert call(client, {"network": "ethereum", "tx_hashes": [H1, H2, H3]}).status_code == 200
    assert units_left(quota) == 2
    calls_before = len(service.calls)

    refused = call(client, {"network": "ethereum", "tx_hashes": [H1, H2, H3]})

    assert refused.status_code == 429
    assert refused.json()["error"]["code"] == "rate_limited"
    assert refused.headers["retry-after"] == "60"
    assert len(service.calls) == calls_before
    assert units_left(quota) == 2  # all-or-nothing: no partial admission
    assert call(client, {"network": "ethereum", "tx_hashes": [H1, H2]}).status_code == 200
    assert call(client, assess_body, path=INSPECT).status_code == 429


def test_fail_fast_still_releases_the_concurrency_slot(client: TestClient) -> None:
    failing = RecordingInspector(fail_on=H1)
    app.dependency_overrides[get_transaction_analysis_service] = lambda: failing
    slots = ConcurrencyLimiter(max_concurrent=1)
    app.dependency_overrides[get_concurrency_limiter] = lambda: slots

    first = call(client, {"network": "ethereum", "tx_hashes": [H1, H2]})
    second = call(client, {"network": "ethereum", "tx_hashes": [H1]})

    assert first.status_code == second.status_code == 504
    assert failing.calls == [H1, H1]


class BlockingService:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def inspect_transaction(self, network: Network, tx_hash: str) -> TransactionInspection:
        self.entered.set()
        assert self.release.wait(10), "test gate was never opened"
        return inspection(tx_hash)


def test_slot_is_held_until_graph_serialization_finishes(
    client: TestClient, quota: SlidingWindowRateLimiter
) -> None:
    service = BlockingService()
    app.dependency_overrides[get_transaction_analysis_service] = lambda: service
    slots = ConcurrencyLimiter(max_concurrent=1)
    app.dependency_overrides[get_concurrency_limiter] = lambda: slots

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            running = pool.submit(call, client, {"network": "ethereum", "tx_hashes": [H1]})
            assert service.entered.wait(10)
            refused = call(client, {"network": "ethereum", "tx_hashes": [H2]})
            assert refused.status_code == 503
            assert refused.json()["error"]["code"] == "service_busy"
            assert units_left(quota) == 29  # only the running request reached the quota
            service.release.set()
            assert running.result(10).status_code == 200
    finally:
        service.release.set()

    assert slots.try_acquire()  # the completed response released the sole slot
    slots.release()


# --- Contract documentation and route regression ------------------------------------------------


def test_openapi_documents_strict_graph_contract_and_protections(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    operation = spec["paths"][URL]["post"]

    assert operation["security"] == [{"HTTPBearer": []}]
    assert {"200", "401", "413", "422", "429", "502", "503", "504"} <= set(
        operation["responses"]
    )
    assert "atomically" in operation["responses"]["429"]["description"]
    success = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert success["$ref"] == "#/components/schemas/UsdtRelationshipGraphResponse"
    request_schema = spec["components"]["schemas"]["UsdtRelationshipsRequest"]
    assert request_schema["additionalProperties"] is False
    hashes = request_schema["properties"]["tx_hashes"]
    assert (hashes["minItems"], hashes["maxItems"]) == (1, 3)
    response = spec["components"]["schemas"]["UsdtRelationshipGraphResponse"]
    assert response["additionalProperties"] is False
    assert response["properties"]["sample_scope"]["const"] == "supplied_transactions_only"
    assert "not a balance" in response["properties"]["known_total_usdt_amount_atomic"]["description"]


def test_existing_routes_remain_registered(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]

    assert {INSPECT, ASSESS, INVESTIGATE, URL, "/health"} <= set(paths)


def test_graph_contract_contains_no_score_balance_or_verdict(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_usdt(eth)
    data = graph(client, "ethereum", [USDT_HASH])
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    keys = set(data)
    for name in (
        "UsdtRelationshipGraphResponse",
        "RelationshipTransactionView",
        "RelationshipNodeView",
        "RelationshipEdgeView",
        "GroupedRelationshipView",
    ):
        keys.update(schemas[name]["properties"])
    assert not {
        key for key in keys
        if any(word in key.lower() for word in ("score", "balance", "verdict", "fraud", "risk"))
    }
