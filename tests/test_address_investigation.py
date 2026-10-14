"""Tests of Address Investigation v1 (POST /api/v1/addresses/investigate).

Integration tests run the real stack (auth, concurrency slot, weighted quota,
real TransactionAnalysisService and Ethereum / TRON providers) against the
in-memory nodes of the end-to-end suite: only the network is simulated.
Every address, hash, URL and key is FICTIONAL test data.
"""

import json
import socket
import threading
import time
from collections import deque
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
from app.api.rate_limit import (
    RateLimitExceededError,
    SlidingWindowRateLimiter,
    get_rate_limiter,
)
from app.api.schemas import MAX_SAFE_INTEGER
from app.api.transactions import get_transaction_analysis_service
from app.domain.analysis_input import Network
from app.domain.token_transfer import MAX_UINT256, NormalizedTokenTransfer
from app.domain.usdt_registry import get_usdt_contract
from app.main import app
from app.providers.base import NativeUnit, NormalizedTransaction, TransactionStatus
from app.services.address_investigation import (
    AddressActivitySummary,
    AddressInvestigation,
    AddressPresence,
    AddressUsdtObservation,
    InvestigatedTransaction,
    TransferCoverage,
    UsdtDirection,
    build_address_investigation,
    investigate_address,
    summarize_address_activity,
)
from app.services.transaction_analysis import TransactionInspection

# The simulated nodes and chain fixtures of the end-to-end suite (same tests/ directory).
from test_e2e_api import (  # noqa: E402
    ALICE,
    BOB,
    CAROL,
    DAVE,
    ETH_RPC_URL,
    ETH_USDT,
    NATIVE_HASH,
    PENDING_HASH,
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
from app.providers.tron import GET_TRANSACTION_PATH  # noqa: E402

INVESTIGATE = "/api/v1/addresses/investigate"
INSPECT = "/api/v1/transactions/inspect"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
FORBIDDEN_WORDS = ("score", "fraud", "balance", "safe", "risk", "verdict", "probab", "unrelated")


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


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


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
def quota(_environment: None, clock: FakeClock) -> SlidingWindowRateLimiter:
    # The production quota (30 per 60 s) on a controlled clock.
    limiter = SlidingWindowRateLimiter(clock=clock)
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    return limiter


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, headers=AUTH)


def call(client: TestClient, body: Any = None, path: str = INVESTIGATE, **kwargs: Any) -> Any:
    if body is not None:
        kwargs["json"] = body
    response = client.post(path, **kwargs)
    raw = response.text + json.dumps(dict(response.headers))
    assert all(secret not in raw for secret in SECRETS)
    assert "example.invalid" not in raw
    return response


def investigate(client: TestClient, network: str, address: str, hashes: list[str]) -> dict:
    response = call(client, {"network": network, "address": address, "tx_hashes": hashes})
    assert response.status_code == 200, response.text
    return response.json()


def units_left(limiter: SlidingWindowRateLimiter) -> int:
    """Quota units still free, measured by probing (then restored)."""
    for cost in range(limiter.max_requests, 0, -1):
        try:
            limiter.acquire(cost)
        except RateLimitExceededError:
            continue
        for _ in range(cost):
            limiter._admissions.pop()  # undo the probe (test helper only)
        return cost
    return 0


def walk(value: Any) -> Iterator[Any]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)
    else:
        yield value


# --- Domain builders (pure tests) ----------------------------------------------------------------

H1, H2, H3, H4 = ("0x" + c * 64 for c in "1234")
USDT = get_usdt_contract(Network.ETHEREUM).contract_address


def transfer(
    tx_hash: str, sender: str, recipient: str, amount: int, index: int
) -> NormalizedTokenTransfer:
    return NormalizedTokenTransfer(
        network=Network.ETHEREUM, tx_hash=tx_hash, token_symbol="USDT", token_contract=USDT,
        from_address=sender, to_address=recipient, amount_atomic=amount, decimals=6,
        log_index=index,
    )


def inspection(
    tx_hash: str, status: TransactionStatus = TransactionStatus.SUCCESS,
    sender: str | None = ALICE, to: str | None = USDT,
    transfers: tuple[NormalizedTokenTransfer, ...] | None = (),
) -> TransactionInspection:
    mined = status in (TransactionStatus.SUCCESS, TransactionStatus.REVERTED)
    found = status is not TransactionStatus.NOT_FOUND
    transaction = NormalizedTransaction(
        network=Network.ETHEREUM, tx_hash=tx_hash, status=status,
        from_address=sender if found else None, to_address=to if found else None,
        native_value_atomic=0 if found else None, native_unit=NativeUnit.WEI if found else None,
        block_number=1 if mined else None, block_timestamp=1 if mined else None,
    )
    return TransactionInspection(
        network=Network.ETHEREUM, tx_hash=tx_hash, transaction=transaction,
        usdt_transfers=transfers if mined else None,
    )


# --- Pure observation and aggregation --------------------------------------------------------


def test_directions_self_transfers_and_counterparties_are_exact() -> None:
    big = 2**60  # above 2**53
    result = build_address_investigation(Network.ETHEREUM, CAROL.lower(), [
        inspection(H1, transfers=(
            transfer(H1, ALICE, CAROL, MAX_UINT256, 5),
            transfer(H1, CAROL, BOB, MAX_UINT256, 8),
            transfer(H1, CAROL, CAROL, 5, 9),
            transfer(H1, ALICE, BOB, 7, 10),  # does not involve CAROL
        )),
        inspection(H2, sender=BOB, to=CAROL, transfers=(transfer(H2, BOB, CAROL, big, 1),)),
    ])

    assert result.address == CAROL  # canonical EIP-55
    first, second = result.transactions
    assert [(o.direction, o.counterparty, o.amount_atomic) for o in first.usdt_observations] == [
        (UsdtDirection.INCOMING, ALICE, MAX_UINT256),
        (UsdtDirection.OUTGOING, BOB, MAX_UINT256),
        (UsdtDirection.SELF_TRANSFER, None, 5),
    ]
    assert [r.value for r in second.observed_roles] == [
        "transaction_recipient", "usdt_transfer_recipient"
    ]
    summary = result.summary
    assert summary.transfer_coverage is TransferCoverage.COMPLETE
    assert (summary.incoming_usdt_event_count, summary.outgoing_usdt_event_count) == (3, 2)
    assert summary.self_transfer_count == 1  # counted in both directions
    assert summary.known_incoming_usdt_amount_atomic == MAX_UINT256 + 5 + big  # above uint256
    assert summary.known_outgoing_usdt_amount_atomic == MAX_UINT256 + 5
    assert summary.known_self_transfer_amount_atomic == 5
    assert summary.counterparties == (ALICE, BOB)


def test_final_transaction_without_event_is_empty_not_unknown() -> None:
    result = build_address_investigation(Network.ETHEREUM, ALICE, [inspection(H1, to=BOB)])

    assert result.transactions[0].usdt_observations == ()
    assert result.summary.transfer_coverage is TransferCoverage.COMPLETE
    assert result.summary.incoming_usdt_event_count == 0
    assert result.summary.known_incoming_usdt_amount_atomic == 0
    assert result.summary.counterparties == ()


@pytest.mark.parametrize(
    ("status", "presence"),
    [
        (TransactionStatus.PENDING, AddressPresence.OBSERVED),
        (TransactionStatus.UNCONFIRMED, AddressPresence.OBSERVED),
        (TransactionStatus.NOT_FOUND, AddressPresence.NOT_OBSERVED),
    ],
)
def test_non_final_transactions_have_unknown_transfers_never_zero(
    status: TransactionStatus, presence: AddressPresence
) -> None:
    tx = inspection(H1, status=status)
    if status is TransactionStatus.UNCONFIRMED:  # TRON-only status: rebuild on TRON
        transaction = NormalizedTransaction(
            network=Network.TRON, tx_hash="ab" * 32, status=status, from_address=TRON_ALICE,
            to_address=TRON_BOB, native_value_atomic=0, native_unit=NativeUnit.SUN,
        )
        tx = TransactionInspection(network=Network.TRON, tx_hash="ab" * 32,
                                   transaction=transaction, usdt_transfers=None)
        result = build_address_investigation(Network.TRON, TRON_ALICE, [tx])
    else:
        result = build_address_investigation(Network.ETHEREUM, ALICE, [tx])

    observed = result.transactions[0]
    assert observed.usdt_observations is None and observed.transfer_data_available is False
    assert observed.presence is presence
    summary = result.summary
    assert summary.transfer_coverage is TransferCoverage.NONE
    assert summary.transactions_with_unknown_transfers == 1
    for name in ("incoming_usdt_event_count", "outgoing_usdt_event_count", "self_transfer_count",
                 "known_incoming_usdt_amount_atomic", "known_outgoing_usdt_amount_atomic",
                 "known_self_transfer_amount_atomic", "counterparties"):
        assert getattr(summary, name) is None  # no invented amount


def test_partial_coverage_keeps_known_totals_apart_from_unknown_ones() -> None:
    result = build_address_investigation(Network.ETHEREUM, BOB, [
        inspection(H1, transfers=(transfer(H1, ALICE, BOB, 100, 0),)),
        inspection(H2, status=TransactionStatus.PENDING, sender=BOB),
    ])

    summary = result.summary
    assert summary.transfer_coverage is TransferCoverage.PARTIAL
    assert (summary.transactions_with_transfer_data,
            summary.transactions_with_unknown_transfers) == (1, 1)
    assert summary.known_incoming_usdt_amount_atomic == 100  # from the known transaction only
    assert summary.transactions_where_observed == 2


def test_absent_address_is_not_observed_never_unrelated() -> None:
    result = build_address_investigation(Network.ETHEREUM, DAVE, [
        inspection(H1, transfers=(transfer(H1, ALICE, BOB, 1, 0),)),
    ])

    assert result.presence is AddressPresence.NOT_OBSERVED
    assert result.transactions[0].observed_roles == ()
    assert result.transactions[0].usdt_observations == ()
    assert result.summary.transactions_where_observed == 0


def test_models_refuse_inconsistent_data() -> None:
    valid = build_address_investigation(Network.ETHEREUM, BOB, [
        inspection(H1, transfers=(transfer(H1, ALICE, BOB, 100, 0),)),
    ])
    with pytest.raises(ValidationError):
        AddressUsdtObservation(direction=UsdtDirection.SELF_TRANSFER, counterparty=ALICE,
                               amount_atomic=1, log_index=0)
    with pytest.raises(ValidationError):  # unknown transfers reported as an empty list
        InvestigatedTransaction(tx_hash=H1, transaction_status=TransactionStatus.PENDING,
                                presence=AddressPresence.NOT_OBSERVED, observed_roles=(),
                                transfer_data_available=False, usdt_observations=())
    with pytest.raises(ValidationError):  # no coverage, yet zero instead of unknown
        AddressActivitySummary(**{**valid.summary.model_dump(), "transfer_coverage": "none",
                                  "transactions_with_transfer_data": 0,
                                  "transactions_with_unknown_transfers": 1})
    with pytest.raises(ValidationError):  # summary not computed from the transactions
        AddressInvestigation(**{**valid.model_dump(), "summary": {
            **valid.summary.model_dump(), "known_incoming_usdt_amount_atomic": 101}})
    assert summarize_address_activity(valid.transactions) == valid.summary


class RecordingInspector:
    def __init__(self, fail_on: str | None = None) -> None:
        self.calls: list[str] = []
        self.fail_on = fail_on

    def inspect_transaction(self, network: Any, tx_hash: str) -> TransactionInspection:
        self.calls.append(tx_hash)
        if tx_hash == self.fail_on:
            raise RuntimeError("provider failure")
        return inspection(tx_hash)


@pytest.mark.parametrize(
    "hashes",
    [[], [H1, H2, H3, H4], [H1, H1.upper().replace("0X", "0x")], ["0x12"], ["ab" * 32]],
    ids=["none", "four", "duplicate-after-normalization", "malformed", "tron-hash-on-ethereum"],
)
def test_invalid_inputs_are_refused_before_any_inspection(hashes: list[str]) -> None:
    inspector = RecordingInspector()

    with pytest.raises(ValueError):
        investigate_address(inspector, Network.ETHEREUM, ALICE, hashes)
    assert inspector.calls == []


def test_investigation_is_fail_fast_and_ordered() -> None:
    inspector = RecordingInspector(fail_on=H2)

    with pytest.raises(RuntimeError):
        investigate_address(inspector, Network.ETHEREUM, ALICE, [H1, H2, H3])
    assert inspector.calls == [H1, H2]  # H3 never inspected, nothing returned


# --- Weighted rate limiter -----------------------------------------------------------------------


def test_weighted_acquisition_is_all_or_nothing(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(clock=clock)
    for _ in range(9):
        limiter.acquire(3)
    limiter.acquire()  # 28 units used

    with pytest.raises(RateLimitExceededError):
        limiter.acquire(3)
    assert len(limiter._admissions) == 28  # nothing partially consumed
    limiter.acquire(2)
    with pytest.raises(RateLimitExceededError):
        limiter.acquire()


def test_weighted_retry_after_waits_for_enough_expirations(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(clock=clock)
    for step in range(3):  # 10 units at t = 0, 10 and 20
        for _ in range(10):
            limiter.acquire()
        clock.now += 10
    # t = 30, quota full: 1 unit needs the t=0 batch, 15 units need the t=10 batch.
    with pytest.raises(RateLimitExceededError) as one:
        limiter.acquire(1)
    with pytest.raises(RateLimitExceededError) as fifteen:
        limiter.acquire(15)

    assert (one.value.retry_after, fifteen.value.retry_after) == (30, 40)
    clock.now += 39.999
    with pytest.raises(RateLimitExceededError):
        limiter.acquire(15)
    clock.now += 0.001
    limiter.acquire(15)


@pytest.mark.parametrize("cost", [0, -1, True, 1.5, "1", 31])
def test_invalid_cost_is_refused_without_consuming(clock: FakeClock, cost: Any) -> None:
    limiter = SlidingWindowRateLimiter(clock=clock)

    with pytest.raises(ValueError):
        limiter.acquire(cost)
    assert len(limiter._admissions) == 0


def test_default_cost_is_one(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(max_requests=2, clock=clock)
    limiter.acquire()
    limiter.acquire(1)

    with pytest.raises(RateLimitExceededError) as refused:
        limiter.acquire()
    assert refused.value.retry_after == 60


def test_concurrent_weighted_acquisitions_never_exceed_the_quota(clock: FakeClock) -> None:
    class SlowLenDeque(deque):
        def __len__(self) -> int:
            length = super().__len__()
            time.sleep(0.0005)  # stale by the time it is used: exposes any race
            return length

    limiter = SlidingWindowRateLimiter(clock=clock)
    limiter._admissions = SlowLenDeque(maxlen=limiter.max_requests)
    threads, barrier, admitted = 40, threading.Barrier(40), []
    lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        try:
            limiter.acquire(3)
        except RateLimitExceededError:
            return
        with lock:
            admitted.append(3)

    workers = [threading.Thread(target=attempt) for _ in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert sum(admitted) == 30 and len(limiter._admissions) == 30


# --- Request validation through HTTP ---------------------------------------------------------


VALID_ETH = {"network": "ethereum", "address": ALICE, "tx_hashes": [USDT_HASH]}


@pytest.mark.parametrize(
    "body",
    [
        {"network": "ethereum", "tx_hashes": [USDT_HASH]},
        {"network": "ethereum", "address": ALICE},
        {**VALID_ETH, "tx_hashes": []},
        {**VALID_ETH, "tx_hashes": [USDT_HASH, SWAP_HASH, NATIVE_HASH, PENDING_HASH]},
        {**VALID_ETH, "tx_hashes": [USDT_HASH, USDT_HASH.upper().replace("0X", "0x")]},
        {**VALID_ETH, "tx_hashes": ["0x1234"]},
        {**VALID_ETH, "tx_hashes": [TRC20_HASH]},
        {**VALID_ETH, "tx_hashes": USDT_HASH},
        {**VALID_ETH, "tx_hashes": [123]},
        {**VALID_ETH, "address": ALICE[:-1] + ("d" if ALICE[-1] != "d" else "e")},
        {**VALID_ETH, "address": "0x5AAEB6053f3e94c9b9a09f33669435e7ef1beaed"},  # bad checksum
        {**VALID_ETH, "address": TRON_ALICE},
        {"network": "tron", "address": ALICE, "tx_hashes": [TRC20_HASH]},
        {"network": "tron", "address": TRON_ALICE, "tx_hashes": [USDT_HASH]},
        {**VALID_ETH, "network": "bitcoin"},
        {**VALID_ETH, "address": "x" * 129},
        {**VALID_ETH, "extra": 1},
        [VALID_ETH],
    ],
    ids=[
        "no-address", "no-hashes", "zero-hashes", "four-hashes", "duplicate", "short-hash",
        "tron-hash", "hashes-not-a-list", "hash-not-a-string", "address-typo", "bad-checksum",
        "tron-address-on-ethereum", "eth-address-on-tron", "eth-hash-on-tron", "bitcoin",
        "address-too-long", "extra-field", "array-body",
    ],
)
def test_invalid_requests_are_422_without_rpc_or_quota(
    client: TestClient, eth: EthereumNode, tron: TronNode, quota: SlidingWindowRateLimiter,
    body: Any,
) -> None:
    eth_usdt(eth)

    response = call(client, body)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"
    assert eth.calls == [] and tron.calls == []
    assert units_left(quota) == 30


def test_validation_errors_do_not_echo_the_input(client: TestClient) -> None:
    marker = "0x" + "f" * 39 + "Z"
    response = call(client, {**VALID_ETH, "address": marker, f"field_{TOKEN[:5]}": 1})

    assert response.status_code == 422
    assert marker not in response.text and TOKEN[:5] not in response.text


# --- Ethereum through the real stack ---------------------------------------------------------


def test_ethereum_sample_for_a_recipient(client: TestClient, eth: EthereumNode) -> None:
    eth_usdt(eth)
    eth_swap(eth)
    mine(eth, NATIVE_HASH, ALICE, BOB, 10**30)

    data = investigate(client, "ethereum", BOB.lower(), [USDT_HASH, SWAP_HASH, NATIVE_HASH])

    assert data["address"] == BOB and data["network"] == "ethereum"
    assert data["sample_scope"] == "supplied_transactions_only"
    assert data["presence"] == "observed"
    assert data["transactions"][0] == {
        "tx_hash": USDT_HASH,
        "transaction_status": "success",
        "presence": "observed",
        "observed_roles": ["usdt_transfer_recipient"],
        "transfer_data_available": True,
        "usdt_observations": [{
            "direction": "incoming", "counterparty": ALICE,
            "amount_atomic": "625000000", "log_index": 316,
        }],
    }
    assert data["transactions"][1]["usdt_observations"] == [{
        "direction": "incoming", "counterparty": CAROL,
        "amount_atomic": str(MAX_UINT256), "log_index": 8,
    }]  # the look-alike token event to BOB is not official USDT
    assert data["transactions"][2]["observed_roles"] == ["transaction_recipient"]
    assert data["transactions"][2]["usdt_observations"] == []  # native only: known empty
    assert data["summary"] == {
        "transfer_coverage": "complete",
        "inspected_transaction_count": 3,
        "transactions_with_transfer_data": 3,
        "transactions_with_unknown_transfers": 0,
        "transactions_where_observed": 3,
        "incoming_usdt_event_count": 2,
        "outgoing_usdt_event_count": 0,
        "self_transfer_count": 0,
        "known_incoming_usdt_amount_atomic": str(625_000_000 + MAX_UINT256),
        "known_outgoing_usdt_amount_atomic": "0",
        "known_self_transfer_amount_atomic": "0",
        "counterparties": [ALICE, CAROL],
    }
    numbers = [v for v in walk(data) if isinstance(v, (int, float)) and not isinstance(v, bool)]
    assert all(isinstance(n, int) and n <= MAX_SAFE_INTEGER for n in numbers)


def test_ethereum_self_transfer_is_flagged(client: TestClient, eth: EthereumNode) -> None:
    eth_swap(eth)

    data = investigate(client, "ethereum", CAROL, [SWAP_HASH])

    tx = data["transactions"][0]
    assert tx["observed_roles"] == [
        "transaction_recipient", "usdt_transfer_sender", "usdt_transfer_recipient"
    ]
    assert [o["direction"] for o in tx["usdt_observations"]] == [
        "incoming", "outgoing", "self_transfer"
    ]
    assert tx["usdt_observations"][2]["counterparty"] is None
    summary = data["summary"]
    assert (summary["incoming_usdt_event_count"], summary["outgoing_usdt_event_count"],
            summary["self_transfer_count"]) == (2, 2, 1)
    assert summary["counterparties"] == [ALICE, BOB]


def test_ethereum_unknown_transfers_are_never_zero(client: TestClient, eth: EthereumNode) -> None:
    eth.transactions[PENDING_HASH] = eth_tx(PENDING_HASH, ALICE, BOB, 1, None)

    data = investigate(client, "ethereum", ALICE, [PENDING_HASH, UNKNOWN_HASH])

    pending, unknown = data["transactions"]
    assert (pending["transaction_status"], pending["presence"]) == ("pending", "observed")
    assert pending["usdt_observations"] is None
    assert (unknown["transaction_status"], unknown["presence"]) == ("not_found", "not_observed")
    summary = data["summary"]
    assert summary["transfer_coverage"] == "none"
    assert summary["known_incoming_usdt_amount_atomic"] is None
    assert summary["counterparties"] is None


def test_address_absent_from_the_sample_is_not_observed(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_usdt(eth)

    data = investigate(client, "ethereum", DAVE, [USDT_HASH])

    assert data["presence"] == "not_observed"
    assert data["transactions"][0]["observed_roles"] == []
    assert data["summary"]["counterparties"] == []


def test_a_failed_inspection_fails_the_whole_investigation(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_usdt(eth)
    eth_swap(eth)
    mine(eth, NATIVE_HASH, ALICE, BOB, 1)
    eth.receipts[SWAP_HASH] = None  # second transaction: receipt unavailable

    response = call(client, {"network": "ethereum", "address": BOB,
                             "tx_hashes": [USDT_HASH, SWAP_HASH, NATIVE_HASH]})

    assert response.status_code == 503
    assert response.json() == {"error": {
        "code": "receipt_unavailable",
        "message": "The transaction execution data is not available yet. Retry later.",
    }}  # no partial result
    assert eth.calls.count("eth_getTransactionByHash") == 4  # 3 reads of the 1st, 1 of the 2nd


# --- TRON through the real stack -----------------------------------------------------------------


def test_tron_sample_with_partial_coverage(client: TestClient, tron: TronNode) -> None:
    tron_usdt(tron)
    tron.stores[GET_TRANSACTION_PATH][UNCONFIRMED_HASH] = trc20_call(UNCONFIRMED_HASH, TRON_BOB)

    data = investigate(client, "tron", TRON_BOB, [TRC20_HASH.upper(), UNCONFIRMED_HASH])

    final, unconfirmed = data["transactions"]
    assert final["tx_hash"] == TRC20_HASH  # normalized
    assert final["observed_roles"] == ["usdt_transfer_sender", "usdt_transfer_recipient"]
    assert final["usdt_observations"] == [
        {"direction": "incoming", "counterparty": TRON_ALICE,
         "amount_atomic": "10000000000", "log_index": None},
        {"direction": "outgoing", "counterparty": TRON_CAROL,
         "amount_atomic": "1", "log_index": None},
    ]
    assert unconfirmed["transaction_status"] == "unconfirmed"
    assert unconfirmed["observed_roles"] == ["transaction_sender"]
    assert unconfirmed["usdt_observations"] is None
    summary = data["summary"]
    assert summary["transfer_coverage"] == "partial"
    assert (summary["transactions_with_transfer_data"],
            summary["transactions_with_unknown_transfers"]) == (1, 1)
    assert summary["known_incoming_usdt_amount_atomic"] == "10000000000"
    assert summary["known_outgoing_usdt_amount_atomic"] == "1"
    assert summary["counterparties"] == sorted([TRON_ALICE, TRON_CAROL])


def test_response_carries_no_score_balance_or_verdict(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_swap(eth)

    data = investigate(client, "ethereum", CAROL, [SWAP_HASH])
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    keys = {k for k in walk(data) if isinstance(k, str) and not k.startswith("0x")}
    for name in ("AddressInvestigationResponse", "AddressActivitySummaryView",
                 "InvestigatedTransactionView", "AddressUsdtObservationView"):
        keys |= set(schemas[name]["properties"])
    assert not [k for k in keys if any(word in k.lower() for word in FORBIDDEN_WORDS)]


# --- Protections ---------------------------------------------------------------------------------


def test_authentication_failures_use_no_rpc_and_no_quota(
    eth: EthereumNode, quota: SlidingWindowRateLimiter, monkeypatch: pytest.MonkeyPatch
) -> None:
    eth_usdt(eth)
    anonymous = TestClient(app)

    for headers in ({}, {"Authorization": "Bearer wrong"}):
        response = call(anonymous, VALID_ETH, headers=headers)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
    monkeypatch.delenv(API_TOKEN_ENV_VAR)
    assert call(anonymous, VALID_ETH, headers=AUTH).json()["error"]["code"] == "auth_not_configured"
    assert eth.calls == [] and units_left(quota) == 30


def test_oversized_body_is_413_before_anything(
    client: TestClient, eth: EthereumNode, quota: SlidingWindowRateLimiter
) -> None:
    body = json.dumps(VALID_ETH).encode() + b" " * MAX_BODY_BYTES

    response = call(client, content=body, headers={"Content-Type": "application/json"})

    assert response.status_code == 413
    assert eth.calls == [] and units_left(quota) == 30


def test_each_hash_costs_one_quota_unit(
    client: TestClient, eth: EthereumNode, quota: SlidingWindowRateLimiter
) -> None:
    eth_usdt(eth)
    eth_swap(eth)
    mine(eth, NATIVE_HASH, ALICE, BOB, 1)
    three = [USDT_HASH, SWAP_HASH, NATIVE_HASH]

    for _ in range(9):
        investigate(client, "ethereum", BOB, three)
    assert units_left(quota) == 3
    investigate(client, "ethereum", BOB, [USDT_HASH])
    calls_before = len(eth.calls)

    refused = call(client, {"network": "ethereum", "address": BOB, "tx_hashes": three})

    assert refused.status_code == 429
    assert refused.json()["error"]["code"] == "rate_limited"
    assert refused.headers["retry-after"] == "60"
    assert len(eth.calls) == calls_before  # refused before any provider call
    assert units_left(quota) == 2  # nothing partially consumed
    investigate(client, "ethereum", BOB, [USDT_HASH, SWAP_HASH])  # exactly fills the quota
    assert call(client, path=INSPECT, body={"network": "ethereum", "tx_hash": USDT_HASH}
                ).status_code == 429  # one quota shared with the existing routes


def test_one_hash_costs_exactly_one_unit_shared_with_inspect(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_usdt(eth)

    investigate(client, "ethereum", ALICE, [USDT_HASH])
    for _ in range(29):
        assert call(client, path=INSPECT,
                    body={"network": "ethereum", "tx_hash": USDT_HASH}).status_code == 200

    assert call(client, path=INSPECT,
                body={"network": "ethereum", "tx_hash": USDT_HASH}).status_code == 429


def test_busy_service_refuses_without_rpc_or_quota(
    client: TestClient, eth: EthereumNode, quota: SlidingWindowRateLimiter
) -> None:
    eth_usdt(eth)
    slots = ConcurrencyLimiter()
    app.dependency_overrides[get_concurrency_limiter] = lambda: slots
    for _ in range(slots.max_concurrent):
        assert slots.try_acquire()

    response = call(client, VALID_ETH)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_busy"
    assert response.headers["retry-after"] == "1"
    assert eth.calls == [] and units_left(quota) == 30
    for _ in range(slots.max_concurrent):
        slots.release()


class BlockingService:
    """Blocks inside every inspection until ``gate`` opens."""

    def __init__(self) -> None:
        self.gate = threading.Event()
        self.entered = threading.Semaphore(0)
        self.calls: list[str] = []

    def inspect_transaction(self, network: Any, tx_hash: str) -> TransactionInspection:
        self.calls.append(tx_hash)
        self.entered.release()
        assert self.gate.wait(10), "gate never opened"
        return inspection(tx_hash)


def free_slots(limiter: ConcurrencyLimiter) -> int:
    taken = 0
    while limiter.try_acquire():
        taken += 1
    for _ in range(taken):
        limiter.release()
    return taken


def test_slot_is_held_for_the_whole_investigation_and_capacity_is_shared(
    client: TestClient, quota: SlidingWindowRateLimiter
) -> None:
    blocking = BlockingService()
    app.dependency_overrides[get_transaction_analysis_service] = lambda: blocking
    slots = ConcurrencyLimiter()
    app.dependency_overrides[get_concurrency_limiter] = lambda: slots
    body = {"network": "ethereum", "address": ALICE, "tx_hashes": [H1, H2]}

    try:
        with ThreadPoolExecutor(max_workers=9) as pool:
            running = [pool.submit(call, client, body) for _ in range(8)]
            for _ in range(8):
                assert blocking.entered.acquire(timeout=10)
            assert free_slots(slots) == 0  # 8 investigations hold every slot

            ninth = pool.submit(call, client, body).result(10)
            assert ninth.status_code == 503 and ninth.json()["error"]["code"] == "service_busy"
            assert units_left(quota) == 30 - 16  # only admitted investigations were charged
            blocking.gate.set()
            assert [f.result(10).status_code for f in running] == [200] * 8
    finally:
        blocking.gate.set()

    assert free_slots(slots) == 8  # released after the whole investigation
    assert len(blocking.calls) == 16


# --- OpenAPI and existing routes -------------------------------------------------------------


def test_openapi_documents_the_investigation_route(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    operation = spec["paths"][INVESTIGATE]["post"]
    assert operation["security"] == [{"HTTPBearer": []}]
    assert {"200", "401", "413", "422", "429", "502", "503", "504"} <= set(operation["responses"])
    assert "per transaction hash" in operation["responses"]["429"]["description"]
    success = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert success["$ref"] == "#/components/schemas/AddressInvestigationResponse"
    request = spec["components"]["schemas"]["AddressInvestigationRequest"]["properties"]
    assert (request["tx_hashes"]["minItems"], request["tx_hashes"]["maxItems"]) == (1, 3)
    response = spec["components"]["schemas"]["AddressInvestigationResponse"]["properties"]
    assert response["sample_scope"]["const"] == "supplied_transactions_only"
    for path in ("/api/v1/transactions/inspect", "/api/v1/transactions/assess"):
        assert "per transaction hash" not in spec["paths"][path]["post"]["responses"]["429"][
            "description"]
