"""API tests for the per-process bound on concurrent analyses.

Concurrency is made deterministic with events and semaphores: admitted
analyses block inside the service until the test opens a gate, so several
requests are provably in flight at once. Waits have a timeout so that a
regression fails instead of hanging; no test relies on arbitrary sleeps.
Every token below is a FICTIONAL test value, never a real credential.
"""

import asyncio
import json
import socket
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient

import app.api.transactions as transactions_module
from app.api.auth import API_TOKEN_ENV_VAR
from app.api.body_limit import MAX_BODY_BYTES
from app.api.concurrency_limit import (
    MAX_CONCURRENT_ANALYSES,
    AnalysisCapacityExceededError,
    ConcurrencyLimiter,
    get_concurrency_limiter,
    hold_analysis_slot,
)
from app.api.rate_limit import SlidingWindowRateLimiter, get_rate_limiter
from app.api.transactions import get_transaction_analysis_service
from app.domain.analysis_input import Network
from app.main import app
from app.providers.base import (
    NativeUnit,
    NormalizedTransaction,
    ProviderTimeoutError,
    ProviderUnavailableError,
    TransactionStatus,
)
from app.providers.ethereum import EthereumProvider
from app.providers.tron import TronProvider
from app.services.transaction_analysis import TransactionInspection

INSPECT = "/api/v1/transactions/inspect"
ASSESS = "/api/v1/transactions/assess"
PROTECTED = (INSPECT, ASSESS)
TOKEN = "fictional-test-token-not-a-secret-0123456789"  # test value only
AUTH = {"Authorization": f"Bearer {TOKEN}"}
ETH_HASH = "0x" + "ab" * 32
ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
BODY = {"network": "ethereum", "tx_hash": ETH_HASH}
SERVICE_BUSY = {
    "error": {"code": "service_busy", "message": "Analysis capacity is temporarily exhausted."}
}
CAPACITY = 8
WAIT = 10.0  # seconds; only reached if a regression blocks
ENV_VARS = (
    "CHAINSHIELD_ETHEREUM_RPC_URL",
    "CHAINSHIELD_TRON_RPC_URL",
    "CHAINSHIELD_TRON_API_KEY",
)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    # TestClient's event loops use loopback socket pairs on Windows.
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


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(API_TOKEN_ENV_VAR, TOKEN)
    get_transaction_analysis_service.cache_clear()
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()
    get_transaction_analysis_service.cache_clear()


class RecordingLimiter(ConcurrencyLimiter):
    """Real limiter that also counts what the API did with it."""

    def __init__(self, max_concurrent: int = MAX_CONCURRENT_ANALYSES) -> None:
        super().__init__(max_concurrent)
        self._counts_lock = threading.Lock()
        self.acquired = self.refused = self.released = 0

    def try_acquire(self) -> bool:
        admitted = super().try_acquire()
        with self._counts_lock:
            if admitted:
                self.acquired += 1
            else:
                self.refused += 1
        return admitted

    def release(self) -> None:
        super().release()
        with self._counts_lock:
            self.released += 1


def occupy(limiter: ConcurrencyLimiter, count: int) -> None:
    """Take slots directly, bypassing the API counters."""
    for _ in range(count):
        assert ConcurrencyLimiter.try_acquire(limiter)


def vacate(limiter: ConcurrencyLimiter, count: int) -> None:
    for _ in range(count):
        ConcurrencyLimiter.release(limiter)


def free_slots(limiter: ConcurrencyLimiter) -> int:
    taken = 0
    while ConcurrencyLimiter.try_acquire(limiter):
        taken += 1
    vacate(limiter, taken)
    return taken


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def slots(_isolated: None) -> RecordingLimiter:
    limiter = RecordingLimiter()
    app.dependency_overrides[get_concurrency_limiter] = lambda: limiter
    return limiter


@pytest.fixture(autouse=True)
def quota(_isolated: None) -> SlidingWindowRateLimiter:
    # Production quota (30 per 60 s) on a frozen clock: deterministic.
    limiter = SlidingWindowRateLimiter(clock=FakeClock())
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    return limiter


def inspection() -> TransactionInspection:
    transaction = NormalizedTransaction(
        network=Network.ETHEREUM, tx_hash=ETH_HASH, status=TransactionStatus.SUCCESS,
        from_address=ALICE, to_address=None, native_value_atomic=0,
        native_unit=NativeUnit.WEI, block_number=1, block_timestamp=1,
    )
    return TransactionInspection(
        network=Network.ETHEREUM, tx_hash=ETH_HASH, transaction=transaction, usdt_transfers=()
    )


class FakeService:
    def __init__(self, outcome: Any = None) -> None:
        self.outcome = outcome
        self.calls = 0
        self.factory_calls = 0

    def inspect_transaction(self, network: Network, tx_hash: str) -> TransactionInspection:
        self.calls += 1
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return inspection()


class BlockingService(FakeService):
    """Each call signals ``entered`` then blocks until ``gate`` is opened."""

    def __init__(self) -> None:
        super().__init__()
        self.gate = threading.Event()
        self.entered = threading.Semaphore(0)
        self._lock = threading.Lock()
        self.active = self.max_active = 0

    def inspect_transaction(self, network: Network, tx_hash: str) -> TransactionInspection:
        with self._lock:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        self.entered.release()
        try:
            assert self.gate.wait(WAIT), "gate never opened"
            return inspection()
        finally:
            with self._lock:
                self.active -= 1


def install(service: FakeService) -> FakeService:
    def factory() -> FakeService:
        service.factory_calls += 1
        return service

    app.dependency_overrides[get_transaction_analysis_service] = factory
    return service


@pytest.fixture
def service() -> FakeService:
    return install(FakeService())


@pytest.fixture
def blocking() -> Iterator[BlockingService]:
    fake = BlockingService()
    install(fake)
    yield fake
    fake.gate.set()  # never leave a worker blocked, even when the test fails


@pytest.fixture
def assess_calls(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    calls: list[Any] = []
    real = transactions_module.assess_transaction

    def recording(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(transactions_module, "assess_transaction", recording)
    return calls


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, headers=AUTH)


def post(client: TestClient, path: str = INSPECT, **kwargs: Any) -> Any:
    kwargs.setdefault("json", BODY)
    return client.post(path, **kwargs)


def wait_entered(service: BlockingService, count: int) -> None:
    for _ in range(count):
        assert service.entered.acquire(timeout=WAIT), "an admitted request never started"


def assert_busy(response: Any) -> None:
    assert response.status_code == 503
    assert response.json() == SERVICE_BUSY
    assert response.headers["retry-after"] == "1"


# --- Limiter unit behaviour --------------------------------------------------------------------


def test_capacity_is_8_and_the_limiter_is_shared() -> None:
    first = asyncio.run(get_concurrency_limiter())
    second = asyncio.run(get_concurrency_limiter())

    assert MAX_CONCURRENT_ANALYSES == CAPACITY
    assert first is second
    assert first.max_concurrent == CAPACITY


def test_limiter_admits_8_and_refuses_the_9th_without_waiting() -> None:
    limiter = ConcurrencyLimiter()

    assert [limiter.try_acquire() for _ in range(9)] == [True] * 8 + [False]
    limiter.release()
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False


def test_releasing_more_than_acquired_is_refused() -> None:
    limiter = ConcurrencyLimiter()
    assert limiter.try_acquire()
    limiter.release()

    with pytest.raises(ValueError):
        limiter.release()
    assert free_slots(limiter) == CAPACITY


@pytest.mark.parametrize("capacity", [0, -1])
def test_invalid_capacity_is_refused(capacity: int) -> None:
    with pytest.raises(ValueError):
        ConcurrencyLimiter(capacity)


def test_concurrent_acquisitions_never_exceed_the_capacity() -> None:
    limiter = ConcurrencyLimiter()
    threads = 64
    barrier = threading.Barrier(threads)
    results: list[bool] = []
    results_lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        admitted = limiter.try_acquire()
        with results_lock:
            results.append(admitted)

    workers = [threading.Thread(target=attempt) for _ in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert results.count(True) == CAPACITY
    assert results.count(False) == threads - CAPACITY


# --- Dependency life cycle -----------------------------------------------------------------------


def test_dependency_releases_its_slot_on_exception_and_cancellation() -> None:
    limiter = ConcurrencyLimiter()

    async def scenario(error: BaseException) -> None:
        holder = hold_analysis_slot(limiter)
        await holder.__anext__()
        assert free_slots(limiter) == CAPACITY - 1
        with pytest.raises(type(error)):
            await holder.athrow(error)

    for error in (RuntimeError("boom"), ProviderTimeoutError("x"), asyncio.CancelledError()):
        asyncio.run(scenario(error))
        assert free_slots(limiter) == CAPACITY


def test_dependency_refusal_releases_nothing() -> None:
    limiter = ConcurrencyLimiter()
    occupy(limiter, CAPACITY)

    async def scenario() -> None:
        with pytest.raises(AnalysisCapacityExceededError):
            await hold_analysis_slot(limiter).__anext__()

    asyncio.run(scenario())

    assert free_slots(limiter) == 0  # a release here would have freed a slot it never took
    vacate(limiter, CAPACITY)


def test_slot_is_held_for_the_whole_analysis(
    client: TestClient, blocking: BlockingService, slots: RecordingLimiter
) -> None:
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(post, client)
        wait_entered(blocking, 1)

        assert free_slots(slots) == CAPACITY - 1  # still inside the endpoint
        blocking.gate.set()
        assert pending.result(WAIT).status_code == 200

    assert free_slots(slots) == CAPACITY
    assert (slots.acquired, slots.released) == (1, 1)


# --- Admission and refusal -----------------------------------------------------------------------


def test_8_simultaneous_analyses_are_admitted_and_the_9th_is_refused_at_once(
    client: TestClient, blocking: BlockingService, slots: RecordingLimiter
) -> None:
    with ThreadPoolExecutor(max_workers=CAPACITY + 1) as pool:
        admitted = [pool.submit(post, client, PROTECTED[i % 2]) for i in range(CAPACITY)]
        wait_entered(blocking, CAPACITY)  # 8 analyses in flight, on both routes

        ninth = pool.submit(post, client, ASSESS).result(WAIT)  # answered while 8 are held

        assert_busy(ninth)
        assert not blocking.gate.is_set()
        assert blocking.calls == CAPACITY
        blocking.gate.set()
        assert [future.result(WAIT).status_code for future in admitted] == [200] * CAPACITY

    assert blocking.max_active == CAPACITY
    assert free_slots(slots) == CAPACITY
    assert post(client).status_code == 200  # admitted again once slots are back


def test_slots_are_shared_by_inspect_and_assess(
    client: TestClient, service: FakeService, slots: RecordingLimiter
) -> None:
    occupy(slots, CAPACITY - 1)
    assert free_slots(slots) == 1
    occupy(slots, 1)

    for path in PROTECTED:
        assert_busy(post(client, path))

    vacate(slots, 1)
    for path in PROTECTED:
        assert post(client, path).status_code == 200
    vacate(slots, CAPACITY - 1)
    assert free_slots(slots) == CAPACITY


def test_503_response_is_exact_and_leaks_nothing(
    client: TestClient, service: FakeService, slots: RecordingLimiter
) -> None:
    occupy(slots, CAPACITY)

    response = post(client)

    assert response.status_code == 503
    assert response.content == (
        b'{"error":{"code":"service_busy",'
        b'"message":"Analysis capacity is temporarily exhausted."}}'
    )
    assert response.headers["content-type"] == "application/json"
    assert response.headers["retry-after"] == "1"
    assert "www-authenticate" not in response.headers
    assert TOKEN not in response.text + json.dumps(dict(response.headers))
    assert response.json()["error"]["code"] not in (
        "auth_not_configured", "provider_not_configured", "provider_unavailable"
    )
    vacate(slots, CAPACITY)


def test_refused_requests_never_reach_the_service_or_risk_engine(
    client: TestClient, service: FakeService, slots: RecordingLimiter, assess_calls: list[Any]
) -> None:
    occupy(slots, CAPACITY)

    for path in PROTECTED * 10:
        assert_busy(post(client, path))

    assert (service.calls, service.factory_calls, assess_calls) == (0, 0, [])
    assert (slots.refused, slots.released) == (20, 0)
    vacate(slots, CAPACITY)


def test_refused_requests_never_build_real_providers(
    client: TestClient, slots: RecordingLimiter, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("provider must not be built for a refused request")

    monkeypatch.setattr(EthereumProvider, "from_env", forbidden)
    monkeypatch.setattr(TronProvider, "from_env", forbidden)
    monkeypatch.setenv("CHAINSHIELD_ETHEREUM_RPC_URL", "https://eth.example.invalid/rpc")
    occupy(slots, CAPACITY)

    for path in PROTECTED:
        assert_busy(post(client, path))

    assert get_transaction_analysis_service.cache_info().currsize == 0
    vacate(slots, CAPACITY)


# --- Release in every outcome --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("outcome", "body", "status"),
    [
        (None, BODY, 200),
        (ProviderTimeoutError("upstream timeout"), BODY, 504),
        (ProviderUnavailableError("upstream down"), BODY, 503),
        (RuntimeError("unexpected"), BODY, 500),
        (None, {"network": "bitcoin", "tx_hash": ETH_HASH}, 422),  # validated after admission
    ],
    ids=["success", "provider-timeout", "provider-unavailable", "unexpected-error", "validation"],
)
def test_slot_is_released_whatever_the_outcome(
    slots: RecordingLimiter, outcome: Any, body: dict, status: int
) -> None:
    install(FakeService(outcome))
    client = TestClient(app, headers=AUTH, raise_server_exceptions=False)

    for path in PROTECTED:
        assert client.post(path, json=body).status_code == status

    assert (slots.acquired, slots.released, slots.refused) == (2, 2, 0)
    assert free_slots(slots) == CAPACITY


def test_rate_limited_request_releases_its_slot(
    client: TestClient, service: FakeService, slots: RecordingLimiter
) -> None:
    for _ in range(30):
        assert post(client).status_code == 200

    response = post(client)

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "rate_limited"
    assert (slots.acquired, slots.released) == (31, 31)
    assert free_slots(slots) == CAPACITY


def test_no_slot_leaks_over_many_requests(slots: RecordingLimiter) -> None:
    app.dependency_overrides[get_rate_limiter] = lambda: SlidingWindowRateLimiter(
        max_requests=10_000, clock=FakeClock()
    )
    outcomes = [None, ProviderTimeoutError("x"), RuntimeError("y")]
    client = TestClient(app, headers=AUTH, raise_server_exceptions=False)

    for index in range(150):
        install(FakeService(outcomes[index % 3]))
        client.post(PROTECTED[index % 2], json=BODY if index % 5 else {"tx_hash": "bad"})

    assert slots.acquired == slots.released == 150
    assert free_slots(slots) == CAPACITY


# --- Interaction with the other protections ------------------------------------------------------


def test_overload_refusals_consume_no_rate_limit_quota(
    client: TestClient, service: FakeService, slots: RecordingLimiter
) -> None:
    occupy(slots, CAPACITY)
    for _ in range(50):
        assert_busy(post(client))
    vacate(slots, CAPACITY)

    for _ in range(30):
        assert post(client).status_code == 200
    assert post(client).status_code == 429


def test_rate_limit_429_is_unchanged(
    client: TestClient, service: FakeService
) -> None:
    for _ in range(30):
        post(client)

    response = post(client, ASSESS)

    assert response.status_code == 429
    assert response.json() == {
        "error": {"code": "rate_limited", "message": "Too many requests. Retry later."}
    }
    assert response.headers["retry-after"] == "60"


def test_authentication_is_checked_before_admission(
    client: TestClient, service: FakeService, slots: RecordingLimiter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    occupy(slots, CAPACITY)

    for headers in ({"Authorization": "Bearer wrong"}, {"Authorization": ""}):
        response = TestClient(app).post(INSPECT, json=BODY, headers=headers)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
    monkeypatch.delenv(API_TOKEN_ENV_VAR)
    response = post(client)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "auth_not_configured"

    assert (slots.acquired, slots.refused) == (0, 0)  # the slot dependency never ran
    vacate(slots, CAPACITY)


def test_oversized_body_is_still_413_before_admission(
    client: TestClient, service: FakeService, slots: RecordingLimiter
) -> None:
    occupy(slots, CAPACITY)
    oversized = json.dumps(BODY).encode() + b" " * MAX_BODY_BYTES

    response = client.post(
        INSPECT, content=oversized, headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 413
    assert slots.refused == 0
    vacate(slots, CAPACITY)


def test_malformed_json_is_rejected_before_admission(
    client: TestClient, service: FakeService, slots: RecordingLimiter
) -> None:
    # Known limit: FastAPI decodes JSON before the router dependencies.
    response = client.post(
        INSPECT, content=b"{not json", headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 422
    assert (slots.acquired, slots.refused) == (0, 0)


def test_public_routes_are_unaffected_when_capacity_is_exhausted(
    client: TestClient, slots: RecordingLimiter
) -> None:
    occupy(slots, CAPACITY)

    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert slots.refused == 0
    vacate(slots, CAPACITY)


def test_openapi_documents_the_busy_response(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    for path in PROTECTED:
        responses = spec["paths"][path]["post"]["responses"]
        assert "service_busy" in responses["503"]["description"]
        assert "429" in responses
    assert "503" not in spec["paths"]["/health"]["get"]["responses"]


# --- Real concurrency through the API ------------------------------------------------------------


def test_concurrent_requests_never_exceed_8_analyses_in_flight(
    client: TestClient, blocking: BlockingService, slots: RecordingLimiter
) -> None:
    total = 32
    start = threading.Barrier(total)
    refused_done = threading.Semaphore(0)

    def request(index: int) -> int:
        start.wait(WAIT)
        status = post(client, PROTECTED[index % 2]).status_code
        if status != 200:
            refused_done.release()
        return status

    with ThreadPoolExecutor(max_workers=total) as pool:
        futures = [pool.submit(request, index) for index in range(total)]
        wait_entered(blocking, CAPACITY)
        for _ in range(total - CAPACITY):  # every other request is answered while 8 are held
            assert refused_done.acquire(timeout=WAIT)

        assert blocking.active == CAPACITY
        assert not blocking.gate.is_set()
        blocking.gate.set()
        statuses = [future.result(WAIT) for future in futures]

    assert statuses.count(200) == CAPACITY
    assert statuses.count(503) == total - CAPACITY
    assert blocking.max_active == CAPACITY
    assert blocking.calls == CAPACITY
    assert (slots.acquired, slots.released, slots.refused) == (8, 8, 24)
    assert free_slots(slots) == CAPACITY
