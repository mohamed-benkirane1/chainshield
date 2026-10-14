"""API tests for the shared in-memory rate limit of the analysis endpoints.

Time is a controlled fake clock: no test sleeps through a real window. Every
token below is a FICTIONAL test value, never a real credential.
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

import app.api.transactions as transactions_module
from app.api.auth import API_TOKEN_ENV_VAR
from app.api.body_limit import MAX_BODY_BYTES
from app.api.rate_limit import (
    MAX_REQUESTS,
    WINDOW_SECONDS,
    RateLimitExceededError,
    SlidingWindowRateLimiter,
    get_rate_limiter,
)
from app.api.transactions import get_transaction_analysis_service
from app.domain.analysis_input import Network
from app.main import app
from app.providers.base import (
    NativeUnit,
    NormalizedTransaction,
    ProviderTimeoutError,
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
RATE_LIMITED = {"error": {"code": "rate_limited", "message": "Too many requests. Retry later."}}
ENV_VARS = (
    "CHAINSHIELD_ETHEREUM_RPC_URL",
    "CHAINSHIELD_TRON_RPC_URL",
    "CHAINSHIELD_TRON_API_KEY",
)


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


class FakeClock:
    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture(autouse=True)
def limiter(_isolated: None, clock: FakeClock) -> SlidingWindowRateLimiter:
    # A real limiter with the production quota, driven by the fake clock.
    fresh = SlidingWindowRateLimiter(clock=clock)
    app.dependency_overrides[get_rate_limiter] = lambda: fresh
    return fresh


class FakeService:
    def __init__(self, outcome: Any = None) -> None:
        self.outcome = outcome
        self.calls: list[tuple[Network, str]] = []
        self.factory_calls = 0

    def inspect_transaction(self, network: Network, tx_hash: str) -> TransactionInspection:
        self.calls.append((network, tx_hash))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        transaction = NormalizedTransaction(
            network=Network.ETHEREUM, tx_hash=ETH_HASH, status=TransactionStatus.SUCCESS,
            from_address=ALICE, to_address=None, native_value_atomic=0,
            native_unit=NativeUnit.WEI, block_number=1, block_timestamp=1,
        )
        return TransactionInspection(
            network=Network.ETHEREUM, tx_hash=ETH_HASH, transaction=transaction, usdt_transfers=()
        )


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


def admit(client: TestClient, count: int, path: str = INSPECT) -> None:
    for _ in range(count):
        assert post(client, path).status_code == 200


def assert_rate_limited(response: Any, retry_after: int | None = None) -> int:
    assert response.status_code == 429
    assert response.json() == RATE_LIMITED
    value = response.headers["retry-after"]
    assert value.isdigit() and int(value) >= 1
    if retry_after is not None:
        assert int(value) == retry_after
    return int(value)


# --- Quota -----------------------------------------------------------------------------------


def test_production_quota_is_30_per_60_seconds() -> None:
    default = get_rate_limiter()

    assert (MAX_REQUESTS, WINDOW_SECONDS) == (30, 60.0)
    assert (default.max_requests, default.window_seconds) == (30, 60.0)
    assert get_rate_limiter() is default  # one shared instance, never rebuilt


def test_30_requests_are_admitted_and_the_31st_is_rejected(
    client: TestClient, service: FakeService
) -> None:
    admit(client, 30)

    assert_rate_limited(post(client), retry_after=60)
    assert len(service.calls) == 30


def test_429_response_is_exact_and_leaks_nothing(client: TestClient, service: FakeService) -> None:
    admit(client, 30)

    response = post(client, ASSESS)

    assert response.status_code == 429
    assert response.content == (
        b'{"error":{"code":"rate_limited","message":"Too many requests. Retry later."}}'
    )
    assert response.headers["content-type"] == "application/json"
    assert response.headers["retry-after"] == "60"
    assert "www-authenticate" not in response.headers
    raw = response.text + json.dumps(dict(response.headers))
    assert TOKEN not in raw
    assert "1000" not in raw  # no internal timestamp


@pytest.mark.parametrize(
    ("elapsed", "expected"),
    [(0.0, 60), (0.4, 60), (10.5, 50), (59.0, 1), (59.999, 1)],
)
def test_retry_after_is_rounded_up_from_the_oldest_admission(
    client: TestClient, service: FakeService, clock: FakeClock, elapsed: float, expected: int
) -> None:
    admit(client, 30)
    clock.advance(elapsed)

    assert_rate_limited(post(client), retry_after=expected)


def test_window_boundary_is_exactly_60_seconds(
    client: TestClient, service: FakeService, clock: FakeClock
) -> None:
    admit(client, 1)  # t = 0
    clock.advance(10)
    admit(client, 29)  # t = 10

    clock.advance(49.999)  # t = 59.999: the first admission is still in the window
    assert_rate_limited(post(client), retry_after=1)
    clock.advance(0.001)  # t = 60: it leaves the window, exactly one slot frees
    assert post(client).status_code == 200
    assert_rate_limited(post(client), retry_after=10)


def test_window_slides_instead_of_resetting(
    client: TestClient, service: FakeService, clock: FakeClock
) -> None:
    admit(client, 15)  # t = 0
    clock.advance(30)
    admit(client, 15)  # t = 30

    clock.advance(29)  # t = 59
    assert_rate_limited(post(client), retry_after=1)
    clock.advance(1)  # t = 60: only the first 15 expire
    admit(client, 15)
    assert_rate_limited(post(client), retry_after=30)


def test_quota_is_available_again_after_a_full_window(
    client: TestClient, service: FakeService, clock: FakeClock
) -> None:
    admit(client, 30)
    assert_rate_limited(post(client))

    clock.advance(60)

    admit(client, 30)
    assert_rate_limited(post(client), retry_after=60)


def test_rejected_requests_do_not_extend_the_blocking(
    client: TestClient, service: FakeService, clock: FakeClock
) -> None:
    admit(client, 30)  # t = 0
    for second in range(1, 60):
        clock.advance(1)
        assert_rate_limited(post(client), retry_after=60 - second)

    clock.advance(1)  # t = 60

    admit(client, 30)
    assert len(service.calls) == 60


# --- Shared quota ----------------------------------------------------------------------------


def test_quota_is_shared_by_inspect_and_assess(client: TestClient, service: FakeService) -> None:
    admit(client, 15, INSPECT)
    admit(client, 15, ASSESS)

    for path in PROTECTED:
        assert_rate_limited(post(client, path))


def test_alternating_routes_cannot_bypass_the_limit(
    client: TestClient, service: FakeService
) -> None:
    statuses = [post(client, PROTECTED[i % 2]).status_code for i in range(40)]

    assert statuses == [200] * 30 + [429] * 10


def test_proxy_and_client_headers_do_not_create_separate_quotas(
    client: TestClient, service: FakeService
) -> None:
    admit(client, 30)

    for headers in (
        {"X-Forwarded-For": "203.0.113.7"},
        {"Forwarded": "for=198.51.100.9"},
        {"X-Real-IP": "192.0.2.1"},
        {"User-Agent": "another-client"},
    ):
        assert_rate_limited(post(client, headers=headers))


# --- Requests rejected before the limiter -------------------------------------------------------


def test_authentication_failures_consume_no_quota(
    client: TestClient, service: FakeService
) -> None:
    for _ in range(50):
        assert post(client, headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert TestClient(app).post(INSPECT, json=BODY).status_code == 401

    admit(client, 30)
    assert_rate_limited(post(client))


def test_authentication_is_checked_before_the_quota(
    client: TestClient, service: FakeService
) -> None:
    admit(client, 30)

    response = TestClient(app).post(INSPECT, json=BODY)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert "retry-after" not in response.headers


def test_auth_not_configured_is_still_503_and_consumes_no_quota(
    client: TestClient, service: FakeService, monkeypatch: pytest.MonkeyPatch
) -> None:
    admit(client, 30)
    monkeypatch.delenv(API_TOKEN_ENV_VAR)

    for _ in range(5):
        response = post(client)
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "auth_not_configured"


def test_oversized_bodies_consume_no_quota(client: TestClient, service: FakeService) -> None:
    oversized = json.dumps(BODY).encode() + b" " * MAX_BODY_BYTES
    headers = {**AUTH, "Content-Type": "application/json"}

    for _ in range(40):
        assert client.post(ASSESS, content=oversized, headers=headers).status_code == 413

    admit(client, 30)
    assert_rate_limited(post(client))
    assert client.post(INSPECT, content=oversized, headers=headers).status_code == 413


def test_malformed_json_is_rejected_before_the_limiter(
    client: TestClient, service: FakeService
) -> None:
    # Documented limit: FastAPI decodes JSON before the router dependencies, so
    # syntactically invalid JSON is a 422 that neither uses nor checks the quota.
    malformed = {"content": b"{not json", "headers": {"Content-Type": "application/json"}}
    for _ in range(40):
        assert client.post(INSPECT, **malformed).status_code == 422

    admit(client, 30)
    assert client.post(INSPECT, **malformed).status_code == 422
    assert_rate_limited(post(client))


# --- Admitted requests -----------------------------------------------------------------------


def test_admitted_requests_count_even_when_the_provider_fails(client: TestClient) -> None:
    install(FakeService(ProviderTimeoutError("upstream timeout")))

    for _ in range(30):
        response = post(client)
        assert response.status_code == 504
        assert response.json()["error"]["code"] == "provider_timeout"

    assert_rate_limited(post(client))


def test_schema_invalid_bodies_are_admitted_then_rejected_422(
    client: TestClient, service: FakeService
) -> None:
    # Valid JSON is validated after the dependencies: it uses quota, and the
    # (cached, network-free) service dependency is resolved but never called.
    for _ in range(30):
        assert post(client, json={"network": "bitcoin", "tx_hash": ETH_HASH}).status_code == 422

    assert_rate_limited(post(client))
    assert service.calls == []


def test_rejected_requests_never_reach_the_service_or_risk_engine(
    client: TestClient, service: FakeService, assess_calls: list[Any]
) -> None:
    admit(client, 30, ASSESS)
    assert (len(service.calls), service.factory_calls, len(assess_calls)) == (30, 30, 30)

    for path in PROTECTED * 10:
        assert_rate_limited(post(client, path))

    assert (len(service.calls), service.factory_calls, len(assess_calls)) == (30, 30, 30)


def test_rejected_requests_never_build_real_providers(
    client: TestClient, service: FakeService, monkeypatch: pytest.MonkeyPatch
) -> None:
    admit(client, 30)
    del app.dependency_overrides[get_transaction_analysis_service]  # real dependency again

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("provider must not be built after a 429")

    monkeypatch.setattr(EthereumProvider, "from_env", forbidden)
    monkeypatch.setattr(TronProvider, "from_env", forbidden)
    monkeypatch.setenv("CHAINSHIELD_ETHEREUM_RPC_URL", "https://eth.example.invalid/rpc")
    monkeypatch.setenv("CHAINSHIELD_TRON_RPC_URL", "https://tron.example.invalid/rpc")

    for path in PROTECTED:
        assert_rate_limited(post(client, path))
    assert get_transaction_analysis_service.cache_info().currsize == 0


def test_business_responses_are_unchanged_under_the_quota(
    client: TestClient, service: FakeService
) -> None:
    inspect = post(client, INSPECT)
    assess = post(client, ASSESS, json={**BODY, "reports": []})

    assert inspect.status_code == assess.status_code == 200
    assert inspect.json()["tx_hash"] == ETH_HASH
    assert assess.json()["assessment"]["risk_determination"] == "indeterminate"
    assert "retry-after" not in inspect.headers


# --- Public routes and OpenAPI -----------------------------------------------------------------


def test_public_routes_are_not_limited(client: TestClient, service: FakeService) -> None:
    admit(client, 30)

    for _ in range(40):
        assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert_rate_limited(post(client))


def test_openapi_documents_429_on_protected_routes_only(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    for path in PROTECTED:
        responses = spec["paths"][path]["post"]["responses"]
        assert "429" in responses
        assert {"401", "413", "422", "503"} <= set(responses)
    assert "429" not in spec["paths"]["/health"]["get"]["responses"]


# --- Limiter unit behaviour --------------------------------------------------------------------


def test_limiter_memory_is_bounded(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(max_requests=3, window_seconds=10, clock=clock)

    for _ in range(1_000):
        try:
            limiter.acquire()
        except RateLimitExceededError:
            pass
        clock.advance(0.001)

    assert len(limiter._admissions) <= 3
    assert limiter._admissions.maxlen == 3


def test_expired_admissions_are_discarded(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=10, clock=clock)
    for _ in range(5):
        limiter.acquire()
        clock.advance(1)

    clock.advance(100)
    limiter.acquire()

    assert len(limiter._admissions) == 1


def test_reset_restores_the_full_quota(clock: FakeClock) -> None:
    limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=60, clock=clock)
    limiter.acquire()
    limiter.acquire()
    with pytest.raises(RateLimitExceededError):
        limiter.acquire()

    limiter.reset()

    limiter.acquire()
    limiter.acquire()


@pytest.mark.parametrize(("max_requests", "window"), [(0, 60), (-1, 60), (30, 0), (30, -1)])
def test_invalid_limiter_configuration_is_refused(max_requests: int, window: float) -> None:
    with pytest.raises(ValueError):
        SlidingWindowRateLimiter(max_requests=max_requests, window_seconds=window)


def test_default_clock_is_monotonic() -> None:
    limiter = SlidingWindowRateLimiter()

    assert limiter._clock is time.monotonic


# --- Concurrency -------------------------------------------------------------------------------


def test_concurrent_admission_never_exceeds_the_quota() -> None:
    class SlowLenDeque(deque):
        # Widens the window between the quota check and the recording, so that
        # a non-atomic admission would let concurrent threads exceed the quota.
        def __len__(self) -> int:
            length = super().__len__()
            time.sleep(0.0005)  # the length is stale by the time it is used
            return length

    limiter = SlidingWindowRateLimiter(clock=FakeClock())
    limiter._admissions = SlowLenDeque(maxlen=limiter.max_requests)
    threads = 64
    barrier = threading.Barrier(threads)
    outcomes: list[bool] = []
    outcomes_lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        try:
            limiter.acquire()
            admitted = True
        except RateLimitExceededError:
            admitted = False
        with outcomes_lock:
            outcomes.append(admitted)

    workers = [threading.Thread(target=attempt) for _ in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert outcomes.count(True) == 30
    assert outcomes.count(False) == threads - 30
    assert len(limiter._admissions) == 30


def test_concurrent_api_requests_admit_exactly_the_quota(
    client: TestClient, service: FakeService
) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(lambda i: post(client, PROTECTED[i % 2]).status_code, range(48)))

    assert statuses.count(200) == 30
    assert statuses.count(429) == 18
    assert len(service.calls) == 30
