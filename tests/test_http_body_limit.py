import asyncio
import json
import socket
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.body_limit import MAX_BODY_BYTES, BodySizeLimitMiddleware
from app.api.transactions import get_transaction_analysis_service
from app.domain.analysis_input import Network
from app.main import app
from app.providers.base import NativeUnit, NormalizedTransaction, TransactionStatus
from app.services.transaction_analysis import TransactionInspection

LIMIT = 262_144
SECRET = "sk-test-0123456789abcdef"
INSPECT = "/api/v1/transactions/inspect"
ASSESS = "/api/v1/transactions/assess"
ETH_HASH = "0x" + "ab" * 32
ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
EXPECTED_413 = {"error": {"code": "request_too_large", "message": "Request body is too large."}}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    # The asyncio loop uses a loopback socket pair on Windows; nothing else is allowed.
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


class FakeService:
    def __init__(self) -> None:
        self.calls: list[tuple[Network, str]] = []

    def inspect_transaction(self, network: Network, tx_hash: str) -> TransactionInspection:
        self.calls.append((network, tx_hash))
        transaction = NormalizedTransaction(
            network=Network.ETHEREUM, tx_hash=ETH_HASH, status=TransactionStatus.SUCCESS,
            from_address=ALICE, to_address=None, native_value_atomic=0,
            native_unit=NativeUnit.WEI, block_number=1, block_timestamp=1,
        )
        return TransactionInspection(
            network=Network.ETHEREUM, tx_hash=ETH_HASH, transaction=transaction, usdt_transfers=()
        )


@pytest.fixture
def service() -> Iterator[FakeService]:
    fake = FakeService()
    factory_calls: list[int] = []

    def factory() -> FakeService:
        factory_calls.append(1)
        return fake

    fake.factory_calls = factory_calls  # type: ignore[attr-defined]
    get_transaction_analysis_service.cache_clear()
    app.dependency_overrides[get_transaction_analysis_service] = factory
    yield fake
    app.dependency_overrides.clear()
    get_transaction_analysis_service.cache_clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# --- Helpers -------------------------------------------------------------------------


def request_json(path_body: dict[str, Any] | None = None) -> bytes:
    body = path_body or {"kind": "transaction", "network": "ethereum", "tx_hash": ETH_HASH}
    return json.dumps(body).encode()


def padded(body: bytes, total: int) -> bytes:
    """Valid JSON padded with trailing whitespace to exactly ``total`` bytes."""
    assert len(body) <= total
    return body + b" " * (total - len(body))


class Recorder:
    """Inner ASGI app recording exactly what it receives."""

    def __init__(self) -> None:
        self.calls = 0
        self.body: bytes | None = None
        self.extra_message: dict | None = None

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        self.calls += 1
        chunks = []
        while True:
            message = await receive()
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        self.body = b"".join(chunks)
        self.extra_message = await receive()  # must be forwarded to the server
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def run_asgi(
    asgi_app: Any,
    messages: list[dict],
    headers: list[tuple[bytes, bytes]] | None = None,
    path: str = "/x",
    method: str = "POST",
) -> tuple[list[dict], int]:
    """Run one HTTP request through an ASGI app; return sent messages and receive calls."""
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
        "query_string": b"", "root_path": "", "headers": headers or [],
        "client": ("127.0.0.1", 50000), "server": ("testserver", 80),
    }
    queue = list(messages)
    sent: list[dict] = []
    receive_calls = 0

    async def receive() -> dict:
        nonlocal receive_calls
        receive_calls += 1
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        sent.append(message)

    asyncio.run(asgi_app(scope, receive, send))
    return sent, receive_calls


def chunks_of(data: bytes, size: int) -> list[dict]:
    parts = [data[i:i + size] for i in range(0, len(data), size)] or [b""]
    return [
        {"type": "http.request", "body": part, "more_body": index < len(parts) - 1}
        for index, part in enumerate(parts)
    ]


def status_of(sent: list[dict]) -> int:
    starts = [m for m in sent if m["type"] == "http.response.start"]
    assert len(starts) == 1, "exactly one response must be started"
    return starts[0]["status"]


def body_of(sent: list[dict]) -> bytes:
    return b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")


def json_headers(length: int | None = None) -> list[tuple[bytes, bytes]]:
    headers = [(b"content-type", b"application/json")]
    if length is not None:
        headers.append((b"content-length", str(length).encode()))
    return headers


# --- Middleware boundary (direct ASGI) ---------------------------------------------------


def test_limit_constant() -> None:
    assert MAX_BODY_BYTES == LIMIT == 256 * 1024


@pytest.mark.parametrize("size", [0, 1, LIMIT - 1, LIMIT])
def test_body_up_to_the_limit_reaches_the_app_unchanged(size: int) -> None:
    data = bytes(i % 256 for i in range(size))  # binary, not only text
    inner = Recorder()

    sent, _ = run_asgi(BodySizeLimitMiddleware(inner), chunks_of(data, 65_536))

    assert status_of(sent) == 200
    assert inner.calls == 1
    assert inner.body == data  # no byte lost, duplicated or reordered


@pytest.mark.parametrize("size", [LIMIT + 1, LIMIT + 65_536, 4 * LIMIT])
def test_body_over_the_limit_is_rejected_before_the_app(size: int) -> None:
    inner = Recorder()

    sent, _ = run_asgi(BodySizeLimitMiddleware(inner), chunks_of(b"x" * size, 65_536))

    assert status_of(sent) == 413
    assert json.loads(body_of(sent)) == EXPECTED_413
    assert inner.calls == 0


def test_many_small_chunks_are_reassembled_exactly() -> None:
    data = bytes(range(256)) * (LIMIT // 256)
    inner = Recorder()

    sent, _ = run_asgi(BodySizeLimitMiddleware(inner), chunks_of(data, 1_000))

    assert len(data) == LIMIT
    assert status_of(sent) == 200
    assert inner.body == data


def test_overflow_in_the_last_chunk() -> None:
    messages = chunks_of(b"a" * LIMIT, 4_096)
    messages[-1]["more_body"] = True
    messages.append({"type": "http.request", "body": b"!", "more_body": False})
    inner = Recorder()

    sent, _ = run_asgi(BodySizeLimitMiddleware(inner), messages)

    assert status_of(sent) == 413
    assert inner.calls == 0


def test_empty_chunks_do_not_count() -> None:
    messages = [{"type": "http.request", "body": b"", "more_body": True}] * 50 + [
        {"type": "http.request", "body": b"{}", "more_body": False}
    ]
    inner = Recorder()

    sent, _ = run_asgi(BodySizeLimitMiddleware(inner), messages)

    assert status_of(sent) == 200
    assert inner.body == b"{}"


def test_missing_content_length_is_counted_from_actual_bytes() -> None:
    inner = Recorder()
    over = chunks_of(b"z" * (LIMIT + 1), 8_192)

    sent, _ = run_asgi(BodySizeLimitMiddleware(inner), over, headers=[])

    assert status_of(sent) == 413
    assert inner.calls == 0


@pytest.mark.parametrize("declared", [b"10", b"0", b"262144", b"abc", b"-5", b" 12 "])
def test_misleading_content_length_cannot_bypass_the_limit(declared: bytes) -> None:
    inner = Recorder()

    sent, _ = run_asgi(
        BodySizeLimitMiddleware(inner),
        chunks_of(b"y" * (LIMIT + 1), 65_536),
        headers=[(b"content-length", declared)],
    )

    assert status_of(sent) == 413
    assert inner.calls == 0


def test_small_body_with_wrong_content_length_is_passed_unchanged() -> None:
    inner = Recorder()

    sent, _ = run_asgi(
        BodySizeLimitMiddleware(inner),
        chunks_of(b"hello", 2),
        headers=[(b"content-length", b"99999")],
    )

    assert status_of(sent) == 200
    assert inner.body == b"hello"  # never truncated or padded to the declared length


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", str(LIMIT + 1).encode())],
        [(b"Content-Length", b"999999999")],
        [(b"content-length", b"10"), (b"content-length", str(LIMIT + 1).encode())],
        [(b"content-length", b"9" * 5_000)],  # beyond int()'s 4300-digit limit
    ],
)
def test_declared_oversize_is_rejected_without_reading_the_body(headers: list) -> None:
    inner = Recorder()

    sent, receive_calls = run_asgi(BodySizeLimitMiddleware(inner), chunks_of(b"{}", 2), headers)

    assert status_of(sent) == 413
    assert receive_calls == 0
    assert inner.calls == 0


def test_utf8_bytes_are_counted_not_characters() -> None:
    inner = Recorder()
    fits = ("é" * (LIMIT // 2)).encode("utf-8")  # 131072 characters, 262144 bytes
    over = ("é" * (LIMIT // 2 + 1)).encode("utf-8")  # 131073 characters, 262146 bytes

    accepted, _ = run_asgi(BodySizeLimitMiddleware(inner), chunks_of(fits, 4_097))
    rejected, _ = run_asgi(BodySizeLimitMiddleware(Recorder()), chunks_of(over, 4_097))

    assert len(fits) == LIMIT and len(over) == LIMIT + 2
    assert status_of(accepted) == 200 and inner.body == fits  # split mid-character, rejoined
    assert status_of(rejected) == 413


def test_client_disconnect_before_the_end_calls_nothing_and_sends_nothing() -> None:
    inner = Recorder()
    messages = [
        {"type": "http.request", "body": b"x" * 1_000, "more_body": True},
        {"type": "http.disconnect"},
    ]

    sent, _ = run_asgi(BodySizeLimitMiddleware(inner), messages)

    assert sent == []
    assert inner.calls == 0


def test_later_receive_calls_are_forwarded_to_the_server() -> None:
    inner = Recorder()

    run_asgi(BodySizeLimitMiddleware(inner), chunks_of(b"{}", 1))

    assert inner.extra_message == {"type": "http.disconnect"}


def test_413_response_is_exact_and_sent_once() -> None:
    sent, _ = run_asgi(
        BodySizeLimitMiddleware(Recorder()), chunks_of(SECRET.encode() * 20_000, 65_536)
    )

    assert [m["type"] for m in sent] == ["http.response.start", "http.response.body"]
    start, body = sent
    headers = dict(start["headers"])
    assert start["status"] == 413
    assert headers[b"content-type"] == b"application/json"
    assert headers[b"content-length"] == str(len(body["body"])).encode()
    assert json.loads(body["body"]) == EXPECTED_413
    assert body["body"] == (
        b'{"error":{"code":"request_too_large","message":"Request body is too large."}}'
    )
    assert SECRET.encode() not in body["body"]
    assert not body.get("more_body", False)


def test_non_http_scopes_are_passed_through() -> None:
    calls = []

    async def inner(scope: dict, receive: Any, send: Any) -> None:
        calls.append(scope["type"])

    middleware = BodySizeLimitMiddleware(inner)
    asyncio.run(middleware({"type": "lifespan"}, None, None))  # type: ignore[arg-type]

    assert calls == ["lifespan"]


# --- Full application (direct ASGI, streamed bodies) ---------------------------------------


def test_streamed_oversized_body_never_reaches_routes_or_services(service: FakeService) -> None:
    for path in (INSPECT, ASSESS):
        sent, _ = run_asgi(
            app, chunks_of(b"{" + b" " * LIMIT + b"}", 16_384), json_headers(), path=path
        )

        assert status_of(sent) == 413
        assert json.loads(body_of(sent)) == EXPECTED_413
    assert service.calls == []
    assert service.factory_calls == []  # the FastAPI dependency never ran


def test_streamed_body_at_the_limit_is_processed_normally(service: FakeService) -> None:
    body = padded(request_json(), LIMIT)

    sent, _ = run_asgi(app, chunks_of(body, 7_000), json_headers(), path=INSPECT)

    assert status_of(sent) == 200
    assert json.loads(body_of(sent))["tx_hash"] == ETH_HASH
    assert service.calls == [(Network.ETHEREUM, ETH_HASH)]


def test_huge_content_length_is_413_not_500_on_the_real_app(service: FakeService) -> None:
    headers = json_headers() + [(b"content-length", b"9" * 5_000)]

    sent, _ = run_asgi(app, chunks_of(request_json(), 1_000), headers, path=INSPECT)

    assert status_of(sent) == 413
    assert json.loads(body_of(sent)) == EXPECTED_413
    assert service.calls == []


def test_lying_content_length_on_the_real_app(service: FakeService) -> None:
    body = padded(request_json(), LIMIT + 1)

    sent, _ = run_asgi(app, chunks_of(body, 50_000), json_headers(length=20), path=ASSESS)

    assert status_of(sent) == 413
    assert service.calls == []


# --- Full application (TestClient) -----------------------------------------------------------


def test_exact_limit_is_accepted(client: TestClient, service: FakeService) -> None:
    body = padded(request_json(), LIMIT)

    response = client.post(INSPECT, content=body, headers={"Content-Type": "application/json"})

    assert len(body) == LIMIT
    assert response.status_code == 200


def test_one_byte_over_is_rejected(client: TestClient, service: FakeService) -> None:
    body = padded(request_json(), LIMIT + 1)

    response = client.post(ASSESS, content=body, headers={"Content-Type": "application/json"})

    assert response.status_code == 413
    assert response.json() == EXPECTED_413
    assert response.headers["content-type"] == "application/json"
    assert service.calls == []


def test_much_larger_body_is_rejected(client: TestClient, service: FakeService) -> None:
    body = json.dumps({"tx_hash": ETH_HASH, "padding": SECRET * 200_000}).encode()

    response = client.post(INSPECT, content=body, headers={"Content-Type": "application/json"})

    assert len(body) > 4_000_000
    assert response.status_code == 413
    assert SECRET not in response.text
    assert service.calls == []


def test_valid_json_under_the_limit_is_unchanged(client: TestClient, service: FakeService) -> None:
    response = client.post(INSPECT, json={"network": "ethereum", "tx_hash": ETH_HASH})

    assert response.status_code == 200
    assert response.json()["transaction"]["status"] == "success"


@pytest.mark.parametrize("body", [b"{not json", b"", b"[1, 2]"], ids=["invalid", "empty", "array"])
def test_invalid_or_empty_json_under_the_limit_keeps_422(
    client: TestClient, service: FakeService, body: bytes
) -> None:
    response = client.post(INSPECT, content=body, headers={"Content-Type": "application/json"})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


def test_invalid_json_over_the_limit_is_413_not_422(
    client: TestClient, service: FakeService
) -> None:
    response = client.post(
        INSPECT, content=b"{not json" + b"!" * LIMIT, headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 413


def test_assess_is_unchanged_under_the_limit(client: TestClient, service: FakeService) -> None:
    report = {
        "network": "ethereum", "address": ALICE, "source_id": "fictional-source",
        "report_id": "F-1", "source_type": "community_report",
        "claim_category": "scam_allegation", "reported_at": "2026-05-01T12:00:00+00:00",
    }

    response = client.post(
        ASSESS, json={"network": "ethereum", "tx_hash": ETH_HASH, "reports": [report]}
    )

    assert response.status_code == 200
    assert response.json()["assessment"]["risk_determination"] == "indeterminate"
    assert response.json()["assessment"]["manual_review_recommended"] is True


def test_other_error_codes_are_preserved(client: TestClient) -> None:
    get_transaction_analysis_service.cache_clear()
    app.dependency_overrides.clear()

    response = client.post(INSPECT, json={"network": "ethereum", "tx_hash": ETH_HASH})

    assert response.status_code == 503  # no provider configured
    assert response.json()["error"]["code"] == "provider_not_configured"
    get_transaction_analysis_service.cache_clear()


def test_health_and_docs_are_unchanged(client: TestClient) -> None:
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/docs").status_code == 200


def test_openapi_documents_413_on_both_post_routes(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]

    for path in (INSPECT, ASSESS):
        responses = paths[path]["post"]["responses"]
        assert "413" in responses
        assert {"200", "422", "502", "503", "504"} <= set(responses)
