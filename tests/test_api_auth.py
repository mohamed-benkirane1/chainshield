"""API tests for bearer-token authentication of the analysis endpoints.

Every token below is a FICTIONAL test value, never a real credential.
"""

import json
import socket
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

import app.api.transactions as transactions_module
from app.api.auth import API_TOKEN_ENV_VAR, MIN_TOKEN_LENGTH, configured_api_token
from app.api.body_limit import MAX_BODY_BYTES
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
OTHER_TOKEN = "fictional-other-token-not-a-secret-9876543210"
ETH_HASH = "0x" + "ab" * 32
ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
BODY = {"network": "ethereum", "tx_hash": ETH_HASH}
UNAUTHORIZED = {"error": {"code": "unauthorized", "message": "Authentication required."}}
NOT_CONFIGURED = {
    "error": {"code": "auth_not_configured", "message": "API authentication is not configured."}
}
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


@pytest.fixture
def service() -> FakeService:
    fake = FakeService()

    def factory() -> FakeService:
        fake.factory_calls += 1
        return fake

    app.dependency_overrides[get_transaction_analysis_service] = factory
    return fake


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
    return TestClient(app)  # no default Authorization header


def bearer(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def assert_unauthorized(response: Any) -> None:
    assert response.status_code == 401
    assert response.json() == UNAUTHORIZED
    assert response.headers["www-authenticate"] == "Bearer"


def assert_not_configured(response: Any) -> None:
    assert response.status_code == 503
    assert response.json() == NOT_CONFIGURED
    assert "www-authenticate" not in response.headers


# --- Valid token -----------------------------------------------------------------------------


def test_valid_token_on_inspect(client: TestClient, service: FakeService) -> None:
    response = client.post(INSPECT, json=BODY, headers=bearer())

    assert response.status_code == 200
    assert response.json()["tx_hash"] == ETH_HASH
    assert service.calls == [(Network.ETHEREUM, ETH_HASH)]


def test_valid_token_on_assess(
    client: TestClient, service: FakeService, assess_calls: list[Any]
) -> None:
    response = client.post(ASSESS, json={**BODY, "reports": []}, headers=bearer())

    assert response.status_code == 200
    assert response.json()["assessment"]["risk_determination"] == "indeterminate"
    assert service.calls == [(Network.ETHEREUM, ETH_HASH)]
    assert len(assess_calls) == 1


def test_scheme_name_is_case_insensitive(client: TestClient, service: FakeService) -> None:
    # RFC 7235: the auth-scheme is case-insensitive; the token itself is not.
    response = client.post(INSPECT, json=BODY, headers={"Authorization": f"bearer {TOKEN}"})

    assert response.status_code == 200


# --- Invalid credentials ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {},
        bearer(OTHER_TOKEN),
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer"},
        {"Authorization": ""},
        {"Authorization": f"Basic {TOKEN}"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": f"Token {TOKEN}"},
        {"Authorization": TOKEN},
        {"Authorization": f"Bearer{TOKEN}"},
        {"Authorization": f"Bearer {TOKEN} extra"},
        {"Authorization": f"Bearer {TOKEN}, Bearer {TOKEN}"},
        {"X-Api-Token": TOKEN},
    ],
    ids=[
        "absent", "wrong", "empty", "scheme-only", "empty-header", "basic-with-token",
        "basic", "other-scheme", "no-scheme", "no-separator", "trailing-data", "comma-list",
        "other-header",
    ],
)
def test_missing_or_invalid_credentials_are_401(
    client: TestClient, service: FakeService, assess_calls: list[Any], headers: dict
) -> None:
    for path in PROTECTED:
        assert_unauthorized(client.post(path, json=BODY, headers=headers))
    assert service.calls == []
    assert service.factory_calls == 0
    assert assess_calls == []


@pytest.mark.parametrize(
    "presented",
    [
        TOKEN[:-1],
        TOKEN + "x",
        TOKEN.upper(),
        " " + TOKEN,
        TOKEN[:MIN_TOKEN_LENGTH],
        "x" + TOKEN[1:],
    ],
    ids=["prefix", "suffix", "case", "leading-space", "truncated", "first-char"],
)
def test_comparison_is_exact(client: TestClient, service: FakeService, presented: str) -> None:
    # " " + TOKEN gives "Bearer  <token>": HTTPBearer would strip it, the check must not.
    assert_unauthorized(client.post(INSPECT, json=BODY, headers=bearer(presented)))
    assert service.calls == []


def test_non_ascii_token_is_401_not_500(client: TestClient, service: FakeService) -> None:
    response = client.post(
        INSPECT, json=BODY, headers=[(b"authorization", b"Bearer " + b"\xe9" * 40)]
    )

    assert_unauthorized(response)


@pytest.mark.parametrize("values", [[TOKEN, TOKEN], [TOKEN, OTHER_TOKEN], [OTHER_TOKEN, TOKEN]])
def test_duplicate_authorization_headers_are_401(
    client: TestClient, service: FakeService, values: list[str]
) -> None:
    headers = [("Authorization", f"Bearer {value}") for value in values]

    response = client.post(INSPECT, json=BODY, headers=headers)

    assert_unauthorized(response)
    assert service.calls == []


def test_missing_and_wrong_token_are_indistinguishable(
    client: TestClient, service: FakeService
) -> None:
    missing = client.post(INSPECT, json=BODY)
    wrong = client.post(INSPECT, json=BODY, headers=bearer(OTHER_TOKEN))

    assert missing.status_code == wrong.status_code == 401
    assert missing.content == wrong.content
    assert missing.headers["www-authenticate"] == wrong.headers["www-authenticate"]


# --- Server configuration --------------------------------------------------------------------


@pytest.mark.parametrize(
    "configured",
    [
        None,
        "",
        "x" * (MIN_TOKEN_LENGTH - 1),
        " " * 40,
        TOKEN + " ",
        " " + TOKEN,
        TOKEN[:20] + " " + TOKEN[20:],
        TOKEN[:20] + "\t" + TOKEN[20:],
        TOKEN + "\x7f",
        TOKEN + "é",
    ],
    ids=[
        "absent", "empty", "too-short", "spaces-only", "trailing-space", "leading-space",
        "inner-space", "tab", "control-char", "non-ascii",
    ],
)
def test_missing_or_invalid_server_token_fails_closed_with_503(
    client: TestClient,
    service: FakeService,
    assess_calls: list[Any],
    monkeypatch: pytest.MonkeyPatch,
    configured: str | None,
) -> None:
    if configured is None:
        monkeypatch.delenv(API_TOKEN_ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(API_TOKEN_ENV_VAR, configured)

    same_as_configured = [(b"authorization", b"Bearer " + (configured or "").strip().encode())]
    for path in PROTECTED:
        for headers in ({}, bearer(), same_as_configured):
            response = client.post(path, json=BODY, headers=headers)
            assert_not_configured(response)
            if configured and configured.strip():
                assert configured.strip() not in response.text
    assert service.calls == []
    assert service.factory_calls == 0
    assert assess_calls == []


def test_minimum_length_token_is_accepted(
    client: TestClient, service: FakeService, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "A1-_.~!" + "z" * (MIN_TOKEN_LENGTH - 7)
    monkeypatch.setenv(API_TOKEN_ENV_VAR, token)

    assert len(token) == MIN_TOKEN_LENGTH
    assert client.post(INSPECT, json=BODY, headers=bearer(token)).status_code == 200
    assert_unauthorized(client.post(INSPECT, json=BODY, headers=bearer(TOKEN)))


def test_configured_token_is_read_without_normalization() -> None:
    assert configured_api_token({API_TOKEN_ENV_VAR: TOKEN}) == TOKEN
    with pytest.raises(Exception) as caught:
        configured_api_token({API_TOKEN_ENV_VAR: TOKEN + " "})
    assert TOKEN not in str(caught.value) and TOKEN not in repr(caught.value)


def test_no_token_is_defined_in_the_code() -> None:
    with pytest.raises(Exception):
        configured_api_token({})


# --- No leak ---------------------------------------------------------------------------------


def test_responses_never_echo_the_configured_or_presented_token(
    client: TestClient, service: FakeService
) -> None:
    responses = [
        client.post(INSPECT, json=BODY),
        client.post(INSPECT, json=BODY, headers=bearer(OTHER_TOKEN)),
        client.post(ASSESS, json=BODY, headers=bearer(TOKEN + "x")),
        client.post(INSPECT, json={"tx_hash": TOKEN}, headers=bearer()),  # 422 path
    ]

    for response in responses:
        raw = response.text + json.dumps(dict(response.headers))
        assert TOKEN not in raw
        assert OTHER_TOKEN not in raw


# --- Order of execution ----------------------------------------------------------------------


def test_real_service_is_never_built_without_authentication(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("provider must not be built without authentication")

    monkeypatch.setattr(EthereumProvider, "from_env", forbidden)
    monkeypatch.setattr(TronProvider, "from_env", forbidden)
    monkeypatch.setenv("CHAINSHIELD_ETHEREUM_RPC_URL", "https://eth.example.invalid/rpc")
    monkeypatch.setenv("CHAINSHIELD_TRON_RPC_URL", "https://tron.example.invalid/rpc")

    for path in PROTECTED:
        assert_unauthorized(client.post(path, json=BODY, headers=bearer(OTHER_TOKEN)))
    assert get_transaction_analysis_service.cache_info().currsize == 0


def test_authentication_runs_before_body_validation(
    client: TestClient, service: FakeService
) -> None:
    # Valid JSON that fails the schema: the router dependency fails first.
    for body in ({"network": "bitcoin"}, {}, [1, 2]):
        assert_unauthorized(client.post(INSPECT, json=body))
    assert service.factory_calls == 0


def test_malformed_json_is_rejected_by_fastapi_before_any_dependency(
    client: TestClient, service: FakeService, assess_calls: list[Any]
) -> None:
    # Documented limit: FastAPI decodes JSON before solving dependencies, so
    # syntactically invalid JSON is a 422 even without a token. Nothing runs.
    response = client.post(
        ASSESS, content=b"{not json", headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"
    assert service.factory_calls == 0
    assert assess_calls == []


@pytest.mark.parametrize("headers", [{}, bearer()], ids=["no-token", "valid-token"])
def test_oversized_body_is_still_413_before_authentication(
    client: TestClient, service: FakeService, headers: dict
) -> None:
    body = json.dumps(BODY).encode() + b" " * MAX_BODY_BYTES

    for path in PROTECTED:
        response = client.post(
            path, content=body, headers={**headers, "Content-Type": "application/json"}
        )
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "request_too_large"
        assert "www-authenticate" not in response.headers
    assert service.factory_calls == 0


# --- Existing behaviour with valid authentication --------------------------------------------


def test_business_errors_are_unchanged_when_authenticated(client: TestClient) -> None:
    fake = FakeService(ProviderTimeoutError("upstream timeout"))
    app.dependency_overrides[get_transaction_analysis_service] = lambda: fake

    response = client.post(ASSESS, json=BODY, headers=bearer())

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "provider_timeout"
    assert "www-authenticate" not in response.headers


def test_provider_not_configured_is_distinct_from_auth_not_configured(
    client: TestClient,
) -> None:
    response = client.post(INSPECT, json=BODY, headers=bearer())

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "provider_not_configured"


def test_validation_errors_are_unchanged_when_authenticated(
    client: TestClient, service: FakeService
) -> None:
    response = client.post(INSPECT, json={"network": "bitcoin", "tx_hash": ETH_HASH},
                           headers=bearer())

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


# --- Public routes and OpenAPI ---------------------------------------------------------------


@pytest.mark.parametrize("configured", [True, False], ids=["configured", "not-configured"])
def test_public_routes_need_no_token(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, configured: bool
) -> None:
    if not configured:
        monkeypatch.delenv(API_TOKEN_ENV_VAR, raising=False)

    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_openapi_declares_bearer_security_on_protected_routes_only(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    schemes = spec["components"]["securitySchemes"]
    assert list(schemes) == ["HTTPBearer"]
    assert schemes["HTTPBearer"]["type"] == "http"
    assert schemes["HTTPBearer"]["scheme"] == "bearer"
    for path in PROTECTED:
        operation = spec["paths"][path]["post"]
        assert operation["security"] == [{"HTTPBearer": []}]
        assert {"401", "413", "503"} <= set(operation["responses"])
    assert "security" not in spec["paths"]["/health"]["get"]
    assert "security" not in spec


def test_openapi_contains_no_secret(client: TestClient) -> None:
    response = client.get("/openapi.json")

    assert TOKEN not in response.text
    assert API_TOKEN_ENV_VAR in response.text  # the variable name only, in the description
    for path in PROTECTED:
        assert "parameters" not in response.json()["paths"][path]["post"]
