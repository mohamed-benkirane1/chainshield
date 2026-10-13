import json
import socket
from collections.abc import Iterator
from typing import Any

import base58
import pytest
from fastapi.testclient import TestClient

from app.api.transactions import (
    build_transaction_analysis_service,
    get_transaction_analysis_service,
)
from app.domain.analysis_input import Network
from app.domain.token_transfer import MAX_UINT256, NormalizedTokenTransfer
from app.main import app
from app.providers.base import (
    ChainMismatchError,
    ExecutionResultUnknownError,
    MalformedResponseError,
    NativeUnit,
    NormalizedTransaction,
    ProviderConfigurationError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    ReceiptUnavailableError,
    RpcError,
    TransactionStatus,
    UnsupportedTransactionError,
)
from app.providers.tron import TronApiError
from app.services.transaction_analysis import (
    InconsistentAnalysisError,
    TransactionAnalysisService,
    TransactionInspection,
)

URL = "/api/v1/transactions/inspect"
SECRET = "sk-test-0123456789abcdef"

ETH_HASH = "0x" + "ab" * 32
TRON_HASH = "cd" * 32
ETH_USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
ETH_ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
ETH_BOB = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
ETH_CAROL = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRON_ALICE = base58.b58encode_check(b"\x41" + bytes(range(1, 21))).decode()
TRON_BOB = base58.b58encode_check(b"\x41" + bytes(range(21, 41))).decode()

ENV_VARS = (
    "CHAINSHIELD_ETHEREUM_RPC_URL",
    "CHAINSHIELD_TRON_RPC_URL",
    "CHAINSHIELD_TRON_API_KEY",
)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    # The asyncio loop behind TestClient connects a local socket pair on
    # Windows; only that loopback traffic is allowed.
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
def _isolated_dependencies(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    get_transaction_analysis_service.cache_clear()
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()
    get_transaction_analysis_service.cache_clear()


class FakeService:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome
        self.calls: list[tuple[Network, str]] = []

    def inspect_transaction(self, network: Network, tx_hash: str) -> TransactionInspection:
        self.calls.append((network, tx_hash))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def use(outcome: Any) -> FakeService:
    fake = FakeService(outcome)
    app.dependency_overrides[get_transaction_analysis_service] = lambda: fake
    return fake


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def lenient_client() -> TestClient:
    # Returns the 500 response instead of re-raising unexpected exceptions.
    return TestClient(app, raise_server_exceptions=False)


# --- Builders ----------------------------------------------------------------


def eth_tx(status: TransactionStatus = TransactionStatus.SUCCESS, **overrides: Any):
    fields: dict[str, Any] = {"network": Network.ETHEREUM, "tx_hash": ETH_HASH, "status": status}
    if status is not TransactionStatus.NOT_FOUND:
        fields.update(
            from_address=ETH_ALICE,
            to_address=ETH_USDT,
            native_value_atomic=0,
            native_unit=NativeUnit.WEI,
        )
    if status in (TransactionStatus.SUCCESS, TransactionStatus.REVERTED):
        fields.update(block_number=19_000_000, block_timestamp=1_705_000_000)
    fields.update(overrides)
    return NormalizedTransaction(**fields)


def tron_tx(status: TransactionStatus = TransactionStatus.SUCCESS):
    fields: dict[str, Any] = {"network": Network.TRON, "tx_hash": TRON_HASH, "status": status}
    if status is not TransactionStatus.NOT_FOUND:
        fields.update(
            from_address=TRON_ALICE,
            to_address=TRON_USDT,
            native_value_atomic=0,
            native_unit=NativeUnit.SUN,
        )
    if status in (TransactionStatus.SUCCESS, TransactionStatus.REVERTED):
        fields.update(block_number=60_000_000, block_timestamp=1_705_000_002)
    return NormalizedTransaction(**fields)


def eth_transfer(sender=ETH_ALICE, recipient=ETH_BOB, amount=35_000_000, log_index=0):
    return NormalizedTokenTransfer(
        network=Network.ETHEREUM,
        tx_hash=ETH_HASH,
        token_symbol="USDT",
        token_contract=ETH_USDT,
        from_address=sender,
        to_address=recipient,
        amount_atomic=amount,
        decimals=6,
        log_index=log_index,
    )


def tron_transfer(amount: int = 10_000_000_000) -> NormalizedTokenTransfer:
    return NormalizedTokenTransfer(
        network=Network.TRON,
        tx_hash=TRON_HASH,
        token_symbol="USDT",
        token_contract=TRON_USDT,
        from_address=TRON_ALICE,
        to_address=TRON_BOB,
        amount_atomic=amount,
        decimals=6,
    )


def inspection(transaction: NormalizedTransaction, transfers: Any) -> TransactionInspection:
    return TransactionInspection(
        network=transaction.network,
        tx_hash=transaction.tx_hash,
        transaction=transaction,
        usdt_transfers=None if transfers is None else tuple(transfers),
    )


def eth_body(**overrides: Any) -> dict[str, Any]:
    return {"kind": "transaction", "network": "ethereum", "tx_hash": ETH_HASH, **overrides}


def tron_body() -> dict[str, Any]:
    return {"kind": "transaction", "network": "tron", "tx_hash": TRON_HASH}


# --- Successful inspections ----------------------------------------------------


def test_ethereum_inspection_with_usdt(client: TestClient) -> None:
    fake = use(inspection(eth_tx(), [eth_transfer(log_index=316)]))

    response = client.post(URL, json=eth_body())

    assert response.status_code == 200
    assert response.json() == {
        "network": "ethereum",
        "tx_hash": ETH_HASH,
        "transaction": {
            "status": "success",
            "from_address": ETH_ALICE,
            "to_address": ETH_USDT,
            "native_value_atomic": "0",
            "native_unit": "wei",
            "block_number": 19_000_000,
            "block_timestamp": 1_705_000_000,
        },
        "usdt_transfers": [
            {
                "token_symbol": "USDT",
                "token_contract": ETH_USDT,
                "from_address": ETH_ALICE,
                "to_address": ETH_BOB,
                "amount_atomic": "35000000",
                "amount_formatted": "35.000000",
                "decimals": 6,
                "log_index": 316,
            }
        ],
    }
    assert fake.calls == [(Network.ETHEREUM, ETH_HASH)]


def test_tron_inspection_with_usdt(client: TestClient) -> None:
    use(inspection(tron_tx(), [tron_transfer()]))

    body = client.post(URL, json=tron_body()).json()

    assert body["network"] == "tron"
    assert body["transaction"]["native_unit"] == "sun"
    assert body["usdt_transfers"] == [
        {
            "token_symbol": "USDT",
            "token_contract": TRON_USDT,
            "from_address": TRON_ALICE,
            "to_address": TRON_BOB,
            "amount_atomic": "10000000000",
            "amount_formatted": "10000.000000",
            "decimals": 6,
            "log_index": None,
        }
    ]


def test_multiple_transfers_keep_order_and_are_not_summed(client: TestClient) -> None:
    transfers = [
        eth_transfer(ETH_ALICE, ETH_BOB, 105_000_000, 171),
        eth_transfer(ETH_BOB, ETH_CAROL, 104_685_000, 172),
        eth_transfer(ETH_CAROL, ETH_ALICE, 104_685_000, 174),
    ]
    use(inspection(eth_tx(), transfers))

    body = client.post(URL, json=eth_body()).json()

    assert [(t["amount_atomic"], t["log_index"]) for t in body["usdt_transfers"]] == [
        ("105000000", 171),
        ("104685000", 172),
        ("104685000", 174),
    ]


def test_final_transaction_without_usdt_is_an_empty_list(client: TestClient) -> None:
    use(inspection(eth_tx(), []))

    assert client.post(URL, json=eth_body()).json()["usdt_transfers"] == []


def test_reverted_transaction_has_an_empty_list(client: TestClient) -> None:
    use(inspection(eth_tx(TransactionStatus.REVERTED), []))

    body = client.post(URL, json=eth_body()).json()

    assert body["transaction"]["status"] == "reverted"
    assert body["usdt_transfers"] == []


@pytest.mark.parametrize(
    ("transaction", "request_body"),
    [
        (eth_tx(TransactionStatus.PENDING), eth_body()),
        (tron_tx(TransactionStatus.UNCONFIRMED), tron_body()),
        (eth_tx(TransactionStatus.NOT_FOUND), eth_body()),
        (tron_tx(TransactionStatus.NOT_FOUND), tron_body()),
    ],
    ids=["pending", "unconfirmed", "eth-not-found", "tron-not-found"],
)
def test_non_final_transaction_reports_null_transfers(
    client: TestClient, transaction: NormalizedTransaction, request_body: dict
) -> None:
    use(inspection(transaction, None))

    response = client.post(URL, json=request_body)

    assert response.status_code == 200
    body = response.json()
    assert body["transaction"]["status"] == transaction.status.value
    assert "usdt_transfers" in body and body["usdt_transfers"] is None
    assert body["transaction"]["block_number"] is None
    assert body["transaction"]["block_timestamp"] is None


def test_not_found_preserves_all_nulls(client: TestClient) -> None:
    use(inspection(eth_tx(TransactionStatus.NOT_FOUND), None))

    assert client.post(URL, json=eth_body()).json()["transaction"] == {
        "status": "not_found",
        "from_address": None,
        "to_address": None,
        "native_value_atomic": None,
        "native_unit": None,
        "block_number": None,
        "block_timestamp": None,
    }


def test_hash_is_normalized_before_reaching_the_service(client: TestClient) -> None:
    fake = use(inspection(eth_tx(), []))

    client.post(URL, json=eth_body(tx_hash="0x" + ETH_HASH[2:].upper()))

    assert fake.calls == [(Network.ETHEREUM, ETH_HASH)]


def test_kind_defaults_to_transaction(client: TestClient) -> None:
    use(inspection(eth_tx(), []))

    assert client.post(URL, json={"network": "ethereum", "tx_hash": ETH_HASH}).status_code == 200


# --- Exact amounts -------------------------------------------------------------


@pytest.mark.parametrize("amount", [2**53 + 1, 123_456_789_012_345_678_901_234_567, MAX_UINT256])
def test_large_amounts_are_exact_decimal_strings(client: TestClient, amount: int) -> None:
    use(inspection(eth_tx(native_value_atomic=amount), [eth_transfer(amount=amount)]))

    response = client.post(URL, json=eth_body())
    body = response.json()

    assert body["usdt_transfers"][0]["amount_atomic"] == str(amount)
    assert body["transaction"]["native_value_atomic"] == str(amount)
    whole, fraction = divmod(amount, 10**6)
    assert body["usdt_transfers"][0]["amount_formatted"] == f"{whole}.{fraction:06d}"
    # The raw JSON carries the digits as strings, never as JSON numbers.
    assert f'"amount_atomic":"{amount}"' in response.text
    assert json.loads(response.text, parse_float=lambda _: pytest.fail("float found"))


def test_integer_outside_json_safe_range_is_rejected_not_rounded(client: TestClient) -> None:
    use(inspection(eth_tx(block_timestamp=2**53), []))

    response = client.post(URL, json=eth_body())

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "provider_malformed_response"


# --- Request validation ----------------------------------------------------------


@pytest.mark.parametrize("network", ["bitcoin", "Ethereum", "", None, 1])
def test_invalid_network_is_422(client: TestClient, network: object) -> None:
    fake = use(inspection(eth_tx(), []))

    response = client.post(URL, json=eth_body(network=network))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"
    assert fake.calls == []


@pytest.mark.parametrize(
    "body",
    [
        eth_body(tx_hash="0x1234"),
        eth_body(tx_hash="ab" * 32),
        eth_body(tx_hash=None),
        {"kind": "transaction", "network": "tron", "tx_hash": ETH_HASH},
        {"kind": "transaction", "network": "ethereum"},
    ],
    ids=["short", "tron-format-on-eth", "null", "eth-format-on-tron", "missing"],
)
def test_malformed_hash_is_422(client: TestClient, body: dict) -> None:
    fake = use(inspection(eth_tx(), []))

    response = client.post(URL, json=body)

    assert response.status_code == 422
    assert fake.calls == []


@pytest.mark.parametrize(
    "body",
    [
        eth_body(score=99),
        eth_body(kind="message"),
        eth_body(kind="address"),
        {"kind": "message", "text": "hello"},
    ],
    ids=["extra-field", "message-kind", "address-kind", "message-body"],
)
def test_extra_fields_and_other_kinds_are_422(client: TestClient, body: dict) -> None:
    use(inspection(eth_tx(), []))

    assert client.post(URL, json=body).status_code == 422


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (b"{not json", "application/json"),
        (b"", "application/json"),
        (b"[1, 2]", "application/json"),
        (b'"text"', "application/json"),
        (b"network=ethereum", "application/x-www-form-urlencoded"),
    ],
    ids=["invalid-json", "empty", "array", "string", "form"],
)
def test_invalid_json_body_is_422(client: TestClient, content: bytes, content_type: str) -> None:
    use(inspection(eth_tx(), []))

    response = client.post(URL, content=content, headers={"Content-Type": content_type})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


def test_validation_errors_do_not_echo_request_content(client: TestClient) -> None:
    use(inspection(eth_tx(), []))
    body = {
        "kind": "transaction",
        "network": f"net-{SECRET}",
        "tx_hash": f"0x{SECRET}",
        f"field_{SECRET}": f"value-{SECRET}",
    }

    response = client.post(URL, json=body)

    assert response.status_code == 422
    assert SECRET not in response.text
    for detail in response.json()["error"]["details"]:
        assert set(detail) == {"field", "type"}
        assert detail["field"] in {"kind", "network", "tx_hash", "body"}


def test_validation_of_invalid_json_does_not_echo_it(client: TestClient) -> None:
    truncated_json = f'{{"tx_hash": "{SECRET}"'.encode()

    response = client.post(
        URL, content=truncated_json, headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 422
    assert SECRET not in response.text


# --- Error mapping -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (ProviderConfigurationError(f"bad {SECRET}"), 503, "provider_not_configured"),
        (ProviderTimeoutError(f"timed out {SECRET}"), 504, "provider_timeout"),
        (ProviderUnavailableError("RPC endpoint returned HTTP 429"), 503, "provider_unavailable"),
        (ReceiptUnavailableError("retry later"), 503, "receipt_unavailable"),
        (ChainMismatchError("got chain ID 5"), 502, "provider_wrong_network"),
        (MalformedResponseError(f"bad data {SECRET}"), 502, "provider_malformed_response"),
        (InconsistentAnalysisError(f"reorg detail {SECRET}"), 502, "inconsistent_provider_data"),
        (ExecutionResultUnknownError("no status"), 502, "execution_result_unknown"),
        (RpcError("eth_getTransactionReceipt", -32000), 502, "provider_rpc_error"),
        (TronApiError(f"node said {SECRET}"), 502, "provider_api_error"),
        (UnsupportedTransactionError("TransferAssetContract"), 422, "unsupported_transaction"),
        (ProviderError(f"other {SECRET}"), 502, "provider_error"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_provider_errors_map_to_explicit_safe_responses(
    client: TestClient, error: Exception, status: int, code: str
) -> None:
    use(error)

    response = client.post(URL, json=eth_body())

    assert response.status_code == status
    body = response.json()
    assert body["error"]["code"] == code
    assert set(body["error"]) == {"code", "message"}
    assert str(error) not in response.text
    assert SECRET not in response.text


def test_unexpected_exception_is_a_safe_500(lenient_client: TestClient) -> None:
    use(RuntimeError(f"boom {SECRET} at /internal/path"))

    response = lenient_client.post(URL, json=eth_body())

    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "internal_error", "message": "An internal error occurred."}
    }
    assert SECRET not in response.text
    assert "Traceback" not in response.text


# --- Real dependency (environment configuration) -----------------------------------


def test_missing_provider_configuration_is_503(client: TestClient) -> None:
    response = client.post(URL, json=eth_body())

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "provider_not_configured"


def test_only_the_unconfigured_network_fails(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CHAINSHIELD_ETHEREUM_RPC_URL", f"https://eth.example.invalid/{SECRET}")

    response = client.post(URL, json=tron_body())

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "provider_not_configured"
    assert SECRET not in response.text


def test_invalid_configuration_is_503_without_leaking_it(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CHAINSHIELD_ETHEREUM_RPC_URL", f"ftp://eth.example.invalid/{SECRET}")

    response = client.post(URL, json=eth_body())

    assert response.status_code == 503
    assert SECRET not in response.text


def test_service_builder_makes_no_network_call() -> None:
    service = build_transaction_analysis_service(
        {
            "CHAINSHIELD_ETHEREUM_RPC_URL": "https://eth.example.invalid",
            "CHAINSHIELD_TRON_RPC_URL": "https://tron.example.invalid",
            "CHAINSHIELD_TRON_API_KEY": API_KEY_FOR_TESTS,
        }
    )

    assert isinstance(service, TransactionAnalysisService)


API_KEY_FOR_TESTS = "a1b2c3d4-e5f6-7890-abcd-ef0123456789"


def test_service_builder_accepts_partial_configuration() -> None:
    assert isinstance(build_transaction_analysis_service({}), TransactionAnalysisService)
    assert isinstance(
        build_transaction_analysis_service({"CHAINSHIELD_TRON_RPC_URL": "https://t.invalid"}),
        TransactionAnalysisService,
    )


def test_real_provider_call_is_blocked_and_safe(
    lenient_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CHAINSHIELD_ETHEREUM_RPC_URL", f"https://eth.example.invalid/{SECRET}")

    response = lenient_client.post(URL, json=eth_body())

    # The socket guard turned the attempted connection into an unexpected error.
    assert response.status_code == 500
    assert SECRET not in response.text
    assert "example.invalid" not in response.text


def test_dependency_overrides_are_isolated(client: TestClient) -> None:
    assert app.dependency_overrides == {}
    use(inspection(eth_tx(), []))
    assert client.post(URL, json=eth_body()).status_code == 200

    app.dependency_overrides.clear()

    assert client.post(URL, json=eth_body()).status_code == 503


def test_overrides_from_previous_test_do_not_leak(client: TestClient) -> None:
    assert app.dependency_overrides == {}
    assert client.post(URL, json=eth_body()).status_code == 503


# --- Health and documentation ----------------------------------------------------------


def test_health_is_unchanged(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_openapi_documents_the_route_and_string_amounts(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    operation = spec["paths"]["/api/v1/transactions/inspect"]["post"]
    assert {"200", "422", "502", "503", "504"} <= set(operation["responses"])
    transfer = spec["components"]["schemas"]["UsdtTransferView"]["properties"]
    assert transfer["amount_atomic"]["type"] == "string"
    assert "/health" in spec["paths"]
    assert client.get("/docs").status_code == 200
