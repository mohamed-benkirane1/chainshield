import io
import urllib.error
import json
from typing import Any

import pytest
from pydantic import ValidationError

from app.domain.analysis_input import Network
from app.providers.base import (
    ChainMismatchError,
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
)
from app.providers.ethereum import RPC_URL_ENV_VAR, EthereumProvider
from app.providers.transport import MAX_RESPONSE_BYTES, UrllibTransport

SECRET = "sk-test-0123456789abcdef"
RPC_URL = f"https://rpc.example.invalid/v3/{SECRET}"

TX_HASH = "0x" + "ab" * 32
BLOCK_HASH = "0x" + "cd" * 32
BLOCK_NUMBER = 19_000_000
BLOCK_TIMESTAMP = 1_705_000_000
# RPC nodes return lowercase addresses; the provider checksums them.
SENDER = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
RECIPIENT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"  # USDT contract


def rpc_tx(**overrides: Any) -> dict[str, Any]:
    tx = {
        "hash": TX_HASH,
        "from": SENDER.lower(),
        "to": RECIPIENT.lower(),
        "value": "0xde0b6b3a7640000",  # 1 ETH
        "blockNumber": hex(BLOCK_NUMBER),
        "blockHash": BLOCK_HASH,
        "input": "0x",
    }
    tx.update(overrides)
    return tx


def rpc_receipt(**overrides: Any) -> dict[str, Any]:
    receipt = {
        "transactionHash": TX_HASH,
        "blockHash": BLOCK_HASH,
        "blockNumber": hex(BLOCK_NUMBER),
        "status": "0x1",
    }
    receipt.update(overrides)
    return receipt


def rpc_block(**overrides: Any) -> dict[str, Any]:
    block = {
        "hash": BLOCK_HASH,
        "number": hex(BLOCK_NUMBER),
        "timestamp": hex(BLOCK_TIMESTAMP),
    }
    block.update(overrides)
    return block


class FakeTransport:
    """Answers JSON-RPC calls from a method -> result table, without network."""

    def __init__(self, results: dict[str, Any] | None = None) -> None:
        self.results = {
            "eth_chainId": "0x1",
            "eth_getTransactionByHash": rpc_tx(),
            "eth_getTransactionReceipt": rpc_receipt(),
            "eth_getBlockByNumber": rpc_block(),
        }
        self.results.update(results or {})
        self.envelopes: dict[str, Any] = {}
        self.raises: dict[str, Exception] = {}
        self.calls: list[tuple[str, list[Any]]] = []
        self.urls: list[str] = []
        self.timeouts: list[float] = []

    def post_json(self, url: str, payload: dict[str, Any], timeout: float) -> Any:
        method = payload["method"]
        self.calls.append((method, payload["params"]))
        self.urls.append(url)
        self.timeouts.append(timeout)
        if method in self.raises:
            raise self.raises[method]
        if method in self.envelopes:
            envelope = self.envelopes[method]
            return envelope(payload) if callable(envelope) else envelope
        return {"jsonrpc": "2.0", "id": payload["id"], "result": self.results[method]}

    @property
    def methods(self) -> list[str]:
        return [method for method, _ in self.calls]


def make_provider(transport: FakeTransport) -> EthereumProvider:
    return EthereumProvider(RPC_URL, transport=transport)


def lookup(transport: FakeTransport, tx_hash: str = TX_HASH) -> NormalizedTransaction:
    return make_provider(transport).get_transaction(tx_hash)


# --- Transaction states -----------------------------------------------------


def test_confirmed_successful_transaction() -> None:
    transport = FakeTransport()

    tx = lookup(transport)

    assert tx == NormalizedTransaction(
        network=Network.ETHEREUM,
        tx_hash=TX_HASH,
        status=TransactionStatus.SUCCESS,
        from_address=SENDER,
        to_address=RECIPIENT,
        native_value_atomic=10**18,
        native_unit=NativeUnit.WEI,
        block_number=BLOCK_NUMBER,
        block_timestamp=BLOCK_TIMESTAMP,
    )
    assert type(tx.block_timestamp) is int  # Unix seconds
    assert transport.calls == [
        ("eth_chainId", []),
        ("eth_getTransactionByHash", [TX_HASH]),
        ("eth_getTransactionReceipt", [TX_HASH]),
        ("eth_getBlockByNumber", [hex(BLOCK_NUMBER), False]),
    ]


def test_reverted_transaction() -> None:
    transport = FakeTransport({"eth_getTransactionReceipt": rpc_receipt(status="0x0")})

    tx = lookup(transport)

    assert tx.status is TransactionStatus.REVERTED
    assert tx.block_number == BLOCK_NUMBER
    assert tx.block_timestamp is not None


def test_pending_transaction_has_no_block_data() -> None:
    transport = FakeTransport(
        {"eth_getTransactionByHash": rpc_tx(blockNumber=None, blockHash=None)}
    )

    tx = lookup(transport)

    assert tx.status is TransactionStatus.PENDING
    assert tx.from_address == SENDER
    assert tx.native_value_atomic == 10**18
    assert tx.native_unit is NativeUnit.WEI
    assert tx.block_number is None
    assert tx.block_timestamp is None
    assert transport.methods == ["eth_chainId", "eth_getTransactionByHash"]


def test_transaction_not_found_carries_no_data() -> None:
    transport = FakeTransport({"eth_getTransactionByHash": None})

    tx = lookup(transport)

    assert tx == NormalizedTransaction(
        network=Network.ETHEREUM, tx_hash=TX_HASH, status=TransactionStatus.NOT_FOUND
    )
    assert transport.methods == ["eth_chainId", "eth_getTransactionByHash"]


def test_contract_creation_has_no_recipient() -> None:
    transport = FakeTransport({"eth_getTransactionByHash": rpc_tx(to=None)})

    assert lookup(transport).to_address is None


def test_input_hash_is_normalized_before_lookup() -> None:
    transport = FakeTransport()

    tx = lookup(transport, "0x" + TX_HASH[2:].upper())

    assert tx.tx_hash == TX_HASH
    assert transport.calls[1] == ("eth_getTransactionByHash", [TX_HASH])


@pytest.mark.parametrize("tx_hash", ["", "0x1234", "ab" * 32, "0x" + "zz" * 32])
def test_invalid_hash_is_rejected_without_rpc_call(tx_hash: str) -> None:
    transport = FakeTransport()

    with pytest.raises(ValueError):
        lookup(transport, tx_hash)
    assert transport.calls == []


# --- Amounts ----------------------------------------------------------------


@pytest.mark.parametrize(
    "wei",
    [0, 1, 10**18 + 1, 2**53 + 1, 123_456_789_012_345_678_901_234_567, 2**256 - 1],
)
def test_native_value_is_exact_in_wei(wei: int) -> None:
    transport = FakeTransport({"eth_getTransactionByHash": rpc_tx(value=hex(wei))})

    tx = lookup(transport)

    assert type(tx.native_value_atomic) is int
    assert tx.native_value_atomic == wei
    assert tx.native_unit is NativeUnit.WEI


def test_token_transfer_amount_is_not_taken_from_native_value() -> None:
    # USDT transfer(address,uint256) call: ETH value is 0, token amount is in
    # the call data and must not be reported as the transaction value.
    usdt_call_data = (
        "0xa9059cbb"
        + "000000000000000000000000" + SENDER[2:].lower()
        + format(1_000_000_000, "064x")  # 1000 USDT (6 decimals)
    )
    transport = FakeTransport(
        {"eth_getTransactionByHash": rpc_tx(value="0x0", input=usdt_call_data)}
    )

    tx = lookup(transport)

    assert tx.native_value_atomic == 0
    assert set(NormalizedTransaction.model_fields) == {
        "network",
        "tx_hash",
        "status",
        "from_address",
        "to_address",
        "native_value_atomic",
        "native_unit",
        "block_number",
        "block_timestamp",
    }


# --- Chain ID ---------------------------------------------------------------


@pytest.mark.parametrize("chain_id", ["0x5", "0xaa36a7", "0x38", "0x0"])
def test_wrong_chain_id_is_rejected_before_lookup(chain_id: str) -> None:
    transport = FakeTransport({"eth_chainId": chain_id})

    with pytest.raises(ChainMismatchError, match="chain ID"):
        lookup(transport)
    assert transport.methods == ["eth_chainId"]


def test_chain_id_is_verified_once_per_provider() -> None:
    transport = FakeTransport()
    provider = make_provider(transport)

    provider.get_transaction(TX_HASH)
    provider.get_transaction(TX_HASH)

    assert transport.methods.count("eth_chainId") == 1


def test_failed_chain_check_is_retried() -> None:
    transport = FakeTransport({"eth_chainId": "0x5"})
    provider = make_provider(transport)
    with pytest.raises(ChainMismatchError):
        provider.get_transaction(TX_HASH)

    transport.results["eth_chainId"] = "0x1"

    assert provider.get_transaction(TX_HASH).status is TransactionStatus.SUCCESS


@pytest.mark.parametrize("chain_id", [None, 1, "1", "0x", "mainnet"])
def test_malformed_chain_id_is_rejected(chain_id: object) -> None:
    transport = FakeTransport({"eth_chainId": chain_id})

    with pytest.raises(MalformedResponseError):
        lookup(transport)


# --- RPC errors and timeouts ------------------------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "eth_chainId",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
        "eth_getBlockByNumber",
    ],
)
def test_rpc_error_is_raised_for_each_method(method: str) -> None:
    transport = FakeTransport()
    transport.envelopes[method] = lambda payload: {
        "jsonrpc": "2.0",
        "id": payload["id"],
        "error": {"code": -32000, "message": "header not found"},
    }

    with pytest.raises(RpcError) as exc_info:
        lookup(transport)

    assert exc_info.value.method == method
    assert exc_info.value.code == -32000


def test_rpc_error_without_valid_error_object() -> None:
    transport = FakeTransport()
    transport.envelopes["eth_chainId"] = lambda payload: {
        "jsonrpc": "2.0",
        "id": payload["id"],
        "error": "boom",
    }

    with pytest.raises(RpcError) as exc_info:
        lookup(transport)

    assert exc_info.value.code is None


@pytest.mark.parametrize(
    "error",
    [
        ProviderTimeoutError("RPC request timed out"),
        ProviderUnavailableError("RPC endpoint returned HTTP 429"),
    ],
)
def test_transport_failures_propagate(error: ProviderError) -> None:
    transport = FakeTransport()
    transport.raises["eth_getTransactionReceipt"] = error

    with pytest.raises(type(error)):
        lookup(transport)


def test_timeout_is_passed_to_transport() -> None:
    transport = FakeTransport()

    EthereumProvider(RPC_URL, transport=transport, timeout=2.5).get_transaction(TX_HASH)

    assert set(transport.timeouts) == {2.5}
    assert set(transport.urls) == {RPC_URL}


# --- Malformed responses ----------------------------------------------------


@pytest.mark.parametrize(
    "envelope",
    [
        None,
        [],
        "0x1",
        {"id": 1, "result": "0x1"},  # missing jsonrpc
        {"jsonrpc": "1.0", "id": 1, "result": "0x1"},
        {"jsonrpc": "2.0", "id": 2, "result": "0x1"},  # wrong id
        {"jsonrpc": "2.0", "id": True, "result": "0x1"},  # bool id
        {"jsonrpc": "2.0", "id": "1", "result": "0x1"},
        {"jsonrpc": "2.0", "id": 1},  # neither result nor error
    ],
)
def test_malformed_json_rpc_envelope(envelope: object) -> None:
    transport = FakeTransport()
    transport.envelopes["eth_chainId"] = envelope

    with pytest.raises(MalformedResponseError):
        lookup(transport)


@pytest.mark.parametrize(
    "tx",
    [
        "not an object",
        rpc_tx(hash="0x" + "ef" * 32),  # different transaction
        rpc_tx(hash=None),
        rpc_tx(value=None),
        rpc_tx(value=1000),  # JSON number instead of hex quantity
        rpc_tx(value="1000"),
        rpc_tx(value="0x"),
        rpc_tx(value="0xZZ"),
        rpc_tx(value="-0x1"),
        rpc_tx(value="0x" + "f" * 65),
        rpc_tx(**{"from": None}),
        rpc_tx(**{"from": "0x1234"}),
        rpc_tx(to="not-an-address"),
        rpc_tx(blockNumber="12"),
        rpc_tx(blockHash=None),
    ],
)
def test_malformed_transaction(tx: object) -> None:
    transport = FakeTransport({"eth_getTransactionByHash": tx})

    with pytest.raises(MalformedResponseError):
        lookup(transport)


def test_transaction_without_to_field_is_malformed() -> None:
    tx = rpc_tx()
    del tx["to"]
    transport = FakeTransport({"eth_getTransactionByHash": tx})

    with pytest.raises(MalformedResponseError):
        lookup(transport)


@pytest.mark.parametrize(
    "receipt",
    [
        [],
        rpc_receipt(transactionHash="0x" + "ef" * 32),
        rpc_receipt(blockHash="0x" + "ef" * 32),
        rpc_receipt(blockNumber=hex(BLOCK_NUMBER + 1)),
        rpc_receipt(status=None),  # pre-Byzantium: outcome unknown
        rpc_receipt(status="0x2"),
        rpc_receipt(status=1),
    ],
)
def test_malformed_receipt(receipt: object) -> None:
    transport = FakeTransport({"eth_getTransactionReceipt": receipt})

    with pytest.raises(MalformedResponseError):
        lookup(transport)


def test_mined_transaction_without_receipt_is_reported_unavailable() -> None:
    transport = FakeTransport({"eth_getTransactionReceipt": None})

    with pytest.raises(ReceiptUnavailableError, match="retry later") as exc_info:
        lookup(transport)

    # Neither pending nor a guessed success/revert, and no further lookups.
    assert not isinstance(exc_info.value, MalformedResponseError)
    assert transport.methods == [
        "eth_chainId",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
    ]


def test_receipt_unavailability_is_not_cached() -> None:
    transport = FakeTransport({"eth_getTransactionReceipt": None})
    provider = make_provider(transport)
    with pytest.raises(ReceiptUnavailableError):
        provider.get_transaction(TX_HASH)

    transport.results["eth_getTransactionReceipt"] = rpc_receipt()

    assert provider.get_transaction(TX_HASH).status is TransactionStatus.SUCCESS
    assert transport.methods.count("eth_getTransactionReceipt") == 2


def test_max_uint64_block_timestamp_is_kept_exact() -> None:
    transport = FakeTransport(
        {"eth_getBlockByNumber": rpc_block(timestamp=hex(2**64 - 1))}
    )

    assert lookup(transport).block_timestamp == 2**64 - 1


@pytest.mark.parametrize(
    "block",
    [
        None,
        "not an object",
        rpc_block(hash="0x" + "ef" * 32),  # reorg / different block
        rpc_block(number=hex(BLOCK_NUMBER + 1)),
        rpc_block(timestamp=None),
        rpc_block(timestamp="0x" + "f" * 64),  # beyond uint64
        rpc_block(timestamp=hex(2**64)),
    ],
)
def test_malformed_block(block: object) -> None:
    transport = FakeTransport({"eth_getBlockByNumber": block})

    with pytest.raises(MalformedResponseError):
        lookup(transport)


# --- Configuration ----------------------------------------------------------


def test_from_env_reads_rpc_url() -> None:
    transport = FakeTransport()

    provider = EthereumProvider.from_env({RPC_URL_ENV_VAR: RPC_URL}, transport=transport)
    provider.get_transaction(TX_HASH)

    assert set(transport.urls) == {RPC_URL}


def test_from_env_uses_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(RPC_URL_ENV_VAR, RPC_URL)
    transport = FakeTransport()

    EthereumProvider.from_env(transport=transport).get_transaction(TX_HASH)

    assert set(transport.urls) == {RPC_URL}


@pytest.mark.parametrize("environ", [{}, {RPC_URL_ENV_VAR: ""}, {RPC_URL_ENV_VAR: "  "}])
def test_missing_rpc_url_is_a_configuration_error(environ: dict[str, str]) -> None:
    with pytest.raises(ProviderConfigurationError, match=RPC_URL_ENV_VAR):
        EthereumProvider.from_env(environ, transport=FakeTransport())


def test_missing_rpc_url_in_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(RPC_URL_ENV_VAR, raising=False)

    with pytest.raises(ProviderConfigurationError):
        EthereumProvider.from_env(transport=FakeTransport())


@pytest.mark.parametrize(
    "rpc_url",
    [
        f"file:///etc/{SECRET}",
        f"ftp://rpc.example.invalid/{SECRET}",
        f"rpc.example.invalid/{SECRET}",
        f"https:///{SECRET}",
        f"wss://rpc.example.invalid/{SECRET}",
    ],
)
def test_invalid_rpc_url_is_rejected_without_echoing_it(rpc_url: str) -> None:
    with pytest.raises(ProviderConfigurationError) as exc_info:
        EthereumProvider(rpc_url, transport=FakeTransport())

    assert SECRET not in str(exc_info.value)


@pytest.mark.parametrize("timeout", [0, -1.0])
def test_non_positive_timeout_is_rejected(timeout: float) -> None:
    with pytest.raises(ProviderConfigurationError):
        EthereumProvider(RPC_URL, transport=FakeTransport(), timeout=timeout)


def test_no_endpoint_is_hard_coded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(RPC_URL_ENV_VAR, raising=False)

    with pytest.raises(ProviderConfigurationError):
        EthereumProvider.from_env()


# --- Secret non-disclosure --------------------------------------------------


def test_provider_repr_does_not_expose_rpc_url() -> None:
    provider = make_provider(FakeTransport())

    assert SECRET not in repr(provider)
    assert SECRET not in str(provider)


def _failing_transports() -> list[FakeTransport]:
    wrong_chain = FakeTransport({"eth_chainId": "0x5"})
    rpc_error = FakeTransport()
    rpc_error.envelopes["eth_chainId"] = lambda payload: {
        "jsonrpc": "2.0",
        "id": payload["id"],
        "error": {"code": -32001, "message": f"invalid key {SECRET} for {RPC_URL}"},
    }
    malformed = FakeTransport({"eth_getTransactionByHash": rpc_tx(value="bad")})
    receipt_unavailable = FakeTransport({"eth_getTransactionReceipt": None})
    return [wrong_chain, rpc_error, malformed, receipt_unavailable]


@pytest.mark.parametrize("transport", _failing_transports())
def test_provider_errors_do_not_expose_secrets(transport: FakeTransport) -> None:
    with pytest.raises(ProviderError) as exc_info:
        lookup(transport)

    assert SECRET not in str(exc_info.value)
    assert SECRET not in repr(exc_info.value)


# --- Default urllib transport (no network: the opener is replaced) ----------


class _FakeResponse(io.BytesIO):
    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class _FakeOpener:
    def __init__(self, outcome: object) -> None:
        self.outcome = outcome
        self.requests: list[Any] = []

    def open(self, request: Any, timeout: float) -> _FakeResponse:
        self.requests.append((request, timeout))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return _FakeResponse(self.outcome)


def _transport_with(outcome: object) -> tuple[UrllibTransport, _FakeOpener]:
    transport = UrllibTransport()
    opener = _FakeOpener(outcome)
    transport._opener = opener  # type: ignore[assignment]
    return transport, opener


def test_urllib_transport_posts_json_and_decodes_response() -> None:
    transport, opener = _transport_with(b'{"jsonrpc": "2.0", "id": 1, "result": "0x1"}')

    result = transport.post_json(RPC_URL, {"method": "eth_chainId"}, 3.0)

    assert result == {"jsonrpc": "2.0", "id": 1, "result": "0x1"}
    request, timeout = opener.requests[0]
    assert request.get_method() == "POST"
    assert request.data == b'{"method": "eth_chainId"}'
    assert request.get_header("Content-type") == "application/json"
    assert timeout == 3.0


def test_urllib_transport_identifies_itself_as_chainshield() -> None:
    # Regression: Cloudflare-fronted providers answered HTTP 403 (error 1010)
    # to urllib's default "Python-urllib/x.y" User-Agent.
    transport, opener = _transport_with(b'{"jsonrpc": "2.0", "id": 1, "result": "0x1"}')

    transport.post_json(RPC_URL, {"method": "eth_chainId"}, 3.0)

    request, _ = opener.requests[0]
    assert request.get_header("User-agent") == "ChainShield/0.2.0"


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (TimeoutError(f"timed out {RPC_URL}"), ProviderTimeoutError),
        (urllib.error.URLError(TimeoutError(RPC_URL)), ProviderTimeoutError),
        (urllib.error.URLError(f"refused {RPC_URL}"), ProviderUnavailableError),
        (ConnectionResetError(f"reset {RPC_URL}"), ProviderUnavailableError),
        (
            urllib.error.HTTPError(RPC_URL, 401, f"bad key {SECRET}", {}, None),  # type: ignore[arg-type]
            ProviderUnavailableError,
        ),
        (b"<html>not json</html>", MalformedResponseError),
        (b"\xff\xfe\x00", MalformedResponseError),
        (b"0" * (MAX_RESPONSE_BYTES + 1), MalformedResponseError),
    ],
    ids=[
        "socket-timeout",
        "urlerror-timeout",
        "urlerror-refused",
        "connection-reset",
        "http-401",
        "not-json",
        "invalid-utf8",
        "oversized-body",
    ],
)
def test_urllib_transport_errors_hide_url_and_cause(
    outcome: object, expected: type[ProviderError]
) -> None:
    transport, _ = _transport_with(outcome)

    with pytest.raises(expected) as exc_info:
        transport.post_json(RPC_URL, {"method": "eth_chainId"}, 1.0)

    assert SECRET not in str(exc_info.value)
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True or exc_info.value.__context__ is None


def test_urllib_transport_reports_http_status() -> None:
    error = urllib.error.HTTPError(RPC_URL, 429, "Too Many Requests", {}, None)  # type: ignore[arg-type]
    transport, _ = _transport_with(error)

    with pytest.raises(ProviderUnavailableError, match="HTTP 429"):
        transport.post_json(RPC_URL, {}, 1.0)


def test_urllib_transport_does_not_follow_redirects() -> None:
    from app.providers.transport import _NoRedirectHandler

    handler = _NoRedirectHandler()

    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil.invalid") is None


# --- Normalized model invariants -------------------------------------------

MINED = {
    "status": "success",
    "from_address": SENDER,
    "native_value_atomic": 0,
    "native_unit": "wei",
    "block_number": 1,
    "block_timestamp": 0,
}


@pytest.mark.parametrize(
    "fields",
    [
        {"status": "not_found", "from_address": SENDER},
        {"status": "not_found", "native_value_atomic": 0, "native_unit": "wei"},
        {"status": "pending", "native_value_atomic": 0, "native_unit": "wei"},
        {"status": "pending", "from_address": SENDER},  # missing value
        {
            "status": "pending",
            "from_address": SENDER,
            "native_value_atomic": 0,
            "native_unit": "wei",
            "block_number": 1,
        },
        {
            "status": "success",
            "from_address": SENDER,
            "native_value_atomic": 0,
            "native_unit": "wei",
        },
        {**MINED, "status": "reverted", "block_timestamp": None},
        {**MINED, "native_value_atomic": -1},
        {**MINED, "block_timestamp": -1},
    ],
)
def test_normalized_transaction_rejects_inconsistent_data(fields: dict) -> None:
    with pytest.raises(ValidationError):
        NormalizedTransaction(network="ethereum", tx_hash=TX_HASH, **fields)


def test_normalized_transaction_is_immutable() -> None:
    tx = NormalizedTransaction(
        network="ethereum", tx_hash=TX_HASH, status=TransactionStatus.NOT_FOUND
    )

    with pytest.raises(ValidationError):
        tx.status = TransactionStatus.SUCCESS  # type: ignore[misc]


@pytest.mark.parametrize(("network", "unit"), [("ethereum", "wei"), ("tron", "sun")])
def test_native_unit_matches_network(network: str, unit: str) -> None:
    tx = NormalizedTransaction(
        **{**MINED, "network": network, "tx_hash": TX_HASH, "native_unit": unit}
    )

    assert tx.native_unit is NativeUnit(unit)


@pytest.mark.parametrize(
    ("network", "unit"),
    [("ethereum", "sun"), ("tron", "wei"), ("ethereum", "eth"), ("ethereum", "gwei")],
)
def test_native_unit_inconsistent_with_network_is_rejected(
    network: str, unit: str
) -> None:
    with pytest.raises(ValidationError):
        NormalizedTransaction(
            **{**MINED, "network": network, "tx_hash": TX_HASH, "native_unit": unit}
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"native_unit": None},  # value without unit
        {"native_value_atomic": None},  # unit without value
    ],
)
def test_native_value_and_unit_go_together(overrides: dict) -> None:
    with pytest.raises(ValidationError, match="go together"):
        NormalizedTransaction(
            network="ethereum", tx_hash=TX_HASH, **{**MINED, **overrides}
        )


@pytest.mark.parametrize("value", [1.0, 1e18, "1000", True, 10**18 + 0.5])
def test_native_value_must_be_an_exact_integer(value: object) -> None:
    with pytest.raises(ValidationError):
        NormalizedTransaction(
            network="ethereum",
            tx_hash=TX_HASH,
            **{**MINED, "native_value_atomic": value},
        )


@pytest.mark.parametrize("timestamp", [1.5, 1_705_000_000.0, "1705000000", True])
def test_block_timestamp_must_be_integer_unix_seconds(timestamp: object) -> None:
    with pytest.raises(ValidationError):
        NormalizedTransaction(
            network="ethereum",
            tx_hash=TX_HASH,
            **{**MINED, "block_timestamp": timestamp},
        )


@pytest.mark.parametrize(("network", "unit"), [("ethereum", "wei"), ("tron", "sun")])
def test_large_native_values_survive_json_round_trip(network: str, unit: str) -> None:
    value = 2**256 - 1
    tx = NormalizedTransaction(
        **{
            **MINED,
            "network": network,
            "tx_hash": TX_HASH,
            "native_value_atomic": value,
            "native_unit": unit,
        }
    )

    dumped = tx.model_dump_json()

    assert json.loads(dumped)["native_value_atomic"] == value
    assert str(value) in dumped
    assert NormalizedTransaction.model_validate_json(dumped) == tx
