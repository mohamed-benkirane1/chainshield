import copy
import io
import urllib.error
from typing import Any

import base58
import pytest
from pydantic import ValidationError

from app.domain.analysis_input import Network
from app.providers.base import (
    ExecutionResultUnknownError,
    MalformedResponseError,
    NativeUnit,
    NormalizedTransaction,
    ProviderConfigurationError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    ReceiptUnavailableError,
    TransactionStatus,
    UnsupportedTransactionError,
)
from app.providers.transport import UrllibTransport
from app.providers.tron import (
    API_KEY_ENV_VAR,
    API_KEY_HEADER,
    GET_SOLID_TRANSACTION_INFO_PATH,
    GET_SOLID_TRANSACTION_PATH,
    GET_TRANSACTION_PATH,
    RPC_URL_ENV_VAR,
    TronApiError,
    TronProvider,
    hex_to_base58_address,
)

SECRET = "sk-tron-0123456789abcdef"
API_KEY = "a1b2c3d4-e5f6-7890-abcd-ef0123456789"
BASE_URL = f"https://tron.example.invalid/{SECRET}"

TX_HASH = "ab" * 32
OTHER_HASH = "ef" * 32

# USDT TRC-20 contract on TRON mainnet, and two synthetic accounts.
USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
SENDER = base58.b58encode_check(b"\x41" + bytes(range(1, 21))).decode()
RECIPIENT = base58.b58encode_check(b"\x41" + bytes(range(21, 41))).decode()


def to_hex(address: str) -> str:
    return base58.b58decode_check(address).hex()


BLOCK_NUMBER = 60_000_000
BLOCK_TIMESTAMP_MS = 1_705_000_002_000
CREATION_TIMESTAMP_MS = 1_704_999_990_123  # raw_data.timestamp, set by sender

USDT_TRANSFER_DATA = (
    "a9059cbb"
    + "0" * 24 + to_hex(RECIPIENT)[2:]
    + format(1_000_000_000, "064x")  # 1000 USDT (6 decimals)
)


def transfer_tx(amount: object = 1_500_000, **value_overrides: Any) -> dict[str, Any]:
    value = {
        "amount": amount,
        "owner_address": to_hex(SENDER),
        "to_address": to_hex(RECIPIENT),
    }
    value.update(value_overrides)
    return {
        "ret": [{"contractRet": "SUCCESS"}],
        "txID": TX_HASH,
        "raw_data": {
            "contract": [
                {
                    "parameter": {
                        "value": value,
                        "type_url": "type.googleapis.com/protocol.TransferContract",
                    },
                    "type": "TransferContract",
                }
            ],
            "ref_block_bytes": "1234",
            "ref_block_hash": "0011223344556677",
            "expiration": CREATION_TIMESTAMP_MS + 60_000,
            "timestamp": CREATION_TIMESTAMP_MS,
        },
        "raw_data_hex": "0a02",
        "signature": ["00" * 65],
    }


def trigger_tx(contract_ret: str = "SUCCESS", **value_overrides: Any) -> dict[str, Any]:
    value = {
        "data": USDT_TRANSFER_DATA,
        "owner_address": to_hex(SENDER),
        "contract_address": to_hex(USDT_CONTRACT),
    }
    value.update(value_overrides)
    return {
        "ret": [{"contractRet": contract_ret}],
        "txID": TX_HASH,
        "raw_data": {
            "contract": [
                {
                    "parameter": {
                        "value": value,
                        "type_url": "type.googleapis.com/protocol.TriggerSmartContract",
                    },
                    "type": "TriggerSmartContract",
                }
            ],
            "fee_limit": 100_000_000,
            "timestamp": CREATION_TIMESTAMP_MS,
        },
    }


def tx_info(receipt_result: str | None = None, failed: bool = False, **overrides: Any) -> dict:
    receipt: dict[str, Any] = {"net_usage": 345}
    if receipt_result is not None:
        receipt["result"] = receipt_result
        receipt["energy_usage_total"] = 14_650
    info: dict[str, Any] = {
        "id": TX_HASH,
        "fee": 1_100_000,
        "blockNumber": BLOCK_NUMBER,
        "blockTimeStamp": BLOCK_TIMESTAMP_MS,
        "contractResult": [""],
        "receipt": receipt,
    }
    if failed:
        info["result"] = "FAILED"
        info["resMessage"] = "5452414e534645525f4641494c4544"
    info.update(overrides)
    return info


class FakeTransport:
    """Answers TRON HTTP API calls by path, without network."""

    def __init__(self, tx: Any, solid_tx: Any = None, info: Any = None) -> None:
        self.responses: dict[str, Any] = {
            GET_TRANSACTION_PATH: tx,
            GET_SOLID_TRANSACTION_PATH: copy.deepcopy(tx) if solid_tx is None else solid_tx,
            GET_SOLID_TRANSACTION_INFO_PATH: tx_info() if info is None else info,
        }
        self.raises: dict[str, Exception] = {}
        self.calls: list[dict[str, Any]] = []

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        timeout: float,
        headers: dict[str, str] | None = None,
    ) -> Any:
        path = next(p for p in self.responses if url.endswith(p))
        self.calls.append(
            {"url": url, "path": path, "payload": payload, "timeout": timeout,
             "headers": dict(headers or {})}
        )
        if path in self.raises:
            raise self.raises[path]
        return copy.deepcopy(self.responses[path])

    @property
    def paths(self) -> list[str]:
        return [call["path"] for call in self.calls]


def make_provider(transport: FakeTransport, **kwargs: Any) -> TronProvider:
    return TronProvider(BASE_URL, transport=transport, **kwargs)


def lookup(transport: FakeTransport, tx_hash: str = TX_HASH) -> NormalizedTransaction:
    return make_provider(transport).get_transaction(tx_hash)


ALL_PATHS = [GET_TRANSACTION_PATH, GET_SOLID_TRANSACTION_PATH, GET_SOLID_TRANSACTION_INFO_PATH]


# --- TRX transfers ----------------------------------------------------------


def test_solidified_trx_transfer() -> None:
    transport = FakeTransport(transfer_tx())

    tx = lookup(transport)

    assert tx == NormalizedTransaction(
        network=Network.TRON,
        tx_hash=TX_HASH,
        status=TransactionStatus.SUCCESS,
        from_address=SENDER,
        to_address=RECIPIENT,
        native_value_atomic=1_500_000,
        native_unit=NativeUnit.SUN,
        block_number=BLOCK_NUMBER,
        block_timestamp=BLOCK_TIMESTAMP_MS // 1000,
    )
    assert transport.paths == ALL_PATHS
    assert all(call["payload"] == {"value": TX_HASH, "visible": False} for call in transport.calls)
    assert [call["url"] for call in transport.calls] == [BASE_URL + p for p in ALL_PATHS]


@pytest.mark.parametrize("amount", [1, 1_000_000, 2**53 + 1, 2**63 - 1])
def test_trx_amount_is_exact_in_sun(amount: int) -> None:
    tx = lookup(FakeTransport(transfer_tx(amount=amount)))

    assert type(tx.native_value_atomic) is int
    assert tx.native_value_atomic == amount
    assert tx.native_unit is NativeUnit.SUN


@pytest.mark.parametrize("amount", [None, 1.0, 1.5, "1000", True, -1, 2**63])
def test_invalid_trx_amount_is_rejected(amount: object) -> None:
    tx = transfer_tx(amount=amount)
    if amount is None:
        del tx["raw_data"]["contract"][0]["parameter"]["value"]["amount"]

    with pytest.raises(MalformedResponseError, match="amount"):
        lookup(FakeTransport(tx))


# --- Smart contract calls ---------------------------------------------------


def test_usdt_contract_call_is_not_reported_as_native_amount() -> None:
    # call_value omitted (proto3 zero); the 1000 USDT in the call data must
    # not surface anywhere in the normalized transaction.
    transport = FakeTransport(trigger_tx(), info=tx_info(receipt_result="SUCCESS"))

    tx = lookup(transport)

    assert tx.status is TransactionStatus.SUCCESS
    assert tx.from_address == SENDER
    assert tx.to_address == USDT_CONTRACT
    assert tx.native_value_atomic == 0
    assert tx.native_unit is NativeUnit.SUN
    assert 1_000_000_000 not in tx.model_dump().values()


def test_contract_call_value_is_trx_in_sun() -> None:
    transport = FakeTransport(
        trigger_tx(call_value=5_000_000), info=tx_info(receipt_result="SUCCESS")
    )

    assert lookup(transport).native_value_atomic == 5_000_000


@pytest.mark.parametrize("call_value", [1.0, "5", True, -1, 2**63])
def test_invalid_call_value_is_rejected(call_value: object) -> None:
    transport = FakeTransport(
        trigger_tx(call_value=call_value), info=tx_info(receipt_result="SUCCESS")
    )

    with pytest.raises(MalformedResponseError, match="call value"):
        lookup(transport)


@pytest.mark.parametrize("failure", ["REVERT", "OUT_OF_ENERGY", "TRANSFER_FAILED"])
def test_failed_contract_call_is_reverted(failure: str) -> None:
    transport = FakeTransport(
        trigger_tx(contract_ret=failure), info=tx_info(receipt_result=failure, failed=True)
    )

    tx = lookup(transport)

    assert tx.status is TransactionStatus.REVERTED
    assert tx.block_number == BLOCK_NUMBER
    assert tx.block_timestamp == BLOCK_TIMESTAMP_MS // 1000


def test_contract_call_without_receipt_result_is_unknown() -> None:
    transport = FakeTransport(trigger_tx(), info=tx_info(receipt_result=None))

    with pytest.raises(ExecutionResultUnknownError):
        lookup(transport)


# --- Statuses and finality --------------------------------------------------


def test_transaction_unknown_to_node_is_not_found() -> None:
    transport = FakeTransport({})

    tx = lookup(transport)

    assert tx == NormalizedTransaction(
        network=Network.TRON, tx_hash=TX_HASH, status=TransactionStatus.NOT_FOUND
    )
    assert transport.paths == [GET_TRANSACTION_PATH]


def test_non_solidified_transaction_is_unconfirmed_not_pending() -> None:
    transport = FakeTransport(transfer_tx(), solid_tx={})

    tx = lookup(transport)

    assert tx.status is TransactionStatus.UNCONFIRMED
    assert tx.from_address == SENDER
    assert tx.to_address == RECIPIENT
    assert tx.native_value_atomic == 1_500_000
    assert tx.block_number is None
    assert tx.block_timestamp is None
    assert transport.paths == [GET_TRANSACTION_PATH, GET_SOLID_TRANSACTION_PATH]


def test_unconfirmed_outcome_is_not_reported_even_if_failed() -> None:
    transport = FakeTransport(trigger_tx(contract_ret="REVERT"), solid_tx={})

    assert lookup(transport).status is TransactionStatus.UNCONFIRMED


def test_missing_execution_info_is_reported_unavailable() -> None:
    transport = FakeTransport(transfer_tx(), info={})

    with pytest.raises(ReceiptUnavailableError, match="retry later"):
        lookup(transport)


@pytest.mark.parametrize(
    "ret",
    [None, [], [{}], [{"contractRet": "DEFAULT"}], [{"contractRet": "UNKNOWN"}],
     [{"contractRet": "SOMETHING_NEW"}], [{"contractRet": "SUCCESS"}, {}], "SUCCESS"],
)
def test_unestablished_execution_result_is_unknown(ret: object) -> None:
    tx = transfer_tx()
    if ret is None:
        del tx["ret"]
    else:
        tx["ret"] = ret

    with pytest.raises(ExecutionResultUnknownError):
        lookup(FakeTransport(tx))


def test_absent_receipt_result_is_not_treated_as_failure() -> None:
    # TransferContract info carries no receipt.result: that is not a failure.
    tx = lookup(FakeTransport(transfer_tx(), info=tx_info(receipt_result=None)))

    assert tx.status is TransactionStatus.SUCCESS


@pytest.mark.parametrize(
    ("tx", "info"),
    [
        (transfer_tx(), tx_info(failed=True)),  # SUCCESS + FAILED
        (trigger_tx(contract_ret="REVERT"), tx_info(receipt_result="REVERT")),  # no FAILED
        (trigger_tx(), tx_info(receipt_result="REVERT")),  # receipt mismatch
        (transfer_tx(), tx_info(result="MAYBE")),
        (transfer_tx(), tx_info(receipt=[])),
    ],
)
def test_contradictory_execution_data_is_malformed(tx: dict, info: dict) -> None:
    with pytest.raises(MalformedResponseError):
        lookup(FakeTransport(tx, info=info))


# --- Timestamps -------------------------------------------------------------


@pytest.mark.parametrize(
    ("millis", "seconds"),
    [(0, 0), (999, 0), (1_000, 1), (1_705_000_002_999, 1_705_000_002), (2**63 - 1, (2**63 - 1) // 1000)],
)
def test_block_timestamp_is_converted_to_seconds_exactly(millis: int, seconds: int) -> None:
    tx = lookup(FakeTransport(transfer_tx(), info=tx_info(blockTimeStamp=millis)))

    assert type(tx.block_timestamp) is int
    assert tx.block_timestamp == seconds


def test_block_timestamp_comes_from_block_not_raw_data() -> None:
    tx = lookup(FakeTransport(transfer_tx()))

    assert tx.block_timestamp == BLOCK_TIMESTAMP_MS // 1000
    assert tx.block_timestamp != CREATION_TIMESTAMP_MS // 1000


@pytest.mark.parametrize("field", ["blockTimeStamp", "blockNumber"])
@pytest.mark.parametrize("bad", [None, 1.7e12, "1705000002000", True, -1, 2**63])
def test_invalid_block_data_is_malformed(field: str, bad: object) -> None:
    info = tx_info(**{field: bad})
    if bad is None:
        del info[field]

    with pytest.raises(MalformedResponseError):
        lookup(FakeTransport(transfer_tx(), info=info))


# --- Addresses --------------------------------------------------------------


def test_hex_address_is_converted_to_base58check() -> None:
    assert hex_to_base58_address(to_hex(USDT_CONTRACT)) == USDT_CONTRACT
    assert hex_to_base58_address(to_hex(USDT_CONTRACT).upper()) == USDT_CONTRACT


@pytest.mark.parametrize(
    "value",
    [
        USDT_CONTRACT,  # Base58 where hex is expected
        "42" + to_hex(USDT_CONTRACT)[2:],  # wrong prefix
        "0x" + to_hex(USDT_CONTRACT)[2:],  # Ethereum-style
        to_hex(USDT_CONTRACT)[:-2],  # 20 bytes
        to_hex(USDT_CONTRACT) + "00",  # 22 bytes
        "41" + "zz" * 20,
        "",
        None,
        41,
    ],
)
def test_invalid_hex_address_is_rejected(value: object) -> None:
    with pytest.raises(MalformedResponseError):
        hex_to_base58_address(value)


@pytest.mark.parametrize(
    ("field", "bad"),
    [("owner_address", "42" + "00" * 20), ("to_address", USDT_CONTRACT), ("owner_address", None)],
)
def test_invalid_transfer_address_is_malformed(field: str, bad: object) -> None:
    tx = transfer_tx(**{field: bad})

    with pytest.raises(MalformedResponseError):
        lookup(FakeTransport(tx))


def test_contract_call_without_contract_address_is_malformed() -> None:
    tx = trigger_tx()
    del tx["raw_data"]["contract"][0]["parameter"]["value"]["contract_address"]

    with pytest.raises(MalformedResponseError, match="contract address"):
        lookup(FakeTransport(tx, info=tx_info(receipt_result="SUCCESS")))


# --- Hash and cross-endpoint consistency -----------------------------------


def test_input_hash_is_normalized() -> None:
    transport = FakeTransport(transfer_tx())

    assert lookup(transport, TX_HASH.upper()).tx_hash == TX_HASH
    assert transport.calls[0]["payload"]["value"] == TX_HASH


@pytest.mark.parametrize("tx_hash", ["", "ab" * 31, "0x" + "ab" * 32, "zz" * 32])
def test_invalid_hash_is_rejected_without_request(tx_hash: str) -> None:
    transport = FakeTransport(transfer_tx())

    with pytest.raises(ValueError):
        lookup(transport, tx_hash)
    assert transport.calls == []


def _with(tx: dict, **changes: Any) -> dict:
    tx = copy.deepcopy(tx)
    tx.update(changes)
    return tx


@pytest.mark.parametrize(
    ("full", "solid", "info"),
    [
        (_with(transfer_tx(), txID=OTHER_HASH), None, None),
        (_with(transfer_tx(), txID=None), None, None),
        (transfer_tx(), _with(transfer_tx(), txID=OTHER_HASH), None),
        (transfer_tx(), transfer_tx(amount=1), None),  # raw_data disagrees
        (transfer_tx(), None, tx_info(id=OTHER_HASH)),
        (transfer_tx(), None, tx_info(id="0x" + TX_HASH)),
    ],
)
def test_inconsistent_hashes_or_data_are_malformed(full: dict, solid: Any, info: Any) -> None:
    with pytest.raises(MalformedResponseError):
        lookup(FakeTransport(full, solid_tx=solid, info=info))


# --- Contract structure -----------------------------------------------------


def _set_contract(tx: dict, contract: Any) -> dict:
    tx = copy.deepcopy(tx)
    tx["raw_data"]["contract"] = contract
    return tx


@pytest.mark.parametrize(
    "tx",
    [
        _with(transfer_tx(), raw_data=None),
        _set_contract(transfer_tx(), []),
        _set_contract(transfer_tx(), transfer_tx()["raw_data"]["contract"] * 2),
        _set_contract(transfer_tx(), None),
        _set_contract(transfer_tx(), ["x"]),
        _set_contract(transfer_tx(), [{"parameter": {"value": {}}}]),  # no type
        _set_contract(transfer_tx(), [{"type": "TransferContract"}]),  # no parameter
        _set_contract(transfer_tx(), [{"type": "TransferContract", "parameter": {}}]),
        _set_contract(
            transfer_tx(),
            [{**transfer_tx()["raw_data"]["contract"][0],
              "type": "TriggerSmartContract"}],  # type_url mismatch
        ),
    ],
)
def test_malformed_contract_structure(tx: dict) -> None:
    with pytest.raises(MalformedResponseError):
        lookup(FakeTransport(tx))


@pytest.mark.parametrize(
    "contract_type",
    ["TransferAssetContract", "FreezeBalanceV2Contract", "CreateSmartContract"],
)
@pytest.mark.parametrize("solidified", [True, False])
def test_unsupported_contract_type(contract_type: str, solidified: bool) -> None:
    tx = _set_contract(
        transfer_tx(),
        [{"type": contract_type, "parameter": {"value": {}, "type_url": "x"}}],
    )

    with pytest.raises(UnsupportedTransactionError, match=contract_type):
        lookup(FakeTransport(tx, solid_tx=None if solidified else {}))


# --- Errors from the node or the network -----------------------------------


@pytest.mark.parametrize("path", ALL_PATHS)
@pytest.mark.parametrize(
    "payload",
    [{"Error": f"class java.lang.IllegalArgumentException : {SECRET}"}, {"error": "bad"}],
)
def test_error_payload_in_http_200_is_reported(path: str, payload: dict) -> None:
    transport = FakeTransport(transfer_tx())
    transport.responses[path] = payload

    with pytest.raises(TronApiError) as exc_info:
        lookup(transport)

    assert SECRET not in str(exc_info.value)


@pytest.mark.parametrize("path", ALL_PATHS)
@pytest.mark.parametrize("payload", [None, [], "ok", 0])
def test_non_object_response_is_malformed(path: str, payload: object) -> None:
    transport = FakeTransport(transfer_tx())
    transport.responses[path] = payload

    with pytest.raises(MalformedResponseError):
        lookup(transport)


@pytest.mark.parametrize("path", ALL_PATHS)
@pytest.mark.parametrize(
    "error",
    [
        ProviderTimeoutError("RPC request timed out"),
        ProviderUnavailableError("RPC endpoint returned HTTP 429"),
        MalformedResponseError("RPC response is not valid JSON"),
    ],
    ids=["timeout", "http-429", "empty-or-invalid-body"],
)
def test_transport_failures_propagate(path: str, error: ProviderError) -> None:
    transport = FakeTransport(transfer_tx())
    transport.raises[path] = error

    with pytest.raises(type(error)):
        lookup(transport)


# --- Configuration ----------------------------------------------------------


def test_from_env_without_api_key_sends_no_key_header() -> None:
    transport = FakeTransport(transfer_tx())

    TronProvider.from_env({RPC_URL_ENV_VAR: BASE_URL}, transport=transport).get_transaction(
        TX_HASH
    )

    assert all(API_KEY_HEADER not in call["headers"] for call in transport.calls)
    assert all(call["url"].startswith(BASE_URL + "/") for call in transport.calls)


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_api_key_is_treated_as_absent(blank: str) -> None:
    transport = FakeTransport(transfer_tx())
    env = {RPC_URL_ENV_VAR: BASE_URL, API_KEY_ENV_VAR: blank}

    TronProvider.from_env(env, transport=transport).get_transaction(TX_HASH)

    assert all(call["headers"] == {} for call in transport.calls)


def test_api_key_is_sent_in_header_when_configured() -> None:
    transport = FakeTransport(transfer_tx())
    env = {RPC_URL_ENV_VAR: BASE_URL, API_KEY_ENV_VAR: API_KEY}

    TronProvider.from_env(env, transport=transport).get_transaction(TX_HASH)

    assert len(transport.calls) == 3
    assert all(call["headers"] == {API_KEY_HEADER: API_KEY} for call in transport.calls)
    assert all(API_KEY not in call["url"] for call in transport.calls)
    assert all(API_KEY not in str(call["payload"]) for call in transport.calls)


def test_from_env_uses_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(RPC_URL_ENV_VAR, BASE_URL)
    monkeypatch.setenv(API_KEY_ENV_VAR, API_KEY)
    transport = FakeTransport(transfer_tx())

    TronProvider.from_env(transport=transport).get_transaction(TX_HASH)

    assert transport.calls[0]["headers"] == {API_KEY_HEADER: API_KEY}


@pytest.mark.parametrize("environ", [{}, {RPC_URL_ENV_VAR: ""}, {RPC_URL_ENV_VAR: "  "}])
def test_missing_rpc_url_is_a_configuration_error(environ: dict[str, str]) -> None:
    with pytest.raises(ProviderConfigurationError, match=RPC_URL_ENV_VAR):
        TronProvider.from_env(environ, transport=FakeTransport({}))


def test_no_endpoint_is_hard_coded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(RPC_URL_ENV_VAR, raising=False)

    with pytest.raises(ProviderConfigurationError):
        TronProvider.from_env()


@pytest.mark.parametrize(
    "rpc_url",
    [
        f"file:///etc/{SECRET}",
        f"ftp://tron.example.invalid/{SECRET}",
        f"tron.example.invalid/{SECRET}",
        f"https:///{SECRET}",
        f"https://tron.example.invalid/?apikey={SECRET}",
        f"https://tron.example.invalid/#{SECRET}",
    ],
)
def test_invalid_rpc_url_is_rejected_without_echoing_it(rpc_url: str) -> None:
    with pytest.raises(ProviderConfigurationError) as exc_info:
        TronProvider(rpc_url, transport=FakeTransport({}))

    assert SECRET not in str(exc_info.value)


@pytest.mark.parametrize(
    "api_key",
    [f"{SECRET} x", f"{SECRET}\r\nX-Injected: 1", f"{SECRET}é", "k" * 257, ""],
)
def test_invalid_api_key_is_rejected_without_echoing_it(api_key: str) -> None:
    with pytest.raises(ProviderConfigurationError) as exc_info:
        TronProvider(BASE_URL, api_key=api_key, transport=FakeTransport({}))

    assert SECRET not in str(exc_info.value)


def test_trailing_slash_and_path_prefix_are_handled() -> None:
    transport = FakeTransport({})

    TronProvider(BASE_URL + "/", transport=transport).get_transaction(TX_HASH)

    assert transport.calls[0]["url"] == BASE_URL + GET_TRANSACTION_PATH


@pytest.mark.parametrize("timeout", [0, -1.0])
def test_non_positive_timeout_is_rejected(timeout: float) -> None:
    with pytest.raises(ProviderConfigurationError):
        TronProvider(BASE_URL, transport=FakeTransport({}), timeout=timeout)


def test_timeout_is_passed_to_transport() -> None:
    transport = FakeTransport(transfer_tx())

    make_provider(transport, timeout=2.5).get_transaction(TX_HASH)

    assert {call["timeout"] for call in transport.calls} == {2.5}


# --- Secret non-disclosure --------------------------------------------------


def test_repr_does_not_expose_url_or_api_key() -> None:
    provider = make_provider(FakeTransport({}), api_key=API_KEY)

    assert SECRET not in repr(provider)
    assert API_KEY not in repr(provider)


def _failing_transports() -> list[FakeTransport]:
    api_error = FakeTransport(transfer_tx())
    api_error.responses[GET_TRANSACTION_PATH] = {"Error": f"bad key {API_KEY} {BASE_URL}"}
    return [
        api_error,
        FakeTransport(_with(transfer_tx(), txID=OTHER_HASH)),
        FakeTransport(transfer_tx(), info={}),
        FakeTransport(_with(transfer_tx(), ret=[{"contractRet": "UNKNOWN"}])),
        FakeTransport(
            _set_contract(transfer_tx(), [{"type": "TransferAssetContract", "parameter": {}}])
        ),
    ]


@pytest.mark.parametrize(
    "transport",
    _failing_transports(),
    ids=["api-error", "malformed", "receipt-unavailable", "unknown-result", "unsupported"],
)
def test_provider_errors_do_not_expose_secrets(transport: FakeTransport) -> None:
    provider = make_provider(transport, api_key=API_KEY)

    with pytest.raises(ProviderError) as exc_info:
        provider.get_transaction(TX_HASH)

    for secret in (SECRET, API_KEY):
        assert secret not in str(exc_info.value)
        assert secret not in repr(exc_info.value)


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
        self.requests.append(request)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return _FakeResponse(self.outcome)


def test_urllib_transport_sends_api_key_header_and_hides_it_on_http_429() -> None:
    transport = UrllibTransport()
    opener = _FakeOpener(
        urllib.error.HTTPError(BASE_URL, 429, f"rate limited {API_KEY}", {}, None)  # type: ignore[arg-type]
    )
    transport._opener = opener  # type: ignore[assignment]
    provider = TronProvider(BASE_URL, api_key=API_KEY, transport=transport)

    with pytest.raises(ProviderUnavailableError, match="HTTP 429") as exc_info:
        provider.get_transaction(TX_HASH)

    request = opener.requests[0]
    assert request.get_header(API_KEY_HEADER.capitalize()) == API_KEY
    assert request.get_header("Content-type") == "application/json"
    assert request.full_url == BASE_URL + GET_TRANSACTION_PATH
    for secret in (SECRET, API_KEY):
        assert secret not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


@pytest.mark.parametrize("body", [b"", b"   ", b"<html>"], ids=["empty", "blank", "html"])
def test_urllib_transport_empty_or_invalid_body_is_malformed(body: bytes) -> None:
    transport = UrllibTransport()
    transport._opener = _FakeOpener(body)  # type: ignore[assignment]

    with pytest.raises(MalformedResponseError):
        TronProvider(BASE_URL, transport=transport).get_transaction(TX_HASH)


# --- Normalized model -------------------------------------------------------


def test_unconfirmed_status_cannot_carry_block_data() -> None:
    with pytest.raises(ValidationError):
        NormalizedTransaction(
            network="tron",
            tx_hash=TX_HASH,
            status="unconfirmed",
            from_address=SENDER,
            native_value_atomic=0,
            native_unit="sun",
            block_number=1,
            block_timestamp=1,
        )


def test_unconfirmed_status_requires_sender_and_value() -> None:
    with pytest.raises(ValidationError):
        NormalizedTransaction(network="tron", tx_hash=TX_HASH, status="unconfirmed")


def test_tron_transaction_cannot_use_wei() -> None:
    with pytest.raises(ValidationError):
        NormalizedTransaction(
            network="tron",
            tx_hash=TX_HASH,
            status="unconfirmed",
            from_address=SENDER,
            native_value_atomic=0,
            native_unit="wei",
        )
