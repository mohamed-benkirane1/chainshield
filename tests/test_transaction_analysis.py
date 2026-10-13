import copy
import json
import socket
from typing import Any

import base58
import pytest
from pydantic import ValidationError

from app.domain.analysis_input import Network
from app.domain.token_transfer import MAX_UINT256, NormalizedTokenTransfer
from app.providers.base import (
    ChainMismatchError,
    ExecutionResultUnknownError,
    NativeUnit,
    NormalizedTransaction,
    ProviderConfigurationError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    ReceiptUnavailableError,
    RpcError,
    TransactionNotFoundError,
    TransactionPendingError,
    TransactionStatus,
    TransactionUnconfirmedError,
)
from app.providers.ethereum import ERC20_TRANSFER_TOPIC, EthereumProvider
from app.providers.tron import (
    GET_SOLID_TRANSACTION_INFO_PATH,
    GET_SOLID_TRANSACTION_PATH,
    GET_TRANSACTION_PATH,
    TRC20_TRANSFER_TOPIC,
    TronProvider,
)
from app.services.transaction_analysis import (
    InconsistentAnalysisError,
    TransactionAnalysisService,
    TransactionInspection,
    UsdtTransferProvider,
)

ETH_HASH = "0x" + "ab" * 32
ETH_OTHER_HASH = "0x" + "ef" * 32
TRON_HASH = "cd" * 32

ETH_USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
ETH_ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
ETH_BOB = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
ETH_CAROL = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"

TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRON_ALICE = base58.b58encode_check(b"\x41" + bytes(range(1, 21))).decode()
TRON_BOB = base58.b58encode_check(b"\x41" + bytes(range(21, 41))).decode()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("tests must not open network connections")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


# --- Builders ----------------------------------------------------------------


def eth_tx(status: TransactionStatus = TransactionStatus.SUCCESS, **overrides: Any):
    mined = status in (TransactionStatus.SUCCESS, TransactionStatus.REVERTED)
    fields: dict[str, Any] = {
        "network": Network.ETHEREUM,
        "tx_hash": ETH_HASH,
        "status": status,
    }
    if status is not TransactionStatus.NOT_FOUND:
        fields.update(
            from_address=ETH_ALICE,
            to_address=ETH_USDT,
            native_value_atomic=0,
            native_unit=NativeUnit.WEI,
        )
    if mined:
        fields.update(block_number=19_000_000, block_timestamp=1_705_000_000)
    fields.update(overrides)
    return NormalizedTransaction(**fields)


def tron_tx(status: TransactionStatus = TransactionStatus.SUCCESS):
    mined = status in (TransactionStatus.SUCCESS, TransactionStatus.REVERTED)
    fields: dict[str, Any] = {"network": Network.TRON, "tx_hash": TRON_HASH, "status": status}
    if status is not TransactionStatus.NOT_FOUND:
        fields.update(
            from_address=TRON_ALICE,
            to_address=TRON_USDT,
            native_value_atomic=0,
            native_unit=NativeUnit.SUN,
        )
    if mined:
        fields.update(block_number=60_000_000, block_timestamp=1_705_000_002)
    return NormalizedTransaction(**fields)


def eth_transfer(sender: str = ETH_ALICE, recipient: str = ETH_BOB, amount: int = 35_000_000,
                 log_index: int = 0, tx_hash: str = ETH_HASH) -> NormalizedTokenTransfer:
    return NormalizedTokenTransfer(
        network=Network.ETHEREUM,
        tx_hash=tx_hash,
        token_symbol="USDT",
        token_contract=ETH_USDT,
        from_address=sender,
        to_address=recipient,
        amount_atomic=amount,
        decimals=6,
        log_index=log_index,
    )


def tron_transfer(amount: int = 35_000_000) -> NormalizedTokenTransfer:
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


Answer = Any  # a value to return, an exception to raise, or a callable


class ScriptedProvider:
    """Replays scripted answers, one per call, without any network access."""

    def __init__(self, network: Network, transactions: list[Answer], transfers: list[Answer]):
        self.network = network
        self._transactions = list(transactions)
        self._transfers = list(transfers)
        self.calls: list[tuple[str, str]] = []

    @staticmethod
    def _answer(queue: list[Answer]) -> Any:
        answer = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(answer, BaseException):
            raise answer
        return answer() if callable(answer) else answer

    def get_transaction(self, tx_hash: str) -> NormalizedTransaction:
        self.calls.append(("get_transaction", tx_hash))
        return self._answer(self._transactions)

    def get_usdt_transfers(self, tx_hash: str) -> list[NormalizedTokenTransfer]:
        self.calls.append(("get_usdt_transfers", tx_hash))
        return self._answer(self._transfers)

    @property
    def methods(self) -> list[str]:
        return [method for method, _ in self.calls]


def service(*providers: UsdtTransferProvider) -> TransactionAnalysisService:
    return TransactionAnalysisService(providers)


def eth_provider(transactions: list[Answer], transfers: list[Answer] | None = None):
    return ScriptedProvider(Network.ETHEREUM, transactions, transfers or [[]])


# --- Final transactions ------------------------------------------------------


def test_ethereum_success_with_usdt() -> None:
    provider = eth_provider([eth_tx()], [[eth_transfer()]])

    result = service(provider).inspect_transaction(Network.ETHEREUM, ETH_HASH)

    assert result.network is Network.ETHEREUM
    assert result.tx_hash == ETH_HASH
    assert result.transaction == eth_tx()
    assert result.usdt_transfers == (eth_transfer(),)
    assert provider.methods == ["get_transaction", "get_usdt_transfers", "get_transaction"]


def test_tron_success_with_usdt() -> None:
    provider = ScriptedProvider(Network.TRON, [tron_tx()], [[tron_transfer()]])

    result = service(provider).inspect_transaction("tron", TRON_HASH)

    assert result.transaction.status is TransactionStatus.SUCCESS
    assert result.usdt_transfers == (tron_transfer(),)
    assert result.usdt_transfers[0].format_amount() == "35.000000"


def test_success_without_usdt_event_is_an_empty_tuple_not_none() -> None:
    result = service(eth_provider([eth_tx()], [[]])).inspect_transaction("ethereum", ETH_HASH)

    assert result.usdt_transfers == ()
    assert result.usdt_transfers is not None


def test_multiple_transfers_keep_their_order() -> None:
    transfers = [
        eth_transfer(ETH_ALICE, ETH_BOB, 105_000_000, 171),
        eth_transfer(ETH_BOB, ETH_CAROL, 104_685_000, 172),
        eth_transfer(ETH_CAROL, ETH_ALICE, 104_685_000, 174),
    ]

    result = service(eth_provider([eth_tx()], [transfers])).inspect_transaction(
        "ethereum", ETH_HASH
    )

    assert result.usdt_transfers == tuple(transfers)
    assert [t.log_index for t in result.usdt_transfers] == [171, 172, 174]


def test_reverted_transaction_has_empty_transfers() -> None:
    provider = eth_provider([eth_tx(TransactionStatus.REVERTED)], [[]])

    result = service(provider).inspect_transaction("ethereum", ETH_HASH)

    assert result.transaction.status is TransactionStatus.REVERTED
    assert result.usdt_transfers == ()


# --- Non-final transactions --------------------------------------------------


@pytest.mark.parametrize(
    ("network", "transaction", "tx_hash"),
    [
        (Network.ETHEREUM, eth_tx(TransactionStatus.PENDING), ETH_HASH),
        (Network.TRON, tron_tx(TransactionStatus.UNCONFIRMED), TRON_HASH),
        (Network.ETHEREUM, eth_tx(TransactionStatus.NOT_FOUND), ETH_HASH),
        (Network.TRON, tron_tx(TransactionStatus.NOT_FOUND), TRON_HASH),
    ],
    ids=["ethereum-pending", "tron-unconfirmed", "ethereum-not-found", "tron-not-found"],
)
def test_non_final_transaction_has_unknown_transfers(
    network: Network, transaction: NormalizedTransaction, tx_hash: str
) -> None:
    provider = ScriptedProvider(network, [transaction], [AssertionError("not called")])

    result = service(provider).inspect_transaction(network, tx_hash)

    assert result.transaction == transaction
    assert result.usdt_transfers is None
    assert provider.methods == ["get_transaction"]


def test_every_status_is_preserved() -> None:
    seen = set()
    for status in TransactionStatus:
        network = Network.TRON if status is TransactionStatus.UNCONFIRMED else Network.ETHEREUM
        tx = tron_tx(status) if network is Network.TRON else eth_tx(status)
        tx_hash = TRON_HASH if network is Network.TRON else ETH_HASH
        provider = ScriptedProvider(network, [tx], [[]])
        seen.add(service(provider).inspect_transaction(network, tx_hash).transaction.status)

    assert seen == set(TransactionStatus)


# --- Input validation and configuration --------------------------------------


@pytest.mark.parametrize("network", ["bitcoin", "Ethereum", "", "TRON"])
def test_invalid_network_is_rejected(network: str) -> None:
    with pytest.raises(ValueError):
        service(eth_provider([eth_tx()])).inspect_transaction(network, ETH_HASH)


@pytest.mark.parametrize(
    ("network", "tx_hash"),
    [
        ("ethereum", ""),
        ("ethereum", "ab" * 32),  # TRON format on Ethereum
        ("ethereum", "0x1234"),
        ("tron", ETH_HASH),  # Ethereum format on TRON
        ("tron", "zz" * 32),
    ],
)
def test_invalid_hash_is_rejected_before_any_provider_call(network: str, tx_hash: str) -> None:
    eth = eth_provider([eth_tx()])
    tron = ScriptedProvider(Network.TRON, [tron_tx()], [[]])

    with pytest.raises(ValueError):
        service(eth, tron).inspect_transaction(network, tx_hash)
    assert eth.calls == [] and tron.calls == []


def test_hash_is_normalized_before_the_provider_call() -> None:
    provider = eth_provider([eth_tx()], [[]])

    result = service(provider).inspect_transaction("ethereum", "0x" + ETH_HASH[2:].upper())

    assert result.tx_hash == ETH_HASH
    assert {tx_hash for _, tx_hash in provider.calls} == {ETH_HASH}


def test_unconfigured_network_is_a_configuration_error() -> None:
    with pytest.raises(ProviderConfigurationError, match="tron"):
        service(eth_provider([eth_tx()])).inspect_transaction("tron", TRON_HASH)


def test_no_provider_at_all() -> None:
    with pytest.raises(ProviderConfigurationError):
        service().inspect_transaction("ethereum", ETH_HASH)


def test_duplicate_providers_for_one_network_are_rejected() -> None:
    with pytest.raises(ProviderConfigurationError, match="several"):
        service(eth_provider([eth_tx()]), eth_provider([eth_tx()]))


# --- Inconsistencies ---------------------------------------------------------


@pytest.mark.parametrize(
    "transaction",
    [
        eth_tx(tx_hash=ETH_OTHER_HASH),
        tron_tx(),  # wrong network
    ],
    ids=["other-hash", "other-network"],
)
def test_provider_returning_another_transaction_is_inconsistent(
    transaction: NormalizedTransaction,
) -> None:
    with pytest.raises(InconsistentAnalysisError, match="another transaction"):
        service(eth_provider([transaction])).inspect_transaction("ethereum", ETH_HASH)


@pytest.mark.parametrize(
    "transfer",
    [eth_transfer(tx_hash=ETH_OTHER_HASH), tron_transfer()],
    ids=["other-hash", "other-network"],
)
def test_transfer_not_matching_the_transaction_is_inconsistent(
    transfer: NormalizedTokenTransfer,
) -> None:
    with pytest.raises(InconsistentAnalysisError, match="transfer does not match"):
        service(eth_provider([eth_tx()], [[transfer]])).inspect_transaction(
            "ethereum", ETH_HASH
        )


def test_reverted_transaction_with_transfers_is_inconsistent() -> None:
    provider = eth_provider([eth_tx(TransactionStatus.REVERTED)], [[eth_transfer()]])

    with pytest.raises(InconsistentAnalysisError, match="reverted"):
        service(provider).inspect_transaction("ethereum", ETH_HASH)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (TransactionStatus.SUCCESS, TransactionStatus.REVERTED),  # reorg
        (TransactionStatus.REVERTED, TransactionStatus.SUCCESS),
        (TransactionStatus.SUCCESS, TransactionStatus.PENDING),
        (TransactionStatus.SUCCESS, TransactionStatus.NOT_FOUND),
    ],
)
def test_state_change_between_reads_is_detected(
    first: TransactionStatus, second: TransactionStatus
) -> None:
    provider = eth_provider([eth_tx(first), eth_tx(second)], [[]])

    with pytest.raises(InconsistentAnalysisError, match="changed"):
        service(provider).inspect_transaction("ethereum", ETH_HASH)


def test_block_change_between_reads_is_detected() -> None:
    provider = eth_provider([eth_tx(), eth_tx(block_number=19_000_001)], [[]])

    with pytest.raises(InconsistentAnalysisError, match="changed"):
        service(provider).inspect_transaction("ethereum", ETH_HASH)


@pytest.mark.parametrize(
    "error",
    [
        TransactionNotFoundError("transaction is unknown to the node"),
        TransactionPendingError("transaction is not yet included in a block"),
        TransactionUnconfirmedError("transaction is not solidified yet"),
    ],
)
def test_transaction_no_longer_final_while_reading_transfers(error: Exception) -> None:
    provider = eth_provider([eth_tx()], [error])

    with pytest.raises(InconsistentAnalysisError, match="no longer final") as exc_info:
        service(provider).inspect_transaction("ethereum", ETH_HASH)
    assert exc_info.value.__cause__ is error


# --- Error propagation --------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        RpcError("eth_getTransactionByHash", -32000),
        ProviderTimeoutError("RPC request timed out"),
        ProviderUnavailableError("RPC endpoint returned HTTP 429"),
        ChainMismatchError("expected Ethereum mainnet"),
    ],
)
def test_errors_reading_the_transaction_propagate_unchanged(error: Exception) -> None:
    with pytest.raises(type(error)) as exc_info:
        service(eth_provider([error])).inspect_transaction("ethereum", ETH_HASH)
    assert exc_info.value is error


@pytest.mark.parametrize(
    "error",
    [
        RpcError("eth_getTransactionReceipt", -32000),
        ProviderTimeoutError("RPC request timed out"),
        ReceiptUnavailableError("retry later"),
        ExecutionResultUnknownError("no status"),
    ],
)
def test_errors_reading_transfers_propagate_unchanged(error: Exception) -> None:
    with pytest.raises(type(error)) as exc_info:
        service(eth_provider([eth_tx()], [error])).inspect_transaction("ethereum", ETH_HASH)
    assert exc_info.value is error


def test_error_on_confirmation_read_propagates() -> None:
    error = ProviderTimeoutError("RPC request timed out")
    provider = eth_provider([eth_tx(), error], [[]])

    with pytest.raises(ProviderTimeoutError):
        service(provider).inspect_transaction("ethereum", ETH_HASH)


# --- Result model -------------------------------------------------------------


def test_inspection_is_immutable() -> None:
    result = service(eth_provider([eth_tx()], [[eth_transfer()]])).inspect_transaction(
        "ethereum", ETH_HASH
    )

    with pytest.raises(ValidationError):
        result.usdt_transfers = ()  # type: ignore[misc]
    with pytest.raises(AttributeError):
        result.usdt_transfers.append(eth_transfer())  # type: ignore[union-attr]
    with pytest.raises(ValidationError):
        result.transaction.status = TransactionStatus.REVERTED  # type: ignore[misc]


def test_large_amounts_are_preserved_exactly() -> None:
    result = service(
        eth_provider([eth_tx()], [[eth_transfer(amount=MAX_UINT256)]])
    ).inspect_transaction("ethereum", ETH_HASH)

    dumped = result.model_dump_json()

    assert result.usdt_transfers[0].amount_atomic == 2**256 - 1
    assert json.loads(dumped)["usdt_transfers"][0]["amount_atomic"] == MAX_UINT256
    assert TransactionInspection.model_validate_json(dumped) == result


@pytest.mark.parametrize(
    "fields",
    [
        {"transaction": eth_tx(TransactionStatus.PENDING), "usdt_transfers": ()},
        {"transaction": eth_tx(), "usdt_transfers": None},
        {"transaction": eth_tx(TransactionStatus.REVERTED), "usdt_transfers": (eth_transfer(),)},
        {"transaction": eth_tx(), "usdt_transfers": (tron_transfer(),)},
        {"transaction": eth_tx(tx_hash=ETH_OTHER_HASH), "usdt_transfers": ()},
        {"transaction": eth_tx(), "usdt_transfers": (), "extra": 1},
    ],
    ids=["pending-with-list", "final-without-list", "reverted-with-transfer",
         "foreign-transfer", "foreign-transaction", "extra-field"],
)
def test_inspection_model_rejects_inconsistent_data(fields: dict) -> None:
    with pytest.raises(ValidationError):
        TransactionInspection(network=Network.ETHEREUM, tx_hash=ETH_HASH, **fields)


# --- Real providers behind the service (simulated transports) -----------------


class EthTransport:
    def __init__(self) -> None:
        log = {
            "address": ETH_USDT.lower(),
            "topics": [
                ERC20_TRANSFER_TOPIC,
                "0x" + "0" * 24 + ETH_ALICE[2:].lower(),
                "0x" + "0" * 24 + ETH_BOB[2:].lower(),
            ],
            "data": "0x" + format(625_000_000, "064x"),
            "blockNumber": hex(19_000_000),
            "blockHash": "0x" + "cd" * 32,
            "transactionHash": ETH_HASH,
            "logIndex": hex(316),
            "removed": False,
        }
        self.results: dict[str, Any] = {
            "eth_chainId": "0x1",
            "eth_getTransactionByHash": {
                "hash": ETH_HASH,
                "from": ETH_ALICE.lower(),
                "to": ETH_USDT.lower(),
                "value": "0x0",
                "blockNumber": hex(19_000_000),
                "blockHash": "0x" + "cd" * 32,
            },
            "eth_getTransactionReceipt": {
                "transactionHash": ETH_HASH,
                "blockHash": "0x" + "cd" * 32,
                "blockNumber": hex(19_000_000),
                "status": "0x1",
                "logs": [log],
            },
            "eth_getBlockByNumber": {
                "hash": "0x" + "cd" * 32,
                "number": hex(19_000_000),
                "timestamp": hex(1_705_000_000),
            },
        }
        self.methods: list[str] = []

    def post_json(self, url: str, payload: dict[str, Any], timeout: float) -> Any:
        self.methods.append(payload["method"])
        return {"jsonrpc": "2.0", "id": payload["id"], "result": self.results[payload["method"]]}


class TronTransport:
    def __init__(self) -> None:
        def body(address: str) -> str:
            return base58.b58decode_check(address)[1:].hex()

        tx = {
            "ret": [{"contractRet": "SUCCESS"}],
            "txID": TRON_HASH,
            "raw_data": {
                "contract": [
                    {
                        "parameter": {
                            "value": {
                                "owner_address": "41" + body(TRON_ALICE),
                                "contract_address": "41" + body(TRON_USDT),
                                "data": "a9059cbb",
                            },
                            "type_url": "type.googleapis.com/protocol.TriggerSmartContract",
                        },
                        "type": "TriggerSmartContract",
                    }
                ]
            },
        }
        info = {
            "id": TRON_HASH,
            "blockNumber": 60_000_000,
            "blockTimeStamp": 1_705_000_002_000,
            "receipt": {"result": "SUCCESS"},
            "log": [
                {
                    "address": body(TRON_USDT),
                    "topics": [
                        TRC20_TRANSFER_TOPIC,
                        "0" * 24 + body(TRON_ALICE),
                        "0" * 24 + body(TRON_BOB),
                    ],
                    "data": format(10_000_000_000, "064x"),
                }
            ],
        }
        self.responses = {
            GET_TRANSACTION_PATH: tx,
            GET_SOLID_TRANSACTION_PATH: copy.deepcopy(tx),
            GET_SOLID_TRANSACTION_INFO_PATH: info,
        }
        self.paths: list[str] = []

    def post_json(self, url: str, payload: dict[str, Any], timeout: float,
                  headers: dict[str, str] | None = None) -> Any:
        path = next(p for p in self.responses if url.endswith(p))
        self.paths.append(path)
        return copy.deepcopy(self.responses[path])


def test_real_providers_satisfy_the_service_contract() -> None:
    eth_transport, tron_transport = EthTransport(), TronTransport()
    analysis = service(
        EthereumProvider("https://eth.example.invalid", transport=eth_transport),
        TronProvider("https://tron.example.invalid", transport=tron_transport),
    )

    eth = analysis.inspect_transaction("ethereum", ETH_HASH)
    tron = analysis.inspect_transaction("tron", TRON_HASH)

    assert eth.transaction.status is TransactionStatus.SUCCESS
    assert eth.usdt_transfers == (eth_transfer(amount=625_000_000, log_index=316),)
    assert tron.transaction.status is TransactionStatus.SUCCESS
    assert [t.amount_atomic for t in tron.usdt_transfers] == [10_000_000_000]
    assert tron.usdt_transfers[0].log_index is None
    # chain ID once, then tx+receipt+block / tx+receipt / tx+receipt+block
    assert eth_transport.methods.count("eth_chainId") == 1
    assert len(tron_transport.paths) == 9


def test_real_tron_provider_unconfirmed_through_service() -> None:
    transport = TronTransport()
    transport.responses[GET_SOLID_TRANSACTION_PATH] = {}

    result = service(
        TronProvider("https://tron.example.invalid", transport=transport)
    ).inspect_transaction("tron", TRON_HASH)

    assert result.transaction.status is TransactionStatus.UNCONFIRMED
    assert result.usdt_transfers is None
    assert len(transport.paths) == 2


# --- No network ---------------------------------------------------------------


def test_default_transports_cannot_reach_network_in_tests() -> None:
    analysis = service(EthereumProvider("https://eth.example.invalid"))

    with pytest.raises(Exception) as exc_info:
        analysis.inspect_transaction("ethereum", ETH_HASH)
    assert isinstance(exc_info.value, (AssertionError, ProviderUnavailableError))


def test_scripted_provider_is_used_without_io() -> None:
    calls: list[str] = []

    def marker() -> NormalizedTransaction:
        calls.append("tx")
        return eth_tx()

    service(eth_provider([marker], [[]])).inspect_transaction("ethereum", ETH_HASH)

    assert calls == ["tx", "tx"]
