"""Multi-Address Investigation Dossier v1, with simulated-node HTTP tests."""

import json
import socket
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from eth_utils import to_checksum_address
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.providers.ethereum as ethereum_module
import app.providers.tron as tron_module
import app.services.investigation_dossier as dossier_module
from app.api.auth import API_TOKEN_ENV_VAR
from app.api.body_limit import MAX_BODY_BYTES
from app.api.concurrency_limit import ConcurrencyLimiter, get_concurrency_limiter
from app.api.dossier_schemas import InvestigationDossierResponse
from app.api.rate_limit import RateLimitExceededError, SlidingWindowRateLimiter, get_rate_limiter
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
from app.risk.address_evidence import ObservedRole
from app.services.address_investigation import (
    AddressPresence,
    TransferCoverage,
    build_address_investigation,
)
from app.services.investigation_dossier import (
    InvestigationDossier,
    SelectedAddressRelationship,
    build_investigation_dossier,
    investigate_dossier,
)
from app.services.transaction_analysis import TransactionInspection
from test_e2e_api import (  # noqa: E402
    ALICE,
    BOB,
    CAROL,
    DAVE,
    ETH_RPC_URL,
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

URL = "/api/v1/investigations/dossier"
INSPECT = "/api/v1/transactions/inspect"
ASSESS = "/api/v1/transactions/assess"
ADDRESS = "/api/v1/addresses/investigate"
GRAPH = "/api/v1/relationships/usdt"
PATHS = "/api/v1/relationships/paths"
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
    def __call__(self) -> float:
        return 1_000.0


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


def dossier(
    client: TestClient, network: str, addresses: list[str], hashes: list[str]
) -> dict[str, Any]:
    response = call(client, {
        "network": network, "addresses": addresses, "tx_hashes": hashes
    })
    assert response.status_code == 200, response.text
    data = response.json()
    InvestigationDossierResponse.model_validate(data)
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


# --- Pure dossier construction ------------------------------------------------------------------

H1, H2, H3, H4 = ("0x" + character * 64 for character in "1234")
EVE = to_checksum_address("0x" + "44" * 20)
USDT = get_usdt_contract(Network.ETHEREUM).contract_address


def transfer(
    tx_hash: str, sender: str, recipient: str, amount: int, log_index: int
) -> NormalizedTokenTransfer:
    return NormalizedTokenTransfer(
        network=Network.ETHEREUM,
        tx_hash=tx_hash,
        token_symbol="USDT",
        token_contract=USDT,
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
    sender: str | None = ALICE,
    recipient: str | None = BOB,
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
            from_address=sender if found else None,
            to_address=recipient if found else None,
            native_value_atomic=0 if found else None,
            native_unit=NativeUnit.WEI if found else None,
            block_number=1 if final else None,
            block_timestamp=2 if final else None,
        ),
        usdt_transfers=transfers if final else None,
    )


def rich_inspection() -> TransactionInspection:
    return inspection(H1, recipient=CAROL, transfers=(
        transfer(H1, ALICE, BOB, MAX_UINT256, 10),
        transfer(H1, ALICE, BOB, MAX_UINT256, 11),
        transfer(H1, BOB, ALICE, 7, 12),
        transfer(H1, CAROL, CAROL, 1, 13),
        transfer(H1, ALICE, DAVE, 9, 14),
    ))


def test_dossier_reuses_exact_address_findings_and_graph_relationships() -> None:
    addresses = [CAROL, ALICE, BOB]
    snapshot = [rich_inspection()]

    result = build_investigation_dossier(Network.ETHEREUM, addresses, snapshot)

    assert result.addresses == tuple(addresses)
    assert result.transfer_coverage is TransferCoverage.COMPLETE
    assert result.address_findings == tuple(
        build_address_investigation(Network.ETHEREUM, address, snapshot)
        for address in addresses
    )
    relationships = result.selected_address_relationships or ()
    assert [(item.from_address, item.to_address) for item in relationships] == sorted([
        (ALICE, BOB), (BOB, ALICE), (CAROL, CAROL)
    ])
    repeated = next(item for item in relationships if (item.from_address, item.to_address) == (ALICE, BOB))
    assert repeated == SelectedAddressRelationship(
        from_address=ALICE,
        to_address=BOB,
        self_transfer=False,
        event_count=2,
        total_amount_atomic=2 * MAX_UINT256,
        tx_hashes=(H1,),
        event_ids=(f"ethereum:{H1}:0", f"ethereum:{H1}:1"),
    )
    self_loop = next(item for item in relationships if item.from_address == CAROL)
    assert self_loop.self_transfer is True and self_loop.event_ids == (f"ethereum:{H1}:3",)
    assert all(item.to_address != DAVE for item in relationships)
    assert result.observed_selected_relationship_count == 3
    assert "relationship_graph" not in result.model_dump()


def test_external_counterparty_remains_in_summary_but_not_selected_relationships() -> None:
    result = build_investigation_dossier(
        Network.ETHEREUM, [ALICE, BOB], [rich_inspection()]
    )

    alice = result.address_findings[0]
    assert DAVE in (alice.summary.counterparties or ())
    assert all(
        DAVE not in (relationship.from_address, relationship.to_address)
        for relationship in result.selected_address_relationships or ()
    )


def test_native_roles_remain_distinct_from_usdt_events() -> None:
    result = build_investigation_dossier(
        Network.ETHEREUM,
        [ALICE, BOB],
        [inspection(H1, sender=ALICE, recipient=BOB)],
    )

    alice, bob = result.address_findings
    assert alice.transactions[0].observed_roles == (ObservedRole.TRANSACTION_SENDER,)
    assert bob.transactions[0].observed_roles == (ObservedRole.TRANSACTION_RECIPIENT,)
    assert alice.transactions[0].usdt_observations == ()
    assert result.selected_address_relationships == ()
    assert result.observed_selected_relationship_count == 0


def test_partial_coverage_keeps_only_known_relations() -> None:
    result = build_investigation_dossier(
        Network.ETHEREUM,
        [ALICE, BOB],
        [
            inspection(H1, transfers=(transfer(H1, ALICE, BOB, 5, 1),)),
            inspection(H2, status=TransactionStatus.PENDING),
        ],
    )

    assert result.transfer_coverage is TransferCoverage.PARTIAL
    assert result.observed_selected_relationship_count == 1
    assert (result.selected_address_relationships or ())[0].total_amount_atomic == 5
    assert all(finding.summary.transfer_coverage is TransferCoverage.PARTIAL
               for finding in result.address_findings)


def test_partial_known_empty_relations_are_an_empty_collection() -> None:
    result = build_investigation_dossier(
        Network.ETHEREUM,
        [ALICE, BOB],
        [inspection(H1), inspection(H2, status=TransactionStatus.NOT_FOUND)],
    )

    assert result.transfer_coverage is TransferCoverage.PARTIAL
    assert result.selected_address_relationships == ()
    assert result.observed_selected_relationship_count == 0


def test_no_coverage_keeps_unknowns_null_never_zero() -> None:
    result = build_investigation_dossier(
        Network.ETHEREUM,
        [ALICE, BOB],
        [
            inspection(H1, status=TransactionStatus.PENDING),
            inspection(H2, status=TransactionStatus.NOT_FOUND),
        ],
    )

    assert result.transfer_coverage is TransferCoverage.NONE
    assert result.selected_address_relationships is None
    assert result.observed_selected_relationship_count is None
    for finding in result.address_findings:
        assert finding.summary.incoming_usdt_event_count is None
        assert finding.summary.known_incoming_usdt_amount_atomic is None


def test_complete_without_relation_uses_empty_and_exact_zero() -> None:
    domain = build_investigation_dossier(
        Network.ETHEREUM, [ALICE, BOB], [inspection(H1)]
    )
    data = InvestigationDossierResponse.from_domain(domain).model_dump(mode="json")

    assert data["transfer_coverage"] == "complete"
    assert data["selected_address_relationships"] == []
    assert data["observed_selected_relationship_count"] == 0
    assert all(finding["summary"]["known_incoming_usdt_amount_atomic"] == "0"
               for finding in data["address_findings"])


def test_addresses_are_canonicalized_and_request_order_is_preserved() -> None:
    result = build_investigation_dossier(
        Network.ETHEREUM, [BOB.lower(), ALICE.lower()], [inspection(H1)]
    )

    assert result.addresses == (BOB, ALICE)
    assert tuple(finding.address for finding in result.address_findings) == (BOB, ALICE)


def test_builders_are_reused_once_per_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph_calls = 0
    address_calls: list[str] = []
    real_graph = dossier_module.build_usdt_relationship_graph
    real_address = dossier_module.build_address_investigation

    def graph_spy(*args: Any, **kwargs: Any):
        nonlocal graph_calls
        graph_calls += 1
        return real_graph(*args, **kwargs)

    def address_spy(network: Network, address: str, inspections: Any):
        address_calls.append(address)
        return real_address(network, address, inspections)

    monkeypatch.setattr(dossier_module, "build_usdt_relationship_graph", graph_spy)
    monkeypatch.setattr(dossier_module, "build_address_investigation", address_spy)

    build_investigation_dossier(
        Network.ETHEREUM, [ALICE, BOB, CAROL], [rich_inspection()]
    )

    assert graph_calls == 1
    assert address_calls == [ALICE, BOB, CAROL]


class RecordingInspector:
    def __init__(self, fail_on: str | None = None) -> None:
        self.calls: list[str] = []
        self.fail_on = fail_on

    def inspect_transaction(self, network: Network, tx_hash: str) -> TransactionInspection:
        self.calls.append(tx_hash)
        if tx_hash == self.fail_on:
            raise ProviderTimeoutError("private provider detail")
        return inspection(tx_hash)


def test_five_addresses_still_inspect_each_transaction_exactly_once() -> None:
    service = RecordingInspector()

    result = investigate_dossier(
        service, Network.ETHEREUM, [ALICE, BOB, CAROL, DAVE, EVE], [H1, H2, H3]
    )

    assert service.calls == [H1, H2, H3]
    assert len(result.address_findings) == 5


def test_service_is_fail_fast_without_inspecting_later_hashes() -> None:
    service = RecordingInspector(fail_on=H2)

    with pytest.raises(ProviderTimeoutError):
        investigate_dossier(service, Network.ETHEREUM, [ALICE, BOB], [H1, H2, H3])
    assert service.calls == [H1, H2]


@pytest.mark.parametrize("addresses, hashes", [
    ([ALICE], [H1]),
    ([ALICE, BOB, CAROL, DAVE, EVE, to_checksum_address("0x" + "55" * 20)], [H1]),
    ([ALICE, ALICE.lower()], [H1]),
    ([ALICE, BOB], []),
    ([ALICE, BOB], [H1, H2, H3, H4]),
    ([ALICE, BOB], [H1, H1.upper().replace("0X", "0x")]),
    ([ALICE, BOB], ["0x12"]),
])
def test_service_rejects_invalid_inputs_before_any_inspection(
    addresses: list[str], hashes: list[str]
) -> None:
    service = RecordingInspector()

    with pytest.raises(ValueError):
        investigate_dossier(service, Network.ETHEREUM, addresses, hashes)
    assert service.calls == []


def test_domain_models_reject_tampered_aggregates_and_provenance() -> None:
    valid = build_investigation_dossier(
        Network.ETHEREUM, [ALICE, BOB], [rich_inspection()]
    )
    relationship = (valid.selected_address_relationships or ())[0]
    common = {**valid.model_dump(), "relationship_graph": valid.relationship_graph}

    with pytest.raises(ValidationError):
        SelectedAddressRelationship(**{
            **relationship.model_dump(), "self_transfer": True
        })
    with pytest.raises(ValidationError):
        InvestigationDossier(**{
            **common,
            "observed_selected_relationship_count": 99,
        })
    tampered = SelectedAddressRelationship(**{
        **relationship.model_dump(), "total_amount_atomic": relationship.total_amount_atomic + 1
    })
    with pytest.raises(ValidationError):
        InvestigationDossier(**{
            **common,
            "selected_address_relationships": (tampered,) + tuple(
                valid.selected_address_relationships or ()
            )[1:],
        })


def test_json_amounts_are_exact_strings_and_numbers_remain_safe() -> None:
    domain = build_investigation_dossier(
        Network.ETHEREUM, [ALICE, BOB], [rich_inspection()]
    )
    data = InvestigationDossierResponse.from_domain(domain).model_dump(mode="json")

    repeated = next(item for item in data["selected_address_relationships"]
                    if item["from_address"] == ALICE and item["to_address"] == BOB)
    assert repeated["total_amount_atomic"] == str(2 * MAX_UINT256)
    assert all(isinstance(number, int) and number <= MAX_SAFE_INTEGER
               for number in walk_numbers(data))


# --- HTTP validation ----------------------------------------------------------------------------

VALID = {
    "network": "ethereum",
    "addresses": [ALICE, BOB],
    "tx_hashes": [USDT_HASH],
}


@pytest.mark.parametrize("body", [
    {},
    {"network": "ethereum", "tx_hashes": [USDT_HASH]},
    {"network": "ethereum", "addresses": [ALICE, BOB]},
    {**VALID, "addresses": [ALICE]},
    {**VALID, "addresses": [ALICE, BOB, CAROL, DAVE, EVE, USDT]},
    {**VALID, "addresses": [ALICE, ALICE.lower()]},
    {**VALID, "addresses": [ALICE, "0x1234"]},
    {**VALID, "addresses": [ALICE, TRON_ALICE]},
    {**VALID, "tx_hashes": []},
    {**VALID, "tx_hashes": [USDT_HASH, SWAP_HASH, NATIVE_HASH, PENDING_HASH]},
    {**VALID, "tx_hashes": [USDT_HASH, USDT_HASH.upper().replace("0X", "0x")]},
    {**VALID, "tx_hashes": ["0x12"]},
    {**VALID, "tx_hashes": [TRC20_HASH]},
    {**VALID, "network": "tron"},
    {**VALID, "network": "bitcoin"},
    {**VALID, "addresses": ALICE},
    {**VALID, "addresses": [ALICE, 123]},
    {**VALID, "extra": True},
    [VALID],
])
def test_invalid_http_input_is_422_without_quota_or_rpc(
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


def test_validation_error_never_echoes_addresses_or_unknown_field(client: TestClient) -> None:
    marker = "0x" + "z" * 40
    response = call(client, {**VALID, "addresses": [ALICE, marker], TOKEN[:8]: 1})

    assert response.status_code == 422
    assert marker not in response.text and TOKEN[:8] not in response.text


# --- End-to-end real services/providers with simulated nodes ------------------------------------


def test_ethereum_dossier_uses_one_inspection_per_hash_for_three_addresses(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_usdt(eth)
    eth_swap(eth)

    data = dossier(
        client, "ethereum", [BOB.lower(), ALICE.lower(), CAROL.lower()],
        [USDT_HASH, SWAP_HASH]
    )

    assert data["addresses"] == [BOB, ALICE, CAROL]
    assert data["sample_scope"] == "supplied_transactions_only"
    assert data["transfer_coverage"] == "complete"
    assert [finding["address"] for finding in data["address_findings"]] == [BOB, ALICE, CAROL]
    assert data["address_findings"][0]["presence"] == "observed"
    relationships = data["selected_address_relationships"]
    assert [(item["from_address"], item["to_address"]) for item in relationships] == sorted([
        (ALICE, BOB), (ALICE, CAROL), (CAROL, BOB), (CAROL, CAROL)
    ])
    assert next(item for item in relationships if item["from_address"] == CAROL
                and item["to_address"] == CAROL)["self_transfer"] is True
    assert data["observed_selected_relationship_count"] == 4
    assert eth.calls.count("eth_getTransactionByHash") == 6  # 3 reads x 2 inspections


def test_tron_dossier_preserves_canonical_relations(
    client: TestClient, tron: TronNode
) -> None:
    tron_usdt(tron)

    data = dossier(
        client, "tron", [TRON_CAROL, TRON_ALICE, TRON_BOB], [TRC20_HASH.upper()]
    )

    assert data["network"] == "tron"
    assert data["addresses"] == [TRON_CAROL, TRON_ALICE, TRON_BOB]
    assert [(item["from_address"], item["to_address"], item["event_ids"])
            for item in data["selected_address_relationships"]] == [
        (TRON_ALICE, TRON_BOB, [f"tron:{TRC20_HASH}:0"]),
        (TRON_BOB, TRON_CAROL, [f"tron:{TRC20_HASH}:1"]),
    ]


def test_http_none_coverage_uses_nulls(client: TestClient, eth: EthereumNode) -> None:
    eth.transactions[PENDING_HASH] = eth_tx(PENDING_HASH, ALICE, BOB, 1, None)

    data = dossier(client, "ethereum", [ALICE, BOB], [PENDING_HASH, UNKNOWN_HASH])

    assert data["transfer_coverage"] == "none"
    assert data["selected_address_relationships"] is None
    assert data["observed_selected_relationship_count"] is None
    assert all(finding["summary"]["counterparties"] is None
               for finding in data["address_findings"])


def test_http_partial_coverage_is_explicit(client: TestClient, tron: TronNode) -> None:
    tron_usdt(tron)
    tron.stores[GET_TRANSACTION_PATH][UNCONFIRMED_HASH] = trc20_call(
        UNCONFIRMED_HASH, TRON_ALICE
    )

    data = dossier(
        client, "tron", [TRON_ALICE, TRON_BOB], [TRC20_HASH, UNCONFIRMED_HASH]
    )

    assert data["transfer_coverage"] == "partial"
    assert data["transactions"][1]["usdt_event_count"] is None
    assert len(data["selected_address_relationships"]) == 1


def test_fail_fast_returns_no_partial_dossier_and_skips_later_hash(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_usdt(eth)
    eth_swap(eth)
    mine(eth, NATIVE_HASH, ALICE, BOB, 1)
    eth.receipts[SWAP_HASH] = None

    response = call(client, {
        **VALID, "tx_hashes": [USDT_HASH, SWAP_HASH, NATIVE_HASH]
    })

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "receipt_unavailable"
    assert "address_findings" not in response.json()
    assert eth.calls.count("eth_getTransactionByHash") == 4


# --- Auth, limits, shared quota and concurrency --------------------------------------------------


def test_bearer_failures_use_no_quota_or_rpc(
    eth: EthereumNode, quota: SlidingWindowRateLimiter, monkeypatch: pytest.MonkeyPatch
) -> None:
    anonymous = TestClient(app)
    for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {TOKEN}"}):
        assert call(anonymous, VALID, headers=headers).status_code == 401
    monkeypatch.delenv(API_TOKEN_ENV_VAR)
    assert call(anonymous, VALID, headers=AUTH).json()["error"]["code"] == "auth_not_configured"
    assert eth.calls == [] and units_left(quota) == 30


def test_body_limit_is_413_before_quota_or_rpc(
    client: TestClient, eth: EthereumNode, quota: SlidingWindowRateLimiter
) -> None:
    body = json.dumps(VALID).encode() + b" " * MAX_BODY_BYTES

    response = call(client, content=body, headers={"Content-Type": "application/json"})

    assert response.status_code == 413
    assert eth.calls == [] and units_left(quota) == 30


def test_busy_service_is_503_before_quota_or_rpc(
    client: TestClient, eth: EthereumNode, quota: SlidingWindowRateLimiter
) -> None:
    slots = ConcurrencyLimiter()
    app.dependency_overrides[get_concurrency_limiter] = lambda: slots
    for _ in range(slots.max_concurrent):
        assert slots.try_acquire()
    try:
        response = call(client, VALID)
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "service_busy"
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


def test_quota_is_shared_weighted_atomic_and_never_per_address(
    client: TestClient, quota: SlidingWindowRateLimiter
) -> None:
    service = EmptyService()
    app.dependency_overrides[get_transaction_analysis_service] = lambda: service
    one = {"network": "ethereum", "tx_hash": H1}
    address = {"network": "ethereum", "address": ALICE, "tx_hashes": [H1, H2]}
    multi = {"network": "ethereum", "tx_hashes": [H1, H2, H3]}
    path_body = {**multi, "source_address": ALICE, "target_address": BOB}
    dossier_body = {**multi, "addresses": [ALICE, BOB, CAROL, DAVE, EVE]}

    assert call(client, one, path=INSPECT).status_code == 200
    assert call(client, one, path=ASSESS).status_code == 200
    assert call(client, address, path=ADDRESS).status_code == 200
    assert call(client, multi, path=GRAPH).status_code == 200
    assert call(client, path_body, path=PATHS).status_code == 200
    for _ in range(6):
        assert call(client, dossier_body).status_code == 200
    assert units_left(quota) == 2
    calls_before = len(service.calls)

    refused = call(client, dossier_body)

    assert refused.status_code == 429
    assert len(service.calls) == calls_before
    assert units_left(quota) == 2
    assert call(client, {**dossier_body, "tx_hashes": [H1, H2]}).status_code == 200
    assert len(service.calls) == calls_before + 2  # two hashes, not five addresses
    assert units_left(quota) == 0


class BlockingService:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def inspect_transaction(self, network: Network, tx_hash: str) -> TransactionInspection:
        self.entered.set()
        assert self.release.wait(10)
        return inspection(tx_hash)


def test_concurrency_slot_is_held_for_whole_dossier_and_released(
    client: TestClient, quota: SlidingWindowRateLimiter
) -> None:
    service = BlockingService()
    app.dependency_overrides[get_transaction_analysis_service] = lambda: service
    slots = ConcurrencyLimiter(max_concurrent=1)
    app.dependency_overrides[get_concurrency_limiter] = lambda: slots
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            running = pool.submit(call, client, VALID)
            assert service.entered.wait(10)
            refused = call(client, VALID)
            assert refused.status_code == 503
            assert units_left(quota) == 29
            service.release.set()
            assert running.result(10).status_code == 200
    finally:
        service.release.set()
    assert slots.try_acquire()
    slots.release()


def test_provider_error_does_not_leak_secrets(client: TestClient, eth: EthereumNode) -> None:
    eth.failures["eth_chainId"] = ProviderTimeoutError(f"private {SECRETS[1]}")

    response = call(client, VALID)

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "provider_timeout"
    assert "private" not in response.text


# --- OpenAPI and regression ---------------------------------------------------------------------


def test_openapi_documents_strict_dossier_contract(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    operation = spec["paths"][URL]["post"]

    assert operation["security"] == [{"HTTPBearer": []}]
    assert {"200", "401", "413", "422", "429", "502", "503", "504"} <= set(
        operation["responses"]
    )
    assert "never per address" in operation["responses"]["429"]["description"]
    success = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert success["$ref"] == "#/components/schemas/InvestigationDossierResponse"
    request = spec["components"]["schemas"]["InvestigationDossierRequest"]
    assert request["additionalProperties"] is False
    assert (request["properties"]["addresses"]["minItems"],
            request["properties"]["addresses"]["maxItems"]) == (2, 5)
    assert (request["properties"]["tx_hashes"]["minItems"],
            request["properties"]["tx_hashes"]["maxItems"]) == (1, 3)
    response = spec["components"]["schemas"]["InvestigationDossierResponse"]
    assert response["additionalProperties"] is False
    assert response["properties"]["sample_scope"]["const"] == "supplied_transactions_only"


def test_existing_routes_remain_registered(client: TestClient) -> None:
    registered = set(client.get("/openapi.json").json()["paths"])

    assert {URL, INSPECT, ASSESS, ADDRESS, GRAPH, PATHS, "/health"} <= registered


def test_contract_has_no_ranking_score_verdict_or_owner_inference(client: TestClient) -> None:
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    keys: set[str] = set()
    for name in (
        "InvestigationDossierResponse",
        "DossierAddressFindingView",
        "SelectedAddressRelationshipView",
    ):
        keys.update(schemas[name]["properties"])
    forbidden = ("score", "rank", "verdict", "fraud", "owner", "guilty", "suspicious")
    assert not {key for key in keys if any(word in key.lower() for word in forbidden)}
