"""Relationship Path Analysis v1, with network-free end-to-end coverage."""

import json
import socket
from collections.abc import Iterator
from typing import Any

import pytest
from eth_utils import to_checksum_address
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.providers.ethereum as ethereum_module
import app.providers.tron as tron_module
from app.api.auth import API_TOKEN_ENV_VAR
from app.api.body_limit import MAX_BODY_BYTES
from app.api.concurrency_limit import ConcurrencyLimiter, get_concurrency_limiter
from app.api.path_schemas import RelationshipPathAnalysisResponse
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
from app.services.address_investigation import TransferCoverage
from app.services.relationship_paths import (
    MAX_RETURNED_PATHS,
    ConnectionStatus,
    PathLeg,
    RelationshipPath,
    RelationshipPathAnalysis,
    analyze_relationship_paths,
)
from app.services.transaction_analysis import TransactionInspection
from app.services.usdt_relationships import build_usdt_relationship_graph
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

URL = "/api/v1/relationships/paths"
GRAPH = "/api/v1/relationships/usdt"
INSPECT = "/api/v1/transactions/inspect"
ASSESS = "/api/v1/transactions/assess"
INVESTIGATE = "/api/v1/addresses/investigate"
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


def paths(
    client: TestClient, network: str, hashes: list[str], source: str, target: str
) -> dict[str, Any]:
    response = call(client, {
        "network": network,
        "tx_hashes": hashes,
        "source_address": source,
        "target_address": target,
    })
    assert response.status_code == 200, response.text
    data = response.json()
    RelationshipPathAnalysisResponse.model_validate(data)
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


# --- Pure path analysis -------------------------------------------------------------------------

H1, H2, H3, H4 = ("0x" + character * 64 for character in "1234")
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
            from_address=ALICE if found else None,
            to_address=BOB if found else None,
            native_value_atomic=0 if found else None,
            native_unit=NativeUnit.WEI if found else None,
            block_number=1 if final else None,
            block_timestamp=2 if final else None,
        ),
        usdt_transfers=transfers if final else None,
    )


def analyze(*inspections: TransactionInspection, source: str = ALICE, target: str = BOB):
    graph = build_usdt_relationship_graph(Network.ETHEREUM, inspections)
    return analyze_relationship_paths(graph, source, target)


def test_direct_path_preserves_every_event_id_and_sum_above_uint256() -> None:
    result = analyze(
        inspection(H1, transfers=(
            transfer(H1, ALICE, BOB, MAX_UINT256, 10),
            transfer(H1, ALICE, BOB, MAX_UINT256, 11),
        ))
    )

    assert result.connection_status is ConnectionStatus.OBSERVED
    assert result.observed_path_count == 1 and result.truncated is False
    assert len(result.paths or ()) == 1  # two events do not create a Cartesian product
    direct = (result.paths or ())[0]
    assert direct.hop_count == 1 and direct.addresses == (ALICE, BOB)
    assert direct.legs[0] == PathLeg(
        from_address=ALICE,
        to_address=BOB,
        event_count=2,
        total_amount_atomic=2 * MAX_UINT256,
        tx_hashes=(H1,),
        event_ids=(f"ethereum:{H1}:0", f"ethereum:{H1}:1"),
    )


def test_two_hop_path_is_topological_not_causal_or_chronological() -> None:
    first = inspection(H1, transfers=(
        transfer(H1, CAROL, BOB, 7, 1),  # second leg appears in the earlier supplied tx
        transfer(H1, CAROL, CAROL, 99, 2),  # self-loop cannot become an intermediate
        transfer(H1, BOB, ALICE, 5, 3),  # inverse direction must not help
    ))
    second = inspection(H2, transfers=(
        transfer(H2, ALICE, CAROL, 11, 8),
        transfer(H2, ALICE, CAROL, 13, 9),
        transfer(H2, ALICE, ALICE, 100, 10),
    ))

    result = analyze(first, second)

    assert result.observed_path_count == 1
    path = (result.paths or ())[0]
    assert path.hop_count == 2 and path.addresses == (ALICE, CAROL, BOB)
    assert [(leg.event_count, leg.total_amount_atomic, leg.tx_hashes) for leg in path.legs] == [
        (2, 24, (H2,)),
        (1, 7, (H1,)),
    ]
    assert path.legs[0].event_ids == (
        f"ethereum:{H2}:0", f"ethereum:{H2}:1"
    )
    assert path.legs[1].event_ids == (f"ethereum:{H1}:0",)


def test_direct_precedes_several_sorted_intermediates() -> None:
    middle_a = to_checksum_address("0x" + "11" * 20)
    middle_b = to_checksum_address("0x" + "22" * 20)
    events = (
        transfer(H1, ALICE, middle_b, 1, 0),
        transfer(H1, middle_b, BOB, 2, 1),
        transfer(H1, ALICE, BOB, 3, 2),
        transfer(H1, ALICE, middle_a, 4, 3),
        transfer(H1, middle_a, BOB, 5, 4),
    )

    result = analyze(inspection(H1, transfers=events))

    assert result.observed_path_count == 3
    assert [path.addresses for path in result.paths or ()] == [
        (ALICE, BOB),
        (ALICE, *sorted((middle_a, middle_b))[0:1], BOB),
        (ALICE, *sorted((middle_a, middle_b))[1:2], BOB),
    ]


def test_inverse_direction_has_no_path() -> None:
    result = analyze(
        inspection(H1, transfers=(transfer(H1, ALICE, BOB, 1, 0),)),
        source=BOB,
        target=ALICE,
    )

    assert result.connection_status is ConnectionStatus.NOT_OBSERVED_COMPLETE
    assert result.observed_path_count == 0 and result.paths == ()


def test_partial_coverage_returns_known_paths_and_declares_incompleteness() -> None:
    result = analyze(
        inspection(H1, transfers=(transfer(H1, ALICE, BOB, 1, 0),)),
        inspection(H2, status=TransactionStatus.PENDING),
    )

    assert result.transfer_coverage is TransferCoverage.PARTIAL
    assert result.connection_status is ConnectionStatus.OBSERVED
    assert result.observed_path_count == 1 and len(result.paths or ()) == 1


def test_partial_coverage_distinguishes_no_known_path_from_absence() -> None:
    result = analyze(
        inspection(H1),
        inspection(H2, status=TransactionStatus.NOT_FOUND),
    )

    assert result.transfer_coverage is TransferCoverage.PARTIAL
    assert result.connection_status is ConnectionStatus.NOT_OBSERVED_PARTIAL
    assert result.observed_path_count == 0 and result.paths == ()


def test_no_coverage_makes_connectivity_and_paths_unknown() -> None:
    result = analyze(
        inspection(H1, status=TransactionStatus.PENDING),
        inspection(H2, status=TransactionStatus.NOT_FOUND),
    )

    assert result.transfer_coverage is TransferCoverage.NONE
    assert result.connection_status is ConnectionStatus.UNKNOWN
    assert result.observed_path_count is None and result.paths is None
    assert result.truncated is False


def test_complete_known_empty_graph_returns_an_empty_list() -> None:
    result = analyze(inspection(H1), inspection(H2, status=TransactionStatus.REVERTED))

    assert result.transfer_coverage is TransferCoverage.COMPLETE
    assert result.connection_status is ConnectionStatus.NOT_OBSERVED_COMPLETE
    assert result.observed_path_count == 0 and result.paths == ()


def test_dense_graph_is_deterministically_truncated_without_event_products() -> None:
    intermediates = [to_checksum_address(f"0x{value:040x}") for value in range(100, 155)]
    events = [transfer(H1, ALICE, BOB, 1, 0)]
    for index, middle in enumerate(reversed(intermediates), start=1):
        events.append(transfer(H1, ALICE, middle, index, index * 2 - 1))
        events.append(transfer(H1, middle, BOB, index, index * 2))

    result = analyze(inspection(H1, transfers=tuple(events)))

    assert result.observed_path_count == 56
    assert result.truncated is True and len(result.paths or ()) == MAX_RETURNED_PATHS
    assert (result.paths or ())[0].addresses == (ALICE, BOB)
    assert [path.addresses[1] for path in (result.paths or ())[1:]] == sorted(intermediates)[:49]
    assert all(len(path.legs) == path.hop_count for path in result.paths or ())


def test_addresses_are_normalized_and_identical_endpoints_rejected() -> None:
    graph = build_usdt_relationship_graph(Network.ETHEREUM, [inspection(H1)])
    result = analyze_relationship_paths(graph, ALICE.lower(), BOB.lower())

    assert (result.source_address, result.target_address) == (ALICE, BOB)
    with pytest.raises(ValueError):
        analyze_relationship_paths(graph, ALICE.lower(), ALICE)


def test_models_reject_inconsistent_legs_paths_and_results() -> None:
    valid = analyze(
        inspection(H1, transfers=(transfer(H1, ALICE, BOB, 1, 0),))
    )
    path = (valid.paths or ())[0]
    leg = path.legs[0]

    with pytest.raises(ValidationError):
        PathLeg(**{**leg.model_dump(), "event_count": 2})
    with pytest.raises(ValidationError):
        RelationshipPath(**{**path.model_dump(), "hop_count": 2})
    with pytest.raises(ValidationError):
        RelationshipPathAnalysis(**{
            **valid.model_dump(), "connection_status": ConnectionStatus.UNKNOWN
        })
    with pytest.raises(ValidationError):
        RelationshipPathAnalysis(**{**valid.model_dump(), "truncated": True})
    wrong_network_leg = PathLeg(
        **{**leg.model_dump(), "event_ids": (f"tron:{H1}:0",)}
    )
    wrong_network_path = RelationshipPath(
        hop_count=1, addresses=(ALICE, BOB), legs=(wrong_network_leg,)
    )
    with pytest.raises(ValidationError):
        RelationshipPathAnalysis(**{
            **valid.model_dump(), "paths": (wrong_network_path,)
        })


def test_json_schema_preserves_exact_amounts_without_float() -> None:
    domain = analyze(inspection(H1, transfers=(
        transfer(H1, ALICE, BOB, MAX_UINT256, 0),
        transfer(H1, ALICE, BOB, MAX_UINT256, 1),
    )))
    data = RelationshipPathAnalysisResponse.from_domain(domain).model_dump(mode="json")

    assert data["paths"][0]["legs"][0]["total_amount_atomic"] == str(2 * MAX_UINT256)
    assert all(isinstance(number, int) and number <= MAX_SAFE_INTEGER for number in walk_numbers(data))


# --- HTTP validation ----------------------------------------------------------------------------

VALID = {
    "network": "ethereum",
    "tx_hashes": [USDT_HASH],
    "source_address": ALICE,
    "target_address": BOB,
}


@pytest.mark.parametrize("body", [
    {},
    {key: value for key, value in VALID.items() if key != "source_address"},
    {key: value for key, value in VALID.items() if key != "target_address"},
    {**VALID, "tx_hashes": []},
    {**VALID, "tx_hashes": [USDT_HASH, SWAP_HASH, NATIVE_HASH, PENDING_HASH]},
    {**VALID, "tx_hashes": [USDT_HASH, USDT_HASH.upper().replace("0X", "0x")]},
    {**VALID, "tx_hashes": ["0x12"]},
    {**VALID, "tx_hashes": [TRC20_HASH]},
    {**VALID, "source_address": ALICE.lower(), "target_address": ALICE},
    {**VALID, "source_address": "0x1234"},
    {**VALID, "source_address": TRON_ALICE},
    {**VALID, "network": "tron"},
    {**VALID, "network": "bitcoin"},
    {**VALID, "extra": 1},
    [VALID],
])
def test_invalid_request_is_422_without_rpc_or_quota(
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


def test_validation_error_does_not_echo_addresses_or_unknown_fields(client: TestClient) -> None:
    marker = "0x" + "z" * 40
    response = call(client, {**VALID, "source_address": marker, TOKEN[:8]: 1})

    assert response.status_code == 422
    assert marker not in response.text and TOKEN[:8] not in response.text


# --- End to end through real providers and simulated nodes --------------------------------------


def test_ethereum_direct_and_two_hop_paths_use_existing_graph_provenance(
    client: TestClient, eth: EthereumNode
) -> None:
    eth_usdt(eth)
    eth_swap(eth)

    data = paths(client, "ethereum", [USDT_HASH, SWAP_HASH], ALICE.lower(), BOB.lower())

    assert data["source_address"] == ALICE and data["target_address"] == BOB
    assert data["sample_scope"] == "supplied_transactions_only"
    assert data["transfer_coverage"] == "complete"
    assert data["connection_status"] == "path_observed"
    assert data["observed_path_count"] == 2 and data["truncated"] is False
    assert not {"nodes", "edges", "grouped_relationships"} & set(data)
    assert [path["addresses"] for path in data["paths"]] == [
        [ALICE, BOB], [ALICE, CAROL, BOB]
    ]
    assert data["paths"][0]["legs"][0] == {
        "from_address": ALICE,
        "to_address": BOB,
        "event_count": 1,
        "total_amount_atomic": "625000000",
        "tx_hashes": [USDT_HASH],
        "event_ids": [f"ethereum:{USDT_HASH}:0"],
    }
    indirect = data["paths"][1]
    assert [leg["event_ids"] for leg in indirect["legs"]] == [
        [f"ethereum:{SWAP_HASH}:0"], [f"ethereum:{SWAP_HASH}:1"]
    ]
    assert [leg["total_amount_atomic"] for leg in indirect["legs"]] == [
        str(MAX_UINT256), str(MAX_UINT256)
    ]
    assert "amount_atomic" not in indirect  # no invented end-to-end amount


def test_tron_two_hop_path_has_canonical_addresses(
    client: TestClient, tron: TronNode
) -> None:
    tron_usdt(tron)

    data = paths(client, "tron", [TRC20_HASH.upper()], TRON_ALICE, TRON_CAROL)

    assert data["network"] == "tron"
    assert data["observed_path_count"] == 1
    assert data["paths"][0]["addresses"] == [TRON_ALICE, TRON_BOB, TRON_CAROL]
    assert [leg["event_ids"] for leg in data["paths"][0]["legs"]] == [
        [f"tron:{TRC20_HASH}:0"], [f"tron:{TRC20_HASH}:1"]
    ]


def test_http_partial_coverage_returns_known_path(
    client: TestClient, tron: TronNode
) -> None:
    tron_usdt(tron)
    tron.stores[GET_TRANSACTION_PATH][UNCONFIRMED_HASH] = trc20_call(
        UNCONFIRMED_HASH, TRON_ALICE
    )

    data = paths(
        client, "tron", [TRC20_HASH, UNCONFIRMED_HASH], TRON_ALICE, TRON_CAROL
    )

    assert data["transfer_coverage"] == "partial"
    assert data["connection_status"] == "path_observed"
    assert data["transactions"][1]["usdt_event_count"] is None
    assert len(data["paths"]) == 1


def test_http_no_coverage_uses_null_not_empty_list(
    client: TestClient, eth: EthereumNode
) -> None:
    eth.transactions[PENDING_HASH] = eth_tx(PENDING_HASH, ALICE, BOB, 1, None)

    data = paths(client, "ethereum", [PENDING_HASH, UNKNOWN_HASH], ALICE, BOB)

    assert data["transfer_coverage"] == "none"
    assert data["connection_status"] == "connectivity_unknown"
    assert data["observed_path_count"] is None and data["paths"] is None


def test_http_complete_absence_uses_empty_list(client: TestClient, eth: EthereumNode) -> None:
    mine(eth, NATIVE_HASH, ALICE, BOB, 1)

    data = paths(client, "ethereum", [NATIVE_HASH], ALICE, BOB)

    assert data["transfer_coverage"] == "complete"
    assert data["connection_status"] == "no_path_observed_in_supplied_transactions"
    assert data["observed_path_count"] == 0 and data["paths"] == []


def test_fail_fast_returns_no_partial_paths_and_skips_later_hash(
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
    assert "paths" not in response.json()
    assert eth.calls.count("eth_getTransactionByHash") == 4


# --- HTTP protections and shared quota -----------------------------------------------------------


def test_bearer_failures_use_no_rpc_or_quota(
    eth: EthereumNode, quota: SlidingWindowRateLimiter, monkeypatch: pytest.MonkeyPatch
) -> None:
    anonymous = TestClient(app)
    for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {TOKEN}"}):
        response = call(anonymous, VALID, headers=headers)
        assert response.status_code == 401
    monkeypatch.delenv(API_TOKEN_ENV_VAR)
    assert call(anonymous, VALID, headers=AUTH).json()["error"]["code"] == "auth_not_configured"
    assert eth.calls == [] and units_left(quota) == 30


def test_body_limit_is_413_before_rpc_and_quota(
    client: TestClient, eth: EthereumNode, quota: SlidingWindowRateLimiter
) -> None:
    body = json.dumps(VALID).encode() + b" " * MAX_BODY_BYTES

    response = call(client, content=body, headers={"Content-Type": "application/json"})

    assert response.status_code == 413
    assert eth.calls == [] and units_left(quota) == 30


def test_busy_service_is_503_before_rpc_and_quota(
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


def test_quota_is_weighted_atomic_shared_and_admitted_once(
    client: TestClient, quota: SlidingWindowRateLimiter
) -> None:
    service = EmptyService()
    app.dependency_overrides[get_transaction_analysis_service] = lambda: service
    one = {"network": "ethereum", "tx_hash": H1}
    address = {"network": "ethereum", "address": ALICE, "tx_hashes": [H1, H2]}
    graph_body = {"network": "ethereum", "tx_hashes": [H1, H2, H3]}
    path_body = {**graph_body, "source_address": ALICE, "target_address": BOB}

    assert call(client, one, path=INSPECT).status_code == 200
    assert call(client, one, path=ASSESS).status_code == 200
    assert call(client, address, path=INVESTIGATE).status_code == 200
    assert call(client, graph_body, path=GRAPH).status_code == 200
    for _ in range(7):
        assert call(client, path_body).status_code == 200
    assert units_left(quota) == 2
    calls_before = len(service.calls)

    refused = call(client, path_body)

    assert refused.status_code == 429
    assert refused.json()["error"]["code"] == "rate_limited"
    assert len(service.calls) == calls_before
    assert units_left(quota) == 2  # rejected cost=3 consumed no partial unit
    assert call(client, {**path_body, "tx_hashes": [H1, H2]}).status_code == 200
    assert units_left(quota) == 0  # exactly two units, never a second admission


def test_provider_error_does_not_leak_exception_or_secrets(
    client: TestClient, eth: EthereumNode
) -> None:
    eth.failures["eth_chainId"] = ProviderTimeoutError(
        f"private data {SECRETS[1]}"
    )

    response = call(client, VALID)

    assert response.status_code == 504
    assert response.json()["error"]["code"] == "provider_timeout"
    assert "private data" not in response.text


# --- OpenAPI and route regression ---------------------------------------------------------------


def test_openapi_documents_paths_limits_and_strict_models(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    operation = spec["paths"][URL]["post"]

    assert operation["security"] == [{"HTTPBearer": []}]
    assert {"200", "401", "413", "422", "429", "502", "503", "504"} <= set(
        operation["responses"]
    )
    success = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert success["$ref"] == "#/components/schemas/RelationshipPathAnalysisResponse"
    request = spec["components"]["schemas"]["RelationshipPathsRequest"]
    assert request["additionalProperties"] is False
    assert (request["properties"]["tx_hashes"]["minItems"],
            request["properties"]["tx_hashes"]["maxItems"]) == (1, 3)
    response = spec["components"]["schemas"]["RelationshipPathAnalysisResponse"]
    assert response["additionalProperties"] is False
    assert "first 50" in response["properties"]["truncated"]["description"]
    assert response["properties"]["paths"]["anyOf"][0]["maxItems"] == 50
    assert response["properties"]["sample_scope"]["const"] == "supplied_transactions_only"


def test_existing_endpoints_remain_registered(client: TestClient) -> None:
    registered = set(client.get("/openapi.json").json()["paths"])

    assert {URL, GRAPH, INSPECT, ASSESS, INVESTIGATE, "/health"} <= registered


def test_contract_contains_no_accusatory_or_score_fields(client: TestClient) -> None:
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    keys: set[str] = set()
    for name in (
        "RelationshipPathAnalysisResponse",
        "RelationshipPathView",
        "PathLegView",
    ):
        keys.update(schemas[name]["properties"])
    forbidden = ("safe", "fraud", "guilty", "suspicious", "risk_score")
    assert not {key for key in keys if any(word in key.lower() for word in forbidden)}
