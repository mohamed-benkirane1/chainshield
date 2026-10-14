"""API tests for POST /api/v1/transactions/assess.

Every report below is FICTIONAL test data: the sources, identifiers and
allegations do not exist and say nothing about the real owners of these
addresses (standard checksum test vectors or synthetic values).
"""

import json
import socket
from collections.abc import Iterator
from typing import Any

import base58
import pytest
from fastapi.testclient import TestClient

from app.api.transactions import get_transaction_analysis_service
from app.domain.analysis_input import Network
from app.domain.token_transfer import MAX_UINT256, NormalizedTokenTransfer
from app.main import app
from app.providers.base import (
    NativeUnit,
    NormalizedTransaction,
    ProviderTimeoutError,
    ProviderUnavailableError,
    TransactionStatus,
)
from app.services.transaction_analysis import TransactionInspection

ASSESS = "/api/v1/transactions/assess"
INSPECT = "/api/v1/transactions/inspect"
SECRET = "sk-test-0123456789abcdef"
API_TOKEN = "fictional-test-token-not-a-secret-0123456789"  # test value only
AUTH = {"Authorization": f"Bearer {API_TOKEN}"}

ETH_HASH = "0x" + "ab" * 32
TRON_HASH = "cd" * 32
ETH_USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
BOB = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
CAROL = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRON_ALICE = base58.b58encode_check(b"\x41" + bytes(range(1, 21))).decode()
TRON_BOB = base58.b58encode_check(b"\x41" + bytes(range(21, 41))).decode()


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
def _isolated_dependencies(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for name in ("CHAINSHIELD_ETHEREUM_RPC_URL", "CHAINSHIELD_TRON_RPC_URL",
                 "CHAINSHIELD_TRON_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CHAINSHIELD_API_TOKEN", API_TOKEN)
    get_transaction_analysis_service.cache_clear()
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()
    get_transaction_analysis_service.cache_clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, headers=AUTH)


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


# --- Builders ---------------------------------------------------------------------


def eth_tx(status: TransactionStatus = TransactionStatus.SUCCESS,
           to: str | None = ETH_USDT) -> NormalizedTransaction:
    fields: dict[str, Any] = {"network": Network.ETHEREUM, "tx_hash": ETH_HASH, "status": status}
    if status is not TransactionStatus.NOT_FOUND:
        fields.update(from_address=ALICE, to_address=to,
                      native_value_atomic=0, native_unit=NativeUnit.WEI)
    if status in (TransactionStatus.SUCCESS, TransactionStatus.REVERTED):
        fields.update(block_number=19_000_000, block_timestamp=1_705_000_000)
    return NormalizedTransaction(**fields)


def tron_tx(status: TransactionStatus = TransactionStatus.SUCCESS) -> NormalizedTransaction:
    fields: dict[str, Any] = {"network": Network.TRON, "tx_hash": TRON_HASH, "status": status}
    if status is not TransactionStatus.NOT_FOUND:
        fields.update(from_address=TRON_ALICE, to_address=TRON_USDT,
                      native_value_atomic=0, native_unit=NativeUnit.SUN)
    if status in (TransactionStatus.SUCCESS, TransactionStatus.REVERTED):
        fields.update(block_number=60_000_000, block_timestamp=1_705_000_002)
    return NormalizedTransaction(**fields)


def transfer(sender: str, recipient: str, amount: int = 35_000_000, log_index: int = 0):
    return NormalizedTokenTransfer(
        network=Network.ETHEREUM, tx_hash=ETH_HASH, token_symbol="USDT",
        token_contract=ETH_USDT, from_address=sender, to_address=recipient,
        amount_atomic=amount, decimals=6, log_index=log_index,
    )


def tron_transfer() -> NormalizedTokenTransfer:
    return NormalizedTokenTransfer(
        network=Network.TRON, tx_hash=TRON_HASH, token_symbol="USDT",
        token_contract=TRON_USDT, from_address=TRON_ALICE, to_address=TRON_BOB,
        amount_atomic=10_000_000_000, decimals=6,
    )


def inspect(transaction: NormalizedTransaction, transfers: Any) -> TransactionInspection:
    return TransactionInspection(
        network=transaction.network, tx_hash=transaction.tx_hash, transaction=transaction,
        usdt_transfers=None if transfers is None else tuple(transfers),
    )


def usdt_payment() -> TransactionInspection:
    return inspect(eth_tx(), [transfer(ALICE, BOB)])


def report(address: str = BOB, report_id: str = "FICTIONAL-1", **overrides: Any) -> dict:
    body = {
        "network": "ethereum",
        "address": address,
        "source_id": "fictional-test-source",
        "report_id": report_id,
        "source_type": "community_report",
        "claim_category": "scam_allegation",
        "reported_at": "2026-05-01T12:00:00+00:00",
    }
    body.update(overrides)
    return body


def eth_body(reports: Any = "omit", **overrides: Any) -> dict:
    body: dict[str, Any] = {"kind": "transaction", "network": "ethereum", "tx_hash": ETH_HASH}
    if reports != "omit":
        body["reports"] = reports
    body.update(overrides)
    return body


def assessment_of(client: TestClient, body: dict) -> dict:
    response = client.post(ASSESS, json=body)
    assert response.status_code == 200, response.text
    return response.json()


# --- Successful assessments -------------------------------------------------------------


def test_ethereum_matching_report(client: TestClient) -> None:
    fake = use(usdt_payment())

    body = assessment_of(client, eth_body([report(BOB)]))

    assert body["report_origin"] == "client_supplied_unverified"
    assert body["inspection"]["usdt_transfers"][0]["amount_atomic"] == "35000000"
    assessment = body["assessment"]
    assert assessment["risk_determination"] == "indeterminate"
    assert assessment["determination_basis"] == "no_verified_evidence"
    assert assessment["manual_review_recommended"] is True
    assert assessment["signals"] == [
        {
            "signal_code": "unverified_address_allegation_match",
            "address": BOB,
            "observed_roles": ["usdt_transfer_recipient"],
            "source_id": "fictional-test-source",
            "report_id": "FICTIONAL-1",
            "source_type": "community_report",
            "claim_category": "scam_allegation",
            "reported_at": "2026-05-01T12:00:00Z",
            "evidence_status": "unverified",
        }
    ]
    assert assessment["address_evidence"]["matches"][0]["allegation_verified"] is False
    assert fake.calls == [(Network.ETHEREUM, ETH_HASH)]  # a single inspection


def test_tron_matching_report(client: TestClient) -> None:
    use(inspect(tron_tx(), [tron_transfer()]))
    body = {"kind": "transaction", "network": "tron", "tx_hash": TRON_HASH,
            "reports": [report(TRON_BOB, network="tron")]}

    assessment = assessment_of(client, body)["assessment"]

    assert assessment["network"] == "tron"
    assert [(s["address"], s["observed_roles"]) for s in assessment["signals"]] == [
        (TRON_BOB, ["usdt_transfer_recipient"])
    ]


def test_several_independent_reports_keep_provenance_and_order(client: TestClient) -> None:
    use(usdt_payment())
    reports = [
        report(BOB, "R-2", source_id="fictional-b", claim_category="phishing_allegation",
               reported_at="2026-04-02T08:30:00+02:00"),
        report(BOB, "R-1", source_id="fictional-a"),
        report(ALICE, "R-3", source_id="fictional-c", source_type="security_vendor"),
    ]

    signals = assessment_of(client, eth_body(reports))["assessment"]["signals"]

    assert [(s["address"], s["source_id"], s["report_id"], s["reported_at"]) for s in signals] == [
        (ALICE, "fictional-c", "R-3", "2026-05-01T12:00:00Z"),
        (BOB, "fictional-a", "R-1", "2026-05-01T12:00:00Z"),
        (BOB, "fictional-b", "R-2", "2026-04-02T08:30:00+02:00"),
    ]


def test_same_address_with_several_roles(client: TestClient) -> None:
    use(usdt_payment())

    signals = assessment_of(client, eth_body([report(ALICE)]))["assessment"]["signals"]

    assert signals[0]["observed_roles"] == ["transaction_sender", "usdt_transfer_sender"]


@pytest.mark.parametrize(
    ("reports", "status", "count"),
    [
        ("omit", "no_report_source", None),
        (None, "no_report_source", None),
        ([], "empty_report_source", 0),
        ([report(CAROL)], "no_match_in_supplied_reports", 1),
    ],
    ids=["omitted", "null", "empty", "no-match"],
)
def test_no_signal_cases(client: TestClient, reports: Any, status: str, count: Any) -> None:
    use(usdt_payment())

    assessment = assessment_of(client, eth_body(reports))["assessment"]

    assert assessment["address_evidence"]["evaluation_status"] == status
    assert assessment["address_evidence"]["supplied_report_count"] == count
    assert assessment["signals"] == []
    assert assessment["manual_review_recommended"] is False
    assert assessment["risk_determination"] == "indeterminate"  # never "safe"


def test_public_authority_source_stays_unverified(client: TestClient) -> None:
    use(usdt_payment())

    assessment = assessment_of(
        client, eth_body([report(BOB, source_type="public_authority")])
    )["assessment"]

    assert assessment["signals"][0]["source_type"] == "public_authority"
    assert assessment["signals"][0]["evidence_status"] == "unverified"
    assert assessment["risk_determination"] == "indeterminate"


def test_identical_duplicates_are_merged(client: TestClient) -> None:
    use(usdt_payment())

    assessment = assessment_of(client, eth_body([report(BOB)] * 3))["assessment"]

    assert assessment["address_evidence"]["supplied_report_count"] == 1
    assert len(assessment["signals"]) == 1


# --- Transaction statuses --------------------------------------------------------------


@pytest.mark.parametrize(
    ("inspection", "body", "matched"),
    [
        (inspect(eth_tx(TransactionStatus.PENDING), None),
         eth_body([report(ALICE), report(BOB, "R-2")]), ["transaction_sender"]),
        (inspect(tron_tx(TransactionStatus.UNCONFIRMED), None),
         {"network": "tron", "tx_hash": TRON_HASH,
          "reports": [report(TRON_ALICE, network="tron"), report(TRON_BOB, "R-2", network="tron")]},
         ["transaction_sender"]),
        (inspect(eth_tx(TransactionStatus.NOT_FOUND), None), eth_body([report(ALICE)]), None),
    ],
    ids=["pending", "unconfirmed", "not-found"],
)
def test_non_final_transactions(
    client: TestClient, inspection: TransactionInspection, body: dict, matched: Any
) -> None:
    use(inspection)

    result = assessment_of(client, body)
    assessment = result["assessment"]

    assert result["inspection"]["usdt_transfers"] is None
    assert assessment["features"]["transfer_data_available"] is False
    assert assessment["features"]["usdt_transfer_count"] is None
    assert assessment["features"]["gross_usdt_event_amount_atomic"] is None
    roles = [s["observed_roles"] for s in assessment["signals"]]
    assert roles == ([matched] if matched else [])
    assert assessment["risk_determination"] == "indeterminate"


def test_reverted_transaction(client: TestClient) -> None:
    use(inspect(eth_tx(TransactionStatus.REVERTED), []))

    assessment = assessment_of(client, eth_body([report(ALICE), report(BOB, "R-2")]))["assessment"]

    assert assessment["transaction_status"] == "reverted"
    assert assessment["features"]["usdt_transfer_count"] == 0
    assert [s["address"] for s in assessment["signals"]] == [ALICE]


def test_success_without_usdt_transfer(client: TestClient) -> None:
    use(inspect(eth_tx(), []))

    features = assessment_of(client, eth_body([report(BOB)]))["assessment"]["features"]

    assert features["usdt_transfer_count"] == 0
    assert features["gross_usdt_event_amount_atomic"] == "0"
    assert features["max_usdt_transfer_amount_atomic"] is None


# --- Precision --------------------------------------------------------------------------


def test_large_amounts_and_sums_beyond_uint256_are_exact_strings(client: TestClient) -> None:
    transfers = [transfer(ALICE, BOB, MAX_UINT256, 0), transfer(BOB, CAROL, MAX_UINT256, 1),
                 transfer(CAROL, ALICE, 2**53 + 1, 2)]
    use(inspect(eth_tx(), transfers))

    response = client.post(ASSESS, json=eth_body(None))
    features = response.json()["assessment"]["features"]

    assert features["gross_usdt_event_amount_atomic"] == str(2 * MAX_UINT256 + 2**53 + 1)
    assert features["max_usdt_transfer_amount_atomic"] == str(MAX_UINT256)
    assert features["usdt_transfer_count"] == 3
    json.loads(response.text, parse_float=lambda _: pytest.fail("float found"))


# --- Validation errors ----------------------------------------------------------------------


def test_contradictory_duplicates_are_422(client: TestClient) -> None:
    use(usdt_payment())
    reports = [report(BOB, source_id=f"src-{SECRET}"),
               report(BOB, source_id=f"src-{SECRET}", claim_category="theft_allegation")]

    response = client.post(ASSESS, json=eth_body(reports))

    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "conflicting_reports",
            "message": "Several supplied reports share the same source and report identifiers "
                       "with different content.",
        }
    }
    assert SECRET not in response.text


def test_more_than_50_reports_is_422(client: TestClient) -> None:
    fake = use(usdt_payment())
    reports = [report(BOB, f"R-{i}") for i in range(51)]

    response = client.post(ASSESS, json=eth_body(reports))

    assert response.status_code == 422
    assert response.json()["error"]["details"] == [{"field": "reports", "type": "too_long"}]
    assert fake.calls == []


def test_exactly_50_reports_is_accepted(client: TestClient) -> None:
    use(usdt_payment())

    assessment = assessment_of(client, eth_body([report(BOB, f"R-{i:02d}") for i in range(50)]))

    assert assessment["assessment"]["address_evidence"]["supplied_report_count"] == 50


@pytest.mark.parametrize(
    "bad_report",
    [
        report(BOB[:-1] + ("a" if BOB[-1] != "a" else "b")),  # bad checksum
        report("0x1234"),
        report(TRON_BOB),  # TRON address declared on Ethereum
        report(BOB, network="bitcoin"),
        report(BOB, source_type="verified_source"),
        report(BOB, source_type="government"),
        report(BOB, claim_category="confirmed_fraud"),
        report(BOB, source_id=""),
        report(BOB, report_id="  "),
        report(BOB, source_id=42),
        report(BOB, reported_at="2026-05-01T12:00:00"),  # naive
        report(BOB, reported_at="yesterday"),
        report(BOB, reported_at=1_746_100_800),
        report(BOB, verified=True),
        "not an object",
    ],
    ids=["bad-checksum", "short", "tron-on-eth", "network", "fake-source-type", "other-type",
         "confirmed", "empty-source", "blank-report", "int-source", "naive-date", "bad-date",
         "unix-date", "extra-field", "string"],
)
def test_invalid_reports_are_422(client: TestClient, bad_report: Any) -> None:
    fake = use(usdt_payment())

    response = client.post(ASSESS, json=eth_body([report(ALICE), bad_report]))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"
    assert {d["field"] for d in response.json()["error"]["details"]} == {"reports"}
    assert fake.calls == []


@pytest.mark.parametrize(
    "body",
    [
        eth_body(network="bitcoin"),
        eth_body(tx_hash="0x1234"),
        eth_body(kind="message"),
        eth_body(score=1),
        eth_body(reports={"0": report()}),
        eth_body(reports="all"),
    ],
    ids=["network", "hash", "kind", "extra-field", "reports-object", "reports-string"],
)
def test_invalid_requests_are_422(client: TestClient, body: dict) -> None:
    use(usdt_payment())

    assert client.post(ASSESS, json=body).status_code == 422


def test_validation_errors_never_echo_client_data(client: TestClient) -> None:
    use(usdt_payment())
    reports = [report(f"0x{SECRET}", source_id=f"src-{SECRET}",
                      source_reference=f"https://example.invalid/{SECRET}",
                      **{f"extra_{SECRET}": SECRET})]

    response = client.post(ASSESS, json=eth_body(reports, **{f"field_{SECRET}": 1}))

    assert response.status_code == 422
    assert SECRET not in response.text
    for detail in response.json()["error"]["details"]:
        assert set(detail) == {"field", "type"}
        assert detail["field"] in {"kind", "network", "tx_hash", "reports", "body"}


# --- Provider errors, secrets, no fetching -------------------------------------------------


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (ProviderTimeoutError(f"timed out {SECRET}"), 504, "provider_timeout"),
        (ProviderUnavailableError(f"HTTP 429 {SECRET}"), 503, "provider_unavailable"),
    ],
)
def test_provider_errors_keep_existing_mapping(
    client: TestClient, error: Exception, status: int, code: str
) -> None:
    use(error)

    response = client.post(ASSESS, json=eth_body([report(BOB)]))

    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert SECRET not in response.text


def test_missing_provider_configuration_is_503(client: TestClient) -> None:
    response = client.post(ASSESS, json=eth_body([report(BOB)]))

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "provider_not_configured"


def test_source_reference_is_never_fetched_nor_echoed(client: TestClient) -> None:
    use(usdt_payment())
    reference = "https://example.invalid/fictional/should-not-be-fetched"

    response = client.post(ASSESS, json=eth_body([report(BOB, source_reference=reference)]))

    # The socket guard would fail the request if anything tried to fetch it.
    assert response.status_code == 200
    assert reference not in response.text


# --- Existing routes, documentation --------------------------------------------------------


def test_inspect_and_health_are_unchanged(client: TestClient) -> None:
    use(usdt_payment())

    inspect_response = client.post(INSPECT, json=eth_body())
    assess_response = client.post(ASSESS, json=eth_body())

    assert inspect_response.status_code == 200
    assert assess_response.json()["inspection"] == inspect_response.json()
    assert client.post(INSPECT, json=eth_body(reports=[])).status_code == 422  # no reports there
    assert client.get("/health").json() == {"status": "ok"}


def test_openapi_documents_the_assess_route(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()

    operation = spec["paths"]["/api/v1/transactions/assess"]["post"]
    assert {"200", "422", "502", "503", "504"} <= set(operation["responses"])
    schemas = spec["components"]["schemas"]
    features = schemas["FeaturesView"]["properties"]
    assert any(
        option.get("type") == "string"
        for option in features["gross_usdt_event_amount_atomic"]["anyOf"]
    )
    request_reports = schemas["TransactionAssessmentRequest"]["properties"]["reports"]
    assert any(option.get("maxItems") == 50 for option in request_reports["anyOf"])
    assert "/api/v1/transactions/inspect" in spec["paths"]
    assert client.get("/docs").status_code == 200


def test_no_score_field_in_the_response_contract(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()["components"]["schemas"]
    names = set()
    for schema in ("TransactionAssessmentResponse", "RiskAssessmentView", "RiskSignalView"):
        names |= set(spec[schema]["properties"])

    forbidden = ("score", "probability", "level", "fraud", "confidence", "verdict")
    assert not [n for n in names if any(word in n for word in forbidden)]
    determination = spec["RiskAssessmentView"]["properties"]["risk_determination"]
    assert spec[determination["$ref"].split("/")[-1]]["enum"] == ["indeterminate"]
