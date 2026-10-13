"""Tests for the explainable risk assessment.

Every report below is FICTIONAL test data: the sources, identifiers and
allegations do not exist and say nothing about the real owners of these
addresses (standard checksum test vectors or synthetic values).
"""

import copy
import json
import socket
from datetime import UTC, datetime
from typing import Any

import base58
import pytest
from pydantic import ValidationError

from app.domain.analysis_input import Network
from app.domain.token_transfer import MAX_UINT256, NormalizedTokenTransfer
from app.features.transaction_features import extract_transaction_features
from app.providers.base import NativeUnit, NormalizedTransaction, TransactionStatus
from app.risk.address_evidence import (
    AddressReport,
    ClaimCategory,
    ConflictingReportError,
    EvaluationStatus,
    ObservedRole,
    ReportSourceType,
    match_address_reports,
)
from app.risk.assessment import (
    EvidenceStatus,
    RiskDetermination,
    RiskSignal,
    SignalCode,
    TransactionRiskAssessment,
    assess_transaction,
)
from app.services.transaction_analysis import TransactionInspection

ETH_HASH = "0x" + "ab" * 32
TRON_HASH = "cd" * 32
ETH_USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
BOB = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
CAROL = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRON_ALICE = base58.b58encode_check(b"\x41" + bytes(range(1, 21))).decode()
TRON_BOB = base58.b58encode_check(b"\x41" + bytes(range(21, 41))).decode()
REPORTED_AT = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("tests must not open network connections")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


# --- Builders -------------------------------------------------------------------


def report(address: str = BOB, report_id: str = "FICTIONAL-1", **overrides: Any) -> AddressReport:
    fields: dict[str, Any] = {
        "network": Network.ETHEREUM,
        "address": address,
        "source_id": "fictional-test-source",
        "report_id": report_id,
        "source_type": ReportSourceType.COMMUNITY_REPORT,
        "claim_category": ClaimCategory.SCAM_ALLEGATION,
        "reported_at": REPORTED_AT,
    }
    fields.update(overrides)
    return AddressReport(**fields)


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


def assert_indeterminate(assessment: TransactionRiskAssessment) -> None:
    assert assessment.risk_determination is RiskDetermination.INDETERMINATE
    assert assessment.determination_basis == "no_verified_evidence"


# --- Matches and signals -----------------------------------------------------------


def test_ethereum_report_match_yields_one_unverified_signal() -> None:
    assessment = assess_transaction(usdt_payment(), [report(BOB)])

    assert assessment.signals == (
        RiskSignal(
            signal_code=SignalCode.UNVERIFIED_ADDRESS_ALLEGATION_MATCH,
            network=Network.ETHEREUM,
            address=BOB,
            observed_roles=(ObservedRole.USDT_TRANSFER_RECIPIENT,),
            source_id="fictional-test-source",
            report_id="FICTIONAL-1",
            source_type=ReportSourceType.COMMUNITY_REPORT,
            claim_category=ClaimCategory.SCAM_ALLEGATION,
            reported_at=REPORTED_AT,
            evidence_status=EvidenceStatus.UNVERIFIED,
        ),
    )
    assert assessment.manual_review_recommended is True
    assert_indeterminate(assessment)


def test_tron_report_match() -> None:
    inspection = inspect(tron_tx(), [tron_transfer()])

    assessment = assess_transaction(inspection, [report(TRON_BOB, network=Network.TRON)])

    assert assessment.network is Network.TRON
    assert [(s.address, s.observed_roles) for s in assessment.signals] == [
        (TRON_BOB, (ObservedRole.USDT_TRANSFER_RECIPIENT,))
    ]
    assert assessment.manual_review_recommended is True


def test_independent_reports_stay_separate_with_full_provenance() -> None:
    reports = [
        report(BOB, "R-2", source_id="fictional-source-b",
               source_type=ReportSourceType.PUBLIC_AUTHORITY,
               claim_category=ClaimCategory.PHISHING_ALLEGATION),
        report(BOB, "R-1", source_id="fictional-source-a"),
        report(ALICE, "R-3", source_id="fictional-source-c",
               source_type=ReportSourceType.SECURITY_VENDOR),
    ]

    assessment = assess_transaction(usdt_payment(), reports)

    assert [
        (s.address, s.source_id, s.report_id, s.source_type, s.claim_category)
        for s in assessment.signals
    ] == [
        (ALICE, "fictional-source-c", "R-3", ReportSourceType.SECURITY_VENDOR,
         ClaimCategory.SCAM_ALLEGATION),
        (BOB, "fictional-source-a", "R-1", ReportSourceType.COMMUNITY_REPORT,
         ClaimCategory.SCAM_ALLEGATION),
        (BOB, "fictional-source-b", "R-2", ReportSourceType.PUBLIC_AUTHORITY,
         ClaimCategory.PHISHING_ALLEGATION),
    ]
    # A declared authority gets no implicit credibility: still unverified.
    assert {s.evidence_status for s in assessment.signals} == {EvidenceStatus.UNVERIFIED}
    assert all(s.reported_at == REPORTED_AT for s in assessment.signals)
    assert_indeterminate(assessment)


def test_same_address_with_several_roles_is_one_signal() -> None:
    assessment = assess_transaction(usdt_payment(), [report(ALICE)])

    assert len(assessment.signals) == 1
    assert assessment.signals[0].observed_roles == (
        ObservedRole.TRANSACTION_SENDER,
        ObservedRole.USDT_TRANSFER_SENDER,
    )


def test_several_reports_on_one_address_give_one_signal_each() -> None:
    inspection = inspect(eth_tx(to=None), [])
    reports = [report(ALICE, f"F-{i}", source_id=f"fictional-source-{i}") for i in range(3)]

    assessment = assess_transaction(inspection, reports)

    assert assessment.address_evidence.observed_address_count == 1
    assert len(assessment.signals) == 3


def test_signals_mirror_address_evidence_exactly() -> None:
    reports = [report(BOB, "R-1"), report(ALICE, "R-2"), report(CAROL, "R-3")]

    assessment = assess_transaction(usdt_payment(), reports)

    assert assessment.address_evidence == match_address_reports(usdt_payment(), reports)
    assert assessment.signals == tuple(
        RiskSignal.from_match(m) for m in assessment.address_evidence.matches
    )


# --- No match and missing data ------------------------------------------------------


@pytest.mark.parametrize(
    ("reports", "status"),
    [
        (None, EvaluationStatus.NO_REPORT_SOURCE),
        ([], EvaluationStatus.EMPTY_REPORT_SOURCE),
        ([report(CAROL)], EvaluationStatus.NO_MATCH_IN_SUPPLIED_REPORTS),
    ],
    ids=["no-source", "empty-source", "no-match"],
)
def test_no_signal_cases_keep_their_distinction(reports: Any, status: EvaluationStatus) -> None:
    assessment = assess_transaction(usdt_payment(), reports)

    assert assessment.address_evidence.evaluation_status is status
    assert assessment.signals == ()
    # No review recommended, but nothing is declared safe: still indeterminate.
    assert assessment.manual_review_recommended is False
    assert_indeterminate(assessment)


def test_none_and_empty_sources_are_distinct() -> None:
    none = assess_transaction(usdt_payment(), None)
    empty = assess_transaction(usdt_payment(), [])

    assert none.address_evidence.supplied_report_count is None
    assert empty.address_evidence.supplied_report_count == 0
    assert none != empty


def test_success_without_usdt_events() -> None:
    assessment = assess_transaction(inspect(eth_tx(), []), [report(BOB)])

    assert assessment.features.usdt_transfer_count == 0
    assert assessment.features.transfer_data_available is True
    assert assessment.signals == ()
    assert assessment.manual_review_recommended is False


def test_reverted_matches_only_transaction_addresses() -> None:
    inspection = inspect(eth_tx(TransactionStatus.REVERTED), [])

    assessment = assess_transaction(inspection, [report(ALICE), report(BOB, "R-2")])

    assert assessment.transaction_status is TransactionStatus.REVERTED
    assert assessment.features.usdt_transfer_count == 0
    assert [(s.address, s.observed_roles) for s in assessment.signals] == [
        (ALICE, (ObservedRole.TRANSACTION_SENDER,))
    ]
    assert_indeterminate(assessment)


@pytest.mark.parametrize(
    ("transaction", "reports"),
    [
        (eth_tx(TransactionStatus.PENDING), [report(ALICE), report(BOB, "R-2")]),
        (tron_tx(TransactionStatus.UNCONFIRMED),
         [report(TRON_ALICE, network=Network.TRON), report(TRON_BOB, "R-2", network=Network.TRON)]),
    ],
    ids=["ethereum-pending", "tron-unconfirmed"],
)
def test_non_final_transaction_never_invents_transfers(
    transaction: NormalizedTransaction, reports: list[AddressReport]
) -> None:
    assessment = assess_transaction(inspect(transaction, None), reports)

    assert assessment.transaction_status is transaction.status
    assert assessment.features.transfer_data_available is False
    assert assessment.features.usdt_transfer_count is None
    # Only the known sender can match; no USDT transfer role is invented.
    assert [s.observed_roles for s in assessment.signals] == [(ObservedRole.TRANSACTION_SENDER,)]
    assert assessment.manual_review_recommended is True


@pytest.mark.parametrize("transaction", [eth_tx(TransactionStatus.NOT_FOUND),
                                         tron_tx(TransactionStatus.NOT_FOUND)])
def test_not_found_has_no_signal(transaction: NormalizedTransaction) -> None:
    supplied = (report(ALICE) if transaction.network is Network.ETHEREUM
                else report(TRON_ALICE, network=Network.TRON))

    assessment = assess_transaction(inspect(transaction, None), [supplied])

    assert assessment.address_evidence.evaluation_status is (
        EvaluationStatus.NO_OBSERVABLE_ADDRESSES
    )
    assert assessment.signals == ()
    assert assessment.manual_review_recommended is False
    assert_indeterminate(assessment)


# --- Duplicates, determinism, immutability, purity ------------------------------------


def test_identical_duplicates_give_a_single_signal() -> None:
    assessment = assess_transaction(usdt_payment(), [report(BOB)] * 3)

    assert len(assessment.signals) == 1


def test_contradictory_duplicates_are_rejected() -> None:
    conflicting = report(BOB, claim_category=ClaimCategory.THEFT_ALLEGATION)

    with pytest.raises(ConflictingReportError):
        assess_transaction(usdt_payment(), [report(BOB), conflicting])


def test_result_is_deterministic_and_order_independent() -> None:
    reports = [report(BOB, "R-2"), report(ALICE, "R-1"), report(ETH_USDT, "R-3")]

    dumps = {
        assess_transaction(usdt_payment(), ordering).model_dump_json()
        for ordering in (reports, list(reversed(reports)), reports[1:] + reports[:1])
    }

    assert len(dumps) == 1


def test_models_are_immutable() -> None:
    assessment = assess_transaction(usdt_payment(), [report(BOB)])

    with pytest.raises(ValidationError):
        assessment.manual_review_recommended = False  # type: ignore[misc]
    with pytest.raises(ValidationError):
        assessment.risk_determination = "fraudulent"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        assessment.signals[0].evidence_status = "verified"  # type: ignore[misc]
    assert isinstance(assessment.signals, tuple)


def test_inputs_are_not_mutated() -> None:
    inspection = usdt_payment()
    reports = [report(BOB), report(ALICE, "R-2")]
    snapshot = (inspection.model_dump_json(), [r.model_dump_json() for r in reports])
    reports_copy = copy.copy(reports)

    assess_transaction(inspection, reports)

    assert (inspection.model_dump_json(), [r.model_dump_json() for r in reports]) == snapshot
    assert reports == reports_copy


def test_features_come_from_the_existing_engine() -> None:
    inspection = usdt_payment()

    assert assess_transaction(inspection, None).features == extract_transaction_features(inspection)


# --- Model consistency ------------------------------------------------------------------


def _valid(**overrides: Any) -> dict[str, Any]:
    assessment = assess_transaction(usdt_payment(), [report(BOB)])
    fields = {name: getattr(assessment, name) for name in TransactionRiskAssessment.model_fields}
    fields.update(overrides)
    return fields


def test_valid_assessment_can_be_rebuilt() -> None:
    expected = assess_transaction(usdt_payment(), [report(BOB)])

    assert TransactionRiskAssessment(**_valid()) == expected


@pytest.mark.parametrize(
    "overrides",
    [
        {"network": Network.TRON},
        {"tx_hash": "0x" + "ef" * 32},
        {"transaction_status": TransactionStatus.REVERTED},
        {"signals": ()},  # matches exist but no signal
        {"manual_review_recommended": False},  # signal exists
        {"risk_determination": "fraudulent"},
        {"risk_determination": "high"},
        {"determination_basis": "verified_evidence"},
        {"manual_review_recommended": 1},  # strict bool
        {"risk_score": 87},
        {"fraud_probability": 0.9},
    ],
)
def test_inconsistent_or_forbidden_values_are_rejected(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        TransactionRiskAssessment(**_valid(**overrides))


def test_review_cannot_be_recommended_without_a_signal() -> None:
    fields = _valid()
    fields.update(
        address_evidence=match_address_reports(usdt_payment(), None),
        signals=(),
        manual_review_recommended=True,
    )

    with pytest.raises(ValidationError, match="manual review"):
        TransactionRiskAssessment(**fields)


def test_signal_without_a_matching_evidence_is_rejected() -> None:
    real = assess_transaction(usdt_payment(), [report(BOB)]).signals[0]
    forged = RiskSignal(**{**real.model_dump(), "report_id": "FORGED-1"})
    unobserved = RiskSignal(**{**real.model_dump(), "address": CAROL})

    for signal in (forged, unobserved):
        with pytest.raises(ValidationError, match="correspond"):
            TransactionRiskAssessment(**_valid(signals=(signal,)))
    with pytest.raises(ValidationError, match="correspond"):
        TransactionRiskAssessment(**_valid(signals=(real, real)))


@pytest.mark.parametrize(
    "overrides",
    [
        {"signal_code": "large_amount"},
        {"signal_code": "multiple_transfers"},
        {"evidence_status": "verified"},
        {"evidence_status": "confirmed"},
        {"observed_roles": ()},
        {"reported_at": datetime(2026, 5, 1)},  # naive
        {"extra": True},
    ],
)
def test_invalid_signals_are_rejected(overrides: dict) -> None:
    real = assess_transaction(usdt_payment(), [report(BOB)]).signals[0]

    with pytest.raises(ValidationError):
        RiskSignal(**{**real.model_dump(), **overrides})


# --- No numeric score, no automatic conclusion -------------------------------------------


def test_only_allowed_codes_and_determination_exist() -> None:
    assert [c.value for c in SignalCode] == ["unverified_address_allegation_match"]
    assert [s.value for s in EvidenceStatus] == ["unverified"]
    assert [d.value for d in RiskDetermination] == ["indeterminate"]


def test_no_numeric_score_level_or_probability_field() -> None:
    forbidden = ("score", "level", "probability", "fraud", "confidence", "weight", "verdict")
    fields = set(TransactionRiskAssessment.model_fields) | set(RiskSignal.model_fields)

    assert not [f for f in fields if any(word in f for word in forbidden)]
    numeric_top_level = [
        name for name, info in TransactionRiskAssessment.model_fields.items()
        if info.annotation in (int, float)
    ]
    assert numeric_top_level == []


def test_large_amounts_or_many_transfers_alone_produce_no_signal() -> None:
    transfers = [transfer(ALICE, BOB, MAX_UINT256, i) for i in range(5)]

    assessment = assess_transaction(inspect(eth_tx(), transfers), [report(CAROL)])

    assert assessment.features.gross_usdt_event_amount_atomic == 5 * MAX_UINT256
    assert assessment.signals == ()
    assert assessment.manual_review_recommended is False
    assert_indeterminate(assessment)


def test_reported_address_does_not_flag_other_participants() -> None:
    inspection = inspect(eth_tx(), [transfer(ALICE, BOB, 1, 0), transfer(BOB, CAROL, 1, 1)])

    assessment = assess_transaction(inspection, [report(BOB)])

    assert {s.address for s in assessment.signals} == {BOB}


def test_every_status_stays_indeterminate() -> None:
    cases = [
        (inspect(eth_tx(), [transfer(ALICE, BOB)]), [report(BOB)]),
        (inspect(eth_tx(TransactionStatus.REVERTED), []), None),
        (inspect(eth_tx(TransactionStatus.PENDING), None), []),
        (inspect(tron_tx(TransactionStatus.UNCONFIRMED), None), None),
        (inspect(eth_tx(TransactionStatus.NOT_FOUND), None), [report(ALICE)]),
    ]

    for inspection, reports in cases:
        assert_indeterminate(assess_transaction(inspection, reports))


# --- Precision and serialization -----------------------------------------------------------


def test_large_amounts_are_preserved_through_serialization() -> None:
    transfers = [transfer(ALICE, BOB, MAX_UINT256, 0), transfer(BOB, CAROL, MAX_UINT256, 1)]
    assessment = assess_transaction(inspect(eth_tx(), transfers), [report(BOB)])

    dumped = assessment.model_dump_json()
    parsed = json.loads(dumped, parse_float=lambda _: pytest.fail("float found"))

    assert parsed["features"]["gross_usdt_event_amount_atomic"] == 2 * MAX_UINT256
    assert parsed["features"]["max_usdt_transfer_amount_atomic"] == MAX_UINT256
    assert TransactionRiskAssessment.model_validate_json(dumped) == assessment


def test_assessment_needs_no_network() -> None:
    # The socket guard is active: any I/O attempt would fail this test.
    supplied = report(BOB, source_reference="https://example.invalid/fictional/not-fetched")

    assert assess_transaction(usdt_payment(), [supplied]).manual_review_recommended is True
