"""Tests for address evidence matching.

Every report below is FICTIONAL test data: the sources, identifiers and
allegations do not exist and say nothing about the real owners of these
addresses (which are standard checksum test vectors or synthetic values).
"""

import copy
import json
import socket
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import base58
import pytest
from pydantic import ValidationError

from app.domain.analysis_input import Network
from app.domain.token_transfer import NormalizedTokenTransfer
from app.providers.base import NativeUnit, NormalizedTransaction, TransactionStatus
from app.risk.address_evidence import (
    AddressEvidenceAssessment,
    AddressReport,
    AddressReportMatch,
    ClaimCategory,
    ConflictingReportError,
    EvaluationStatus,
    ObservedRole,
    ReportSourceType,
    match_address_reports,
    observed_address_roles,
)
from app.services.transaction_analysis import TransactionInspection

ETH_HASH = "0x" + "ab" * 32
TRON_HASH = "cd" * 32
ETH_USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
BOB = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
CAROL = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
DAVE = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
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


def eth_tx(status: TransactionStatus = TransactionStatus.SUCCESS, sender: str = ALICE,
           to: str | None = ETH_USDT) -> NormalizedTransaction:
    fields: dict[str, Any] = {"network": Network.ETHEREUM, "tx_hash": ETH_HASH, "status": status}
    if status is not TransactionStatus.NOT_FOUND:
        fields.update(from_address=sender, to_address=to,
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


def transfer(sender: str, recipient: str, log_index: int = 0) -> NormalizedTokenTransfer:
    return NormalizedTokenTransfer(
        network=Network.ETHEREUM, tx_hash=ETH_HASH, token_symbol="USDT",
        token_contract=ETH_USDT, from_address=sender, to_address=recipient,
        amount_atomic=35_000_000, decimals=6, log_index=log_index,
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
    # ALICE calls the USDT contract, which records a transfer ALICE -> BOB.
    return inspect(eth_tx(), [transfer(ALICE, BOB)])


def roles_by_address(assessment: AddressEvidenceAssessment) -> dict[str, tuple]:
    return {m.address: m.observed_roles for m in assessment.matches}


# --- Matching on each role ------------------------------------------------------------


def test_match_on_usdt_transfer_recipient() -> None:
    assessment = match_address_reports(usdt_payment(), [report(BOB)])

    assert assessment.evaluation_status is EvaluationStatus.MATCHES_FOUND
    assert assessment.supplied_report_count == 1
    assert assessment.observed_address_count == 3  # ALICE, USDT contract, BOB
    assert assessment.matches == (
        AddressReportMatch(
            network=Network.ETHEREUM,
            address=BOB,
            source_id="fictional-test-source",
            report_id="FICTIONAL-1",
            source_type=ReportSourceType.COMMUNITY_REPORT,
            claim_category=ClaimCategory.SCAM_ALLEGATION,
            reported_at=REPORTED_AT,
            observed_roles=(ObservedRole.USDT_TRANSFER_RECIPIENT,),
        ),
    )
    assert assessment.matches[0].allegation_verified is False


def test_match_on_sender_with_several_roles() -> None:
    assessment = match_address_reports(usdt_payment(), [report(ALICE)])

    assert roles_by_address(assessment) == {
        ALICE: (ObservedRole.TRANSACTION_SENDER, ObservedRole.USDT_TRANSFER_SENDER)
    }


def test_match_on_transaction_recipient_contract() -> None:
    # The transaction recipient is the token contract, not the funds' recipient.
    assessment = match_address_reports(usdt_payment(), [report(ETH_USDT)])

    assert roles_by_address(assessment) == {ETH_USDT: (ObservedRole.TRANSACTION_RECIPIENT,)}


def test_same_address_with_all_four_roles_is_one_match() -> None:
    inspection = inspect(eth_tx(sender=ALICE, to=ALICE), [transfer(ALICE, ALICE)])

    assessment = match_address_reports(inspection, [report(ALICE)])

    assert len(assessment.matches) == 1
    assert assessment.matches[0].observed_roles == tuple(ObservedRole)
    assert assessment.observed_address_count == 1


def test_several_independent_reports_on_a_single_observed_address() -> None:
    # Contract creation: the sender is the only observable address.
    inspection = inspect(eth_tx(to=None), [])
    reports = [
        report(ALICE, "F-1", source_id="fictional-source-a"),
        report(ALICE, "F-2", source_id="fictional-source-b",
               claim_category=ClaimCategory.PHISHING_ALLEGATION),
        report(ALICE, "F-3", source_id="fictional-source-c",
               source_type=ReportSourceType.SECURITY_VENDOR),
    ]

    assessment = match_address_reports(inspection, reports)

    assert assessment.observed_address_count == 1
    assert assessment.supplied_report_count == 3
    assert len(assessment.matches) == 3
    assert assessment.evaluation_status is EvaluationStatus.MATCHES_FOUND
    # Each provenance is kept as its own allegation, none merged into another.
    assert [(m.source_id, m.report_id, m.claim_category) for m in assessment.matches] == [
        ("fictional-source-a", "F-1", ClaimCategory.SCAM_ALLEGATION),
        ("fictional-source-b", "F-2", ClaimCategory.PHISHING_ALLEGATION),
        ("fictional-source-c", "F-3", ClaimCategory.SCAM_ALLEGATION),
    ]
    assert all(m.address == ALICE for m in assessment.matches)
    assert all(m.observed_roles == (ObservedRole.TRANSACTION_SENDER,) for m in assessment.matches)
    assert all(m.allegation_verified is False for m in assessment.matches)


def test_identical_duplicates_still_merge_alongside_independent_reports() -> None:
    inspection = inspect(eth_tx(to=None), [])
    first = report(ALICE, "F-1", source_id="fictional-source-a")
    second = report(ALICE, "F-2", source_id="fictional-source-b")

    assessment = match_address_reports(inspection, [first, second, first, second])

    assert assessment.supplied_report_count == 2
    assert len(assessment.matches) == 2
    with pytest.raises(ConflictingReportError):
        match_address_reports(
            inspection, [first, report(ALICE, "F-1", source_id="fictional-source-a",
                                       claim_category=ClaimCategory.THEFT_ALLEGATION)]
        )


def test_model_accepts_more_matches_than_observed_addresses() -> None:
    inspection = inspect(eth_tx(to=None), [])
    reports = [report(ALICE, f"F-{i}", source_id=f"fictional-source-{i}") for i in range(3)]
    valid = match_address_reports(inspection, reports)

    rebuilt = AddressEvidenceAssessment(**valid.model_dump())

    assert rebuilt == valid
    assert len(rebuilt.matches) > rebuilt.observed_address_count


def test_model_rejects_more_distinct_matched_addresses_than_observed() -> None:
    inspection = inspect(eth_tx(to=None), [])
    alice = match_address_reports(inspection, [report(ALICE, "F-1")]).matches[0]
    bob = AddressReportMatch(**{**alice.model_dump(), "address": BOB, "report_id": "F-2"})

    with pytest.raises(ValidationError, match="observed addresses"):
        AddressEvidenceAssessment(
            network=Network.ETHEREUM,
            tx_hash=ETH_HASH,
            evaluation_status=EvaluationStatus.MATCHES_FOUND,
            supplied_report_count=2,
            observed_address_count=1,
            matches=(alice, bob),
        )


def test_tron_match() -> None:
    inspection = inspect(tron_tx(), [tron_transfer()])
    tron_report = report(TRON_BOB, network=Network.TRON)

    assessment = match_address_reports(inspection, [tron_report])

    assert assessment.network is Network.TRON
    assert roles_by_address(assessment) == {TRON_BOB: (ObservedRole.USDT_TRANSFER_RECIPIENT,)}


# --- Several reports and provenance ---------------------------------------------------


def test_several_reports_are_kept_separately_in_deterministic_order() -> None:
    reports = [
        report(BOB, "R-2", source_id="fictional-source-b",
               claim_category=ClaimCategory.PHISHING_ALLEGATION),
        report(ALICE, "R-9", source_id="fictional-source-a"),
        report(BOB, "R-1", source_id="fictional-source-a"),
        report(CAROL, "R-3"),  # not observed
    ]

    assessment = match_address_reports(usdt_payment(), reports)

    assert [(m.address, m.source_id, m.report_id) for m in assessment.matches] == [
        (ALICE, "fictional-source-a", "R-9"),
        (BOB, "fictional-source-a", "R-1"),
        (BOB, "fictional-source-b", "R-2"),
    ]
    assert assessment.supplied_report_count == 4
    # Two sources on BOB stay two allegations: no merged "confirmed" record.
    assert {m.claim_category for m in assessment.matches if m.address == BOB} == {
        ClaimCategory.SCAM_ALLEGATION,
        ClaimCategory.PHISHING_ALLEGATION,
    }


def test_order_does_not_depend_on_input_order() -> None:
    reports = [report(BOB, "R-2"), report(ALICE, "R-1"), report(ETH_USDT, "R-3")]

    first = match_address_reports(usdt_payment(), reports)
    second = match_address_reports(usdt_payment(), list(reversed(reports)))

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_identical_duplicates_are_merged() -> None:
    assessment = match_address_reports(usdt_payment(), [report(BOB), report(BOB), report(BOB)])

    assert assessment.supplied_report_count == 1
    assert len(assessment.matches) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"address": CAROL},
        {"claim_category": ClaimCategory.THEFT_ALLEGATION},
        {"source_type": ReportSourceType.SECURITY_VENDOR},
        {"reported_at": REPORTED_AT + timedelta(seconds=1)},
        {"source_reference": "fictional-case-42"},
        {"network": Network.TRON, "address": TRON_BOB},
    ],
)
def test_contradictory_duplicates_are_rejected(change: dict) -> None:
    with pytest.raises(ConflictingReportError):
        match_address_reports(usdt_payment(), [report(BOB), report(**{"address": BOB, **change})])


def test_same_report_id_from_different_sources_is_not_a_duplicate() -> None:
    reports = [
        report(BOB, "R-1", source_id="fictional-a"),
        report(CAROL, "R-1", source_id="fictional-b"),
    ]

    assessment = match_address_reports(usdt_payment(), reports)

    assert assessment.supplied_report_count == 2
    assert [m.source_id for m in assessment.matches] == ["fictional-a"]


def test_report_from_another_network_never_matches() -> None:
    reports = [report(TRON_ALICE, network=Network.TRON)]

    assessment = match_address_reports(usdt_payment(), reports)

    assert assessment.evaluation_status is EvaluationStatus.NO_MATCH_IN_SUPPLIED_REPORTS
    assert assessment.supplied_report_count == 1


def test_tron_body_of_ethereum_address_is_not_a_match() -> None:
    # Same 20 bytes on another chain are a different account.
    body = bytes.fromhex(ALICE[2:])
    tron_twin = base58.b58encode_check(b"\x41" + body).decode()
    inspection = inspect(tron_tx(), [tron_transfer()])

    assessment = match_address_reports(inspection, [report(ALICE)])
    assert assessment.matches == ()
    twin_report = report(tron_twin, network=Network.TRON)
    assert match_address_reports(usdt_payment(), [twin_report]).matches == ()


# --- Canonical addresses and validation ------------------------------------------------


@pytest.mark.parametrize("address", [BOB.lower(), "0x" + BOB[2:].upper(), BOB])
def test_ethereum_addresses_are_canonicalized_before_matching(address: str) -> None:
    supplied = report(address)

    assert supplied.address == BOB
    assert len(match_address_reports(usdt_payment(), [supplied]).matches) == 1


@pytest.mark.parametrize(
    ("network", "address"),
    [
        (Network.ETHEREUM, BOB[:-1] + ("a" if BOB[-1] != "a" else "b")),  # bad checksum
        (Network.ETHEREUM, BOB[2:]),
        (Network.ETHEREUM, "0x1234"),
        (Network.ETHEREUM, TRON_BOB),
        (Network.ETHEREUM, ""),
        (Network.TRON, TRON_BOB.lower()),
        (Network.TRON, BOB),
        (Network.TRON, TRON_BOB[:-1]),
        (Network.ETHEREUM, 123),
    ],
)
def test_malformed_addresses_are_rejected(network: Network, address: object) -> None:
    with pytest.raises(ValidationError):
        report(address, network=network)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"source_id": ""},
        {"source_id": "   "},
        {"source_id": " padded"},
        {"source_id": "line\nbreak"},
        {"source_id": None},
        {"source_id": 42},
        {"report_id": ""},
        {"report_id": "x" * 201},
        {"report_id": "tab\tinside"},
        {"source_reference": ""},
        {"source_reference": "ref\x00"},
        {"source_reference": "r" * 2049},
    ],
)
def test_missing_or_invalid_identifiers_are_rejected(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        report(**overrides)


@pytest.mark.parametrize(
    "reported_at",
    [
        datetime(2026, 5, 1, 12, 0),  # naive
        "2026-05-01T12:00:00Z",  # string in Python mode
        1_746_100_800,  # Unix timestamp
        None,
    ],
)
def test_invalid_timestamps_are_rejected(reported_at: object) -> None:
    with pytest.raises(ValidationError):
        report(reported_at=reported_at)


def test_any_timezone_aware_timestamp_is_accepted() -> None:
    offset = timezone(timedelta(hours=1))

    assert report(reported_at=datetime(2026, 5, 1, 13, tzinfo=offset)).reported_at.tzinfo


@pytest.mark.parametrize(
    "overrides",
    [
        {"network": "Ethereum"},
        {"network": "bitcoin"},
        {"source_type": "verified_source"},
        {"claim_category": "confirmed_fraud"},
        {"claim_category": "scam"},
        {"verified": True},
    ],
)
def test_closed_enums_and_unknown_fields(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        report(**overrides)


def test_report_from_json_is_accepted() -> None:
    raw = json.dumps({
        "network": "tron", "address": TRON_BOB, "source_id": "fictional-json-source",
        "report_id": "J-1", "source_type": "security_vendor",
        "claim_category": "phishing_allegation", "reported_at": "2026-05-01T12:00:00+00:00",
        "source_reference": "https://example.invalid/fictional/1",
    })

    parsed = AddressReport.model_validate_json(raw)

    assert parsed.network is Network.TRON
    assert parsed.reported_at == REPORTED_AT


def test_no_verified_or_confirmed_status_exists() -> None:
    values = {v.value for v in ClaimCategory} | {v.value for v in ReportSourceType}

    assert not any("verified" in v or "confirmed" in v for v in values)
    assert all(v.endswith("_allegation") for v in (c.value for c in ClaimCategory))
    with pytest.raises(ValidationError):
        AddressReportMatch(**{**match_address_reports(usdt_payment(), [report()])
                              .matches[0].model_dump(), "allegation_verified": True})


# --- Evaluation statuses ---------------------------------------------------------------


def test_no_report_source() -> None:
    assessment = match_address_reports(usdt_payment(), None)

    assert assessment.evaluation_status is EvaluationStatus.NO_REPORT_SOURCE
    assert assessment.supplied_report_count is None
    assert assessment.observed_address_count == 3
    assert assessment.matches == ()


@pytest.mark.parametrize(
    "empty", [[], (), set(), iter(())], ids=["list", "tuple", "set", "iterator"]
)
def test_empty_report_source(empty: Any) -> None:
    assessment = match_address_reports(usdt_payment(), empty)

    assert assessment.evaluation_status is EvaluationStatus.EMPTY_REPORT_SOURCE
    assert assessment.supplied_report_count == 0


def test_none_and_empty_are_distinct() -> None:
    none = match_address_reports(usdt_payment(), None)
    empty = match_address_reports(usdt_payment(), [])

    assert none.evaluation_status is not empty.evaluation_status
    assert none.supplied_report_count is None and empty.supplied_report_count == 0


def test_reports_without_match() -> None:
    assessment = match_address_reports(usdt_payment(), [report(CAROL), report(DAVE, "R-2")])

    assert assessment.evaluation_status is EvaluationStatus.NO_MATCH_IN_SUPPLIED_REPORTS
    assert assessment.matches == ()


def test_generator_is_consumed_once() -> None:
    consumed = []

    def generate() -> Iterator[AddressReport]:
        for item in (report(BOB), report(CAROL, "R-2")):
            consumed.append(item.report_id)
            yield item

    assessment = match_address_reports(usdt_payment(), generate())

    assert consumed == ["FICTIONAL-1", "R-2"]
    assert assessment.supplied_report_count == 2


def test_non_report_items_are_rejected() -> None:
    with pytest.raises(TypeError):
        mixed = [report(), {"address": BOB}]
        match_address_reports(usdt_payment(), mixed)  # type: ignore[arg-type]


# --- Transaction statuses ---------------------------------------------------------------


def test_pending_uses_only_known_transaction_addresses() -> None:
    inspection = inspect(eth_tx(TransactionStatus.PENDING), None)

    assessment = match_address_reports(inspection, [report(ALICE), report(BOB, "R-2")])

    assert observed_address_roles(inspection) == {
        ALICE: {ObservedRole.TRANSACTION_SENDER},
        ETH_USDT: {ObservedRole.TRANSACTION_RECIPIENT},
    }
    assert roles_by_address(assessment) == {ALICE: (ObservedRole.TRANSACTION_SENDER,)}


def test_unconfirmed_tron_has_no_invented_transfer_roles() -> None:
    inspection = inspect(tron_tx(TransactionStatus.UNCONFIRMED), None)

    assessment = match_address_reports(
        inspection,
        [
            report(TRON_ALICE, network=Network.TRON),
            report(TRON_BOB, "R-2", network=Network.TRON),
        ],
    )

    assert roles_by_address(assessment) == {TRON_ALICE: (ObservedRole.TRANSACTION_SENDER,)}


@pytest.mark.parametrize(
    "transaction", [eth_tx(TransactionStatus.NOT_FOUND), tron_tx(TransactionStatus.NOT_FOUND)]
)
def test_not_found_has_no_observable_address(transaction: NormalizedTransaction) -> None:
    supplied = report(ALICE) if transaction.network is Network.ETHEREUM else report(
        TRON_ALICE, network=Network.TRON
    )

    assessment = match_address_reports(inspect(transaction, None), [supplied])

    assert assessment.evaluation_status is EvaluationStatus.NO_OBSERVABLE_ADDRESSES
    assert assessment.observed_address_count == 0
    assert assessment.matches == ()


def test_reverted_keeps_transaction_addresses_without_transfers() -> None:
    inspection = inspect(eth_tx(TransactionStatus.REVERTED), [])

    assessment = match_address_reports(inspection, [report(ALICE), report(BOB, "R-2")])

    assert roles_by_address(assessment) == {ALICE: (ObservedRole.TRANSACTION_SENDER,)}
    assert ObservedRole.USDT_TRANSFER_SENDER not in assessment.matches[0].observed_roles


def test_success_without_usdt_transfer() -> None:
    inspection = inspect(eth_tx(to=DAVE), [])

    assessment = match_address_reports(inspection, [report(DAVE)])

    assert assessment.observed_address_count == 2
    assert roles_by_address(assessment) == {DAVE: (ObservedRole.TRANSACTION_RECIPIENT,)}


def test_contract_creation_has_no_recipient_role() -> None:
    inspection = inspect(eth_tx(to=None), [])

    assert observed_address_roles(inspection) == {ALICE: {ObservedRole.TRANSACTION_SENDER}}


def test_multi_transfer_roles_are_grouped() -> None:
    inspection = inspect(eth_tx(to=DAVE), [transfer(ALICE, DAVE, 0), transfer(DAVE, BOB, 1)])

    assessment = match_address_reports(inspection, [report(DAVE)])

    assert roles_by_address(assessment) == {
        DAVE: (
            ObservedRole.TRANSACTION_RECIPIENT,
            ObservedRole.USDT_TRANSFER_SENDER,
            ObservedRole.USDT_TRANSFER_RECIPIENT,
        )
    }


# --- Immutability and purity -------------------------------------------------------------


def test_models_are_immutable() -> None:
    supplied = report()
    assessment = match_address_reports(usdt_payment(), [supplied])

    with pytest.raises(ValidationError):
        supplied.address = ALICE  # type: ignore[misc]
    with pytest.raises(ValidationError):
        assessment.matches[0].observed_roles = ()  # type: ignore[misc]
    with pytest.raises(ValidationError):
        assessment.evaluation_status = EvaluationStatus.NO_REPORT_SOURCE  # type: ignore[misc]
    assert isinstance(assessment.matches, tuple)


def test_inputs_are_not_mutated() -> None:
    inspection = usdt_payment()
    reports = [report(BOB), report(ALICE, "R-2")]
    snapshot = (inspection.model_dump_json(), [r.model_dump_json() for r in reports])
    reports_copy = copy.copy(reports)

    match_address_reports(inspection, reports)

    assert (inspection.model_dump_json(), [r.model_dump_json() for r in reports]) == snapshot
    assert reports == reports_copy


def test_result_is_deterministic() -> None:
    reports = [report(BOB), report(ALICE, "R-2"), report(ETH_USDT, "R-3")]

    results = {match_address_reports(usdt_payment(), reports).model_dump_json() for _ in range(5)}

    assert len(results) == 1


# --- Assessment model consistency --------------------------------------------------------


def _assessment(**overrides: Any) -> dict[str, Any]:
    valid = match_address_reports(usdt_payment(), [report(BOB)]).model_dump()
    valid.update(overrides)
    return valid


@pytest.mark.parametrize(
    "overrides",
    [
        {"evaluation_status": EvaluationStatus.NO_MATCH_IN_SUPPLIED_REPORTS},
        {"supplied_report_count": None},
        {"supplied_report_count": 0},
        {"observed_address_count": 0},
        {"tx_hash": "ab" * 32},
        {"supplied_report_count": 1.0},
        {"extra": True},
        {"matches": ()},  # status says matches found
    ],
)
def test_inconsistent_assessments_are_rejected(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        AddressEvidenceAssessment(**_assessment(**overrides))


def test_duplicate_or_unsorted_matches_are_rejected() -> None:
    match = match_address_reports(usdt_payment(), [report(BOB)]).matches[0]
    other = match_address_reports(usdt_payment(), [report(ALICE, "R-0")]).matches[0]

    with pytest.raises(ValidationError):
        AddressEvidenceAssessment(**_assessment(matches=(match, match), supplied_report_count=2))
    with pytest.raises(ValidationError):
        AddressEvidenceAssessment(**_assessment(matches=(match, other), supplied_report_count=2))


@pytest.mark.parametrize(
    "roles",
    [
        (),
        (ObservedRole.USDT_TRANSFER_SENDER, ObservedRole.TRANSACTION_SENDER),  # unsorted
        (ObservedRole.TRANSACTION_SENDER, ObservedRole.TRANSACTION_SENDER),
        ("ceo_of_scam",),
    ],
)
def test_invalid_observed_roles_are_rejected(roles: tuple) -> None:
    match = match_address_reports(usdt_payment(), [report(BOB)]).matches[0]

    with pytest.raises(ValidationError):
        AddressReportMatch(**{**match.model_dump(), "observed_roles": roles})


# --- No automatic conclusion --------------------------------------------------------------


def test_no_fraud_score_or_verdict_field_exists() -> None:
    forbidden = ("score", "fraud", "risk", "suspicious", "verdict", "confidence", "confirmed")
    fields = (
        set(AddressReport.model_fields)
        | set(AddressReportMatch.model_fields)
        | set(AddressEvidenceAssessment.model_fields)
    )

    assert not [f for f in fields if any(word in f for word in forbidden)]
    assert {status.value for status in EvaluationStatus} == {
        "no_report_source",
        "empty_report_source",
        "no_observable_addresses",
        "no_match_in_supplied_reports",
        "matches_found",
    }


def test_reported_sender_does_not_flag_other_participants() -> None:
    # Only the reported address is matched; ALICE and BOB get nothing attached.
    inspection = inspect(eth_tx(to=DAVE), [transfer(ALICE, DAVE, 0), transfer(DAVE, BOB, 1)])

    assessment = match_address_reports(inspection, [report(DAVE)])

    assert {m.address for m in assessment.matches} == {DAVE}


def test_matching_needs_no_network() -> None:
    # The socket guard is active: any I/O attempt would fail this test.
    reference = report(source_reference="https://example.invalid/fictional/should-not-be-fetched")

    assert len(match_address_reports(usdt_payment(), [reference]).matches) == 1
