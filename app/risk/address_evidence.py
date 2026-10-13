"""Match the addresses observed in a transaction against supplied reports.

An ``AddressReport`` records an allegation made by a source about an
address. It is NOT proof that the address committed fraud, and neither the
declared source type nor the claim category guarantees the source's
reliability. Nothing here verifies a report, weighs its credibility or merges
reports from different sources into a stronger claim.

A match only says that an address listed in a supplied report was observed
in the transaction, in the given roles. It does not accuse the transaction's
initiator or any other participant. Conversely, no match only means "no
correspondence in the supplied reports", never "safe address".

Reports are caller-supplied data: nothing is fetched, scraped or executed,
and ``source_reference`` is opaque metadata that is never dereferenced.
"""

from collections.abc import Iterable
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    Strict,
    StrictStr,
    ValidationInfo,
    field_validator,
    model_validator,
)

from app.domain.analysis_input import Network, normalize_transaction_hash
from app.domain.usdt_registry import normalize_contract_address
from app.services.transaction_analysis import TransactionInspection

# Visible text without control characters or surrounding whitespace.
_IDENTIFIER_PATTERN = r"^[^\s\x00-\x1f\x7f](?:[^\x00-\x1f\x7f]*[^\s\x00-\x1f\x7f])?$"
_Identifier = Annotated[
    StrictStr, Field(min_length=1, max_length=200, pattern=_IDENTIFIER_PATTERN)
]
_Reference = Annotated[
    StrictStr, Field(min_length=1, max_length=2048, pattern=_IDENTIFIER_PATTERN)
]
_StrictAwareDatetime = Annotated[AwareDatetime, Strict()]
_Count = Annotated[int, Strict(), Field(ge=0)]


class ReportSourceType(StrEnum):
    """Kind of source, as declared by whoever supplied the report (unverified)."""

    COMMUNITY_REPORT = "community_report"
    SECURITY_VENDOR = "security_vendor"
    PUBLIC_AUTHORITY = "public_authority"
    INTERNAL_ANALYST = "internal_analyst"
    OTHER = "other"


class ClaimCategory(StrEnum):
    """What the source alleges about the address. Every value is an allegation."""

    SCAM_ALLEGATION = "scam_allegation"
    PHISHING_ALLEGATION = "phishing_allegation"
    IMPERSONATION_ALLEGATION = "impersonation_allegation"
    THEFT_ALLEGATION = "theft_allegation"
    OTHER_ALLEGATION = "other_allegation"


class ObservedRole(StrEnum):
    """Where an address appears in the inspected data (declaration order is canonical).

    ``transaction_recipient`` is the address the transaction was sent to, which
    is often a smart contract (e.g. the USDT contract or a router), not the
    economic recipient of funds.
    """

    TRANSACTION_SENDER = "transaction_sender"
    TRANSACTION_RECIPIENT = "transaction_recipient"
    USDT_TRANSFER_SENDER = "usdt_transfer_sender"
    USDT_TRANSFER_RECIPIENT = "usdt_transfer_recipient"


_ROLE_ORDER = {role: index for index, role in enumerate(ObservedRole)}


class EvaluationStatus(StrEnum):
    NO_REPORT_SOURCE = "no_report_source"  # reports=None: nothing was supplied
    EMPTY_REPORT_SOURCE = "empty_report_source"  # a collection with no report
    NO_OBSERVABLE_ADDRESSES = "no_observable_addresses"
    NO_MATCH_IN_SUPPLIED_REPORTS = "no_match_in_supplied_reports"
    MATCHES_FOUND = "matches_found"


class ConflictingReportError(ValueError):
    """Two supplied records share (source_id, report_id) but differ."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _canonical_address(value: object, info: ValidationInfo) -> str:
    network = info.data.get("network")
    if network is None:
        raise ValueError("address cannot be validated without a valid network")
    if not isinstance(value, str):
        raise ValueError("address must be a string")
    return normalize_contract_address(network, value)


class AddressReport(_FrozenModel):
    """An allegation about an address, as supplied by a source. Not a proof."""

    network: Network
    address: StrictStr
    source_id: _Identifier
    report_id: _Identifier
    source_type: ReportSourceType
    claim_category: ClaimCategory
    reported_at: _StrictAwareDatetime
    source_reference: _Reference | None = None  # opaque metadata, never fetched

    @field_validator("address")
    @classmethod
    def _canonical(cls, value: object, info: ValidationInfo) -> str:
        return _canonical_address(value, info)


class AddressReportMatch(_FrozenModel):
    """A supplied report whose address was observed in the transaction."""

    network: Network
    address: StrictStr
    source_id: _Identifier
    report_id: _Identifier
    source_type: ReportSourceType
    claim_category: ClaimCategory
    reported_at: _StrictAwareDatetime
    observed_roles: tuple[ObservedRole, ...] = Field(min_length=1)
    allegation_verified: Literal[False] = False

    @field_validator("address")
    @classmethod
    def _canonical(cls, value: object, info: ValidationInfo) -> str:
        return _canonical_address(value, info)

    @field_validator("observed_roles")
    @classmethod
    def _check_roles(cls, roles: tuple[ObservedRole, ...]) -> tuple[ObservedRole, ...]:
        if list(roles) != sorted(set(roles), key=_ROLE_ORDER.__getitem__):
            raise ValueError("observed_roles must be unique and in canonical order")
        return roles


class AddressEvidenceAssessment(_FrozenModel):
    """Result of matching one inspected transaction against supplied reports.

    ``supplied_report_count`` counts distinct (source_id, report_id) records
    and is ``None`` when no report source was supplied.
    """

    network: Network
    tx_hash: StrictStr
    evaluation_status: EvaluationStatus
    supplied_report_count: _Count | None
    observed_address_count: _Count
    matches: tuple[AddressReportMatch, ...]

    @model_validator(mode="after")
    def _check_consistency(self) -> "AddressEvidenceAssessment":
        if normalize_transaction_hash(self.network, self.tx_hash) != self.tx_hash:
            raise ValueError("tx_hash must be in canonical form")
        count, observed, matches = (
            self.supplied_report_count,
            self.observed_address_count,
            self.matches,
        )
        expected = _status_for(count, observed, bool(matches))
        if expected is not self.evaluation_status:
            raise ValueError("evaluation_status does not match the counts and matches")
        if matches:
            keys = [(m.address, m.source_id, m.report_id) for m in matches]
            if keys != sorted(set(keys)):
                raise ValueError("matches must be unique and sorted")
            if any(m.network is not self.network for m in matches):
                raise ValueError("matches must be on the inspected network")
            if len({(m.source_id, m.report_id) for m in matches}) != len(matches):
                raise ValueError("a report can match only once")
            if len(matches) > count or len({m.address for m in matches}) > observed:
                raise ValueError("more matches than supplied reports or observed addresses")
        return self


def _status_for(count: int | None, observed: int, has_matches: bool) -> EvaluationStatus:
    if count is None:
        return EvaluationStatus.NO_REPORT_SOURCE
    if count == 0:
        return EvaluationStatus.EMPTY_REPORT_SOURCE
    if observed == 0:
        return EvaluationStatus.NO_OBSERVABLE_ADDRESSES
    if not has_matches:
        return EvaluationStatus.NO_MATCH_IN_SUPPLIED_REPORTS
    return EvaluationStatus.MATCHES_FOUND


def observed_address_roles(inspection: TransactionInspection) -> dict[str, set[ObservedRole]]:
    """Canonical addresses observed in the inspection, with their roles.

    Uses the transaction's sender and recipient when known and the official
    USDT transfers when available; never infers executed transfers.
    """
    network = inspection.network
    roles: dict[str, set[ObservedRole]] = {}

    def add(address: str | None, role: ObservedRole) -> None:
        if address is not None:
            roles.setdefault(normalize_contract_address(network, address), set()).add(role)

    add(inspection.transaction.from_address, ObservedRole.TRANSACTION_SENDER)
    add(inspection.transaction.to_address, ObservedRole.TRANSACTION_RECIPIENT)
    for transfer in inspection.usdt_transfers or ():
        add(transfer.from_address, ObservedRole.USDT_TRANSFER_SENDER)
        add(transfer.to_address, ObservedRole.USDT_TRANSFER_RECIPIENT)
    return roles


def match_address_reports(
    inspection: TransactionInspection, reports: Iterable[AddressReport] | None
) -> AddressEvidenceAssessment:
    """Match supplied reports against the inspection. Pure: no I/O, no mutation.

    ``reports=None`` means no report source was supplied; an empty iterable
    means a source with no report. The iterable is consumed once. Identical
    duplicates are merged; records sharing (source_id, report_id) with
    different content raise ``ConflictingReportError``.
    """
    observed = observed_address_roles(inspection)
    identity = {"network": inspection.network, "tx_hash": inspection.tx_hash}
    if reports is None:
        return AddressEvidenceAssessment(
            **identity,
            evaluation_status=EvaluationStatus.NO_REPORT_SOURCE,
            supplied_report_count=None,
            observed_address_count=len(observed),
            matches=(),
        )

    unique: dict[tuple[str, str], AddressReport] = {}
    for report in reports:
        if not isinstance(report, AddressReport):
            raise TypeError("reports must be AddressReport instances")
        key = (report.source_id, report.report_id)
        existing = unique.setdefault(key, report)
        if existing != report:
            raise ConflictingReportError(
                "conflicting records share the same (source_id, report_id)"
            )

    matches = sorted(
        (
            AddressReportMatch(
                network=report.network,
                address=report.address,
                source_id=report.source_id,
                report_id=report.report_id,
                source_type=report.source_type,
                claim_category=report.claim_category,
                reported_at=report.reported_at,
                observed_roles=tuple(
                    sorted(observed[report.address], key=_ROLE_ORDER.__getitem__)
                ),
            )
            for report in unique.values()
            if report.network is inspection.network and report.address in observed
        ),
        key=lambda m: (m.address, m.source_id, m.report_id),
    )
    return AddressEvidenceAssessment(
        **identity,
        evaluation_status=_status_for(len(unique), len(observed), bool(matches)),
        supplied_report_count=len(unique),
        observed_address_count=len(observed),
        matches=tuple(matches),
    )
