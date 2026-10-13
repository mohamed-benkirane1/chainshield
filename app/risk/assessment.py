"""Explainable assessment of a transaction from facts and unverified reports.

This module assembles two existing, independent results without merging them:

* ``TransactionFeatures``: facts derived from the chain data;
* ``AddressEvidenceAssessment``: matches against caller-supplied reports.

It produces no score, no level and no probability. ChainShield v1 has no
verified evidence: an unverified allegation cannot establish that a
transaction is fraudulent, so ``risk_determination`` is always
``indeterminate`` and ``determination_basis`` states why.

``manual_review_recommended`` is True only when a supplied report matched an
address actually observed in the transaction. It means that an allegation
deserves human examination, not that the address or any other participant
did anything wrong. False never means "safe": it may simply reflect that no
report was supplied or that none matched.

A declared source type (even ``public_authority``) gives no implicit
credibility: every signal is ``unverified``.
"""

from collections.abc import Iterable
from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictStr, model_validator

from app.domain.analysis_input import Network
from app.features.transaction_features import TransactionFeatures, extract_transaction_features
from app.providers.base import TransactionStatus
from app.risk.address_evidence import (
    AddressEvidenceAssessment,
    AddressReport,
    AddressReportMatch,
    ClaimCategory,
    ObservedRole,
    ReportSourceType,
    match_address_reports,
)
from app.services.transaction_analysis import TransactionInspection


class SignalCode(StrEnum):
    # A supplied, unverified allegation names an address observed in the transaction.
    UNVERIFIED_ADDRESS_ALLEGATION_MATCH = "unverified_address_allegation_match"


class EvidenceStatus(StrEnum):
    UNVERIFIED = "unverified"  # no independent verification exists in v1


class RiskDetermination(StrEnum):
    """Outcome of the determination. v1 can only report that it is not determined."""

    INDETERMINATE = "indeterminate"


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RiskSignal(_StrictFrozenModel):
    """A traceable observation worth reviewing, derived from one report match.

    It records who alleged what about which observed address. It is not a
    finding against that address.
    """

    signal_code: SignalCode
    network: Network
    address: StrictStr
    observed_roles: tuple[ObservedRole, ...] = Field(min_length=1)
    source_id: StrictStr
    report_id: StrictStr
    source_type: ReportSourceType
    claim_category: ClaimCategory
    reported_at: AwareDatetime
    evidence_status: EvidenceStatus

    @classmethod
    def from_match(cls, match: AddressReportMatch) -> "RiskSignal":
        return cls(
            signal_code=SignalCode.UNVERIFIED_ADDRESS_ALLEGATION_MATCH,
            network=match.network,
            address=match.address,
            observed_roles=match.observed_roles,
            source_id=match.source_id,
            report_id=match.report_id,
            source_type=match.source_type,
            claim_category=match.claim_category,
            reported_at=match.reported_at,
            evidence_status=EvidenceStatus.UNVERIFIED,
        )


class TransactionRiskAssessment(_StrictFrozenModel):
    """Facts, report matches and review recommendation for one transaction.

    ``risk_determination`` is always ``indeterminate`` because no verified
    evidence is available (``determination_basis``). There is deliberately no
    score, level or probability field.
    """

    network: Network
    tx_hash: StrictStr
    transaction_status: TransactionStatus
    features: TransactionFeatures
    address_evidence: AddressEvidenceAssessment
    signals: tuple[RiskSignal, ...]
    risk_determination: RiskDetermination
    determination_basis: Literal["no_verified_evidence"]
    manual_review_recommended: bool

    @model_validator(mode="after")
    def _check_consistency(self) -> "TransactionRiskAssessment":
        identity = (self.network, self.tx_hash)
        if (self.features.network, self.features.tx_hash) != identity or (
            self.address_evidence.network,
            self.address_evidence.tx_hash,
        ) != identity:
            raise ValueError("features and address evidence must describe this transaction")
        if self.features.transaction_status is not self.transaction_status:
            raise ValueError("transaction_status must match the features")
        expected = tuple(RiskSignal.from_match(m) for m in self.address_evidence.matches)
        if self.signals != expected:
            raise ValueError("signals must correspond exactly to the address evidence matches")
        if self.manual_review_recommended != bool(self.signals):
            raise ValueError("manual review is recommended exactly when a signal exists")
        return self


def assess_transaction(
    inspection: TransactionInspection, reports: Iterable[AddressReport] | None
) -> TransactionRiskAssessment:
    """Assess an inspected transaction. Pure: no I/O, no mutation, deterministic.

    ``reports`` follows ``match_address_reports``: ``None`` means no report
    source, an empty iterable means an empty source; it is consumed once and
    conflicting records raise ``ConflictingReportError``.
    """
    features = extract_transaction_features(inspection)
    evidence = match_address_reports(inspection, reports)
    signals = tuple(RiskSignal.from_match(match) for match in evidence.matches)
    return TransactionRiskAssessment(
        network=inspection.network,
        tx_hash=inspection.tx_hash,
        transaction_status=inspection.transaction.status,
        features=features,
        address_evidence=evidence,
        signals=signals,
        risk_determination=RiskDetermination.INDETERMINATE,
        determination_basis="no_verified_evidence",
        manual_review_recommended=bool(signals),
    )
