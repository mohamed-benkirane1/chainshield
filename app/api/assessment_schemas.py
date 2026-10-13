"""Public JSON contract of the risk assessment endpoint.

Reports in the request are supplied by the client and are never verified,
fetched or enriched. The response carries no score: ``risk_determination``
is always ``indeterminate``.

Atomic amounts are exact decimal strings; counters are JSON integers within
the safe range (helpers shared with ``app.api.schemas``).
"""

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field

from app.api.schemas import (
    DecimalString,
    SafeInteger,
    TransactionInspectionResponse,
    _decimal,
    _ResponseModel,
    _safe_int,
)
from app.domain.analysis_input import Network, TransactionAnalysisRequest
from app.features.transaction_features import TransactionFeatures
from app.providers.base import TransactionStatus
from app.risk.address_evidence import (
    AddressEvidenceAssessment,
    AddressReport,
    AddressReportMatch,
    ClaimCategory,
    EvaluationStatus,
    ObservedRole,
    ReportSourceType,
)
from app.risk.assessment import (
    EvidenceStatus,
    RiskDetermination,
    RiskSignal,
    SignalCode,
    TransactionRiskAssessment,
)
from app.services.transaction_analysis import TransactionInspection

MAX_REPORTS_PER_REQUEST = 50  # operational bound on work per request, not a risk threshold


def _parse_reported_at(value: Any) -> Any:
    # FastAPI validates JSON bodies in Python mode, where AddressReport only
    # accepts datetime objects. Convert an ISO 8601 string here and let
    # AddressReport enforce everything else (timezone, address, identifiers).
    if isinstance(value, dict) and isinstance(value.get("reported_at"), str):
        try:
            parsed = datetime.fromisoformat(value["reported_at"])
        except ValueError:
            raise ValueError("reported_at must be an ISO 8601 date-time") from None
        return {**value, "reported_at": parsed}
    return value


ReportInput = Annotated[AddressReport, BeforeValidator(_parse_reported_at)]


class TransactionAssessmentRequest(TransactionAnalysisRequest):
    """Transaction to assess, with optional client-supplied reports.

    ``reports`` omitted or ``null``: no report source. ``[]``: an explicitly
    empty source. ``source_reference`` is opaque and never fetched.
    """

    reports: list[ReportInput] | None = Field(
        default=None,
        max_length=MAX_REPORTS_PER_REQUEST,
        description="Client-supplied, unverified allegations (at most 50).",
    )


class FeaturesView(_ResponseModel):
    transfer_data_available: bool
    usdt_transfer_count: SafeInteger | None
    has_usdt_transfers: bool | None
    unique_usdt_senders: SafeInteger | None
    unique_usdt_recipients: SafeInteger | None
    unique_usdt_participants: SafeInteger | None
    self_transfer_count: SafeInteger | None
    zero_amount_transfer_count: SafeInteger | None
    gross_usdt_event_amount_atomic: DecimalString | None = Field(
        description="Sum over all USDT Transfer events; not a net or deduplicated volume."
    )
    max_usdt_transfer_amount_atomic: DecimalString | None

    @classmethod
    def from_domain(cls, features: TransactionFeatures) -> "FeaturesView":
        return cls(
            transfer_data_available=features.transfer_data_available,
            usdt_transfer_count=_safe_int(features.usdt_transfer_count),
            has_usdt_transfers=features.has_usdt_transfers,
            unique_usdt_senders=_safe_int(features.unique_usdt_senders),
            unique_usdt_recipients=_safe_int(features.unique_usdt_recipients),
            unique_usdt_participants=_safe_int(features.unique_usdt_participants),
            self_transfer_count=_safe_int(features.self_transfer_count),
            zero_amount_transfer_count=_safe_int(features.zero_amount_transfer_count),
            gross_usdt_event_amount_atomic=_decimal(features.gross_usdt_event_amount_atomic),
            max_usdt_transfer_amount_atomic=_decimal(features.max_usdt_transfer_amount_atomic),
        )


class ReportMatchView(_ResponseModel):
    address: str
    observed_roles: list[ObservedRole]
    source_id: str
    report_id: str
    source_type: ReportSourceType = Field(description="Declared by the client, not verified.")
    claim_category: ClaimCategory
    reported_at: datetime
    allegation_verified: Literal[False]

    @classmethod
    def from_domain(cls, match: AddressReportMatch) -> "ReportMatchView":
        return cls(
            address=match.address,
            observed_roles=list(match.observed_roles),
            source_id=match.source_id,
            report_id=match.report_id,
            source_type=match.source_type,
            claim_category=match.claim_category,
            reported_at=match.reported_at,
            allegation_verified=match.allegation_verified,
        )


class AddressEvidenceView(_ResponseModel):
    evaluation_status: EvaluationStatus
    supplied_report_count: SafeInteger | None = Field(
        description="Distinct reports supplied; null when no report source was supplied."
    )
    observed_address_count: SafeInteger
    matches: list[ReportMatchView]

    @classmethod
    def from_domain(cls, evidence: AddressEvidenceAssessment) -> "AddressEvidenceView":
        return cls(
            evaluation_status=evidence.evaluation_status,
            supplied_report_count=_safe_int(evidence.supplied_report_count),
            observed_address_count=_safe_int(evidence.observed_address_count),
            matches=[ReportMatchView.from_domain(m) for m in evidence.matches],
        )


class RiskSignalView(_ResponseModel):
    signal_code: SignalCode
    address: str
    observed_roles: list[ObservedRole]
    source_id: str
    report_id: str
    source_type: ReportSourceType
    claim_category: ClaimCategory
    reported_at: datetime
    evidence_status: EvidenceStatus

    @classmethod
    def from_domain(cls, signal: RiskSignal) -> "RiskSignalView":
        return cls(
            signal_code=signal.signal_code,
            address=signal.address,
            observed_roles=list(signal.observed_roles),
            source_id=signal.source_id,
            report_id=signal.report_id,
            source_type=signal.source_type,
            claim_category=signal.claim_category,
            reported_at=signal.reported_at,
            evidence_status=signal.evidence_status,
        )


class RiskAssessmentView(_ResponseModel):
    network: Network
    tx_hash: str
    transaction_status: TransactionStatus
    features: FeaturesView
    address_evidence: AddressEvidenceView
    signals: list[RiskSignalView]
    risk_determination: RiskDetermination = Field(
        description="Always indeterminate: unverified allegations cannot establish fraud."
    )
    determination_basis: Literal["no_verified_evidence"]
    manual_review_recommended: bool = Field(
        description=(
            "True only when a supplied allegation matches an observed address; it is not "
            "evidence against anyone. False never means the transaction is safe."
        )
    )

    @classmethod
    def from_domain(cls, assessment: TransactionRiskAssessment) -> "RiskAssessmentView":
        return cls(
            network=assessment.network,
            tx_hash=assessment.tx_hash,
            transaction_status=assessment.transaction_status,
            features=FeaturesView.from_domain(assessment.features),
            address_evidence=AddressEvidenceView.from_domain(assessment.address_evidence),
            signals=[RiskSignalView.from_domain(s) for s in assessment.signals],
            risk_determination=assessment.risk_determination,
            determination_basis=assessment.determination_basis,
            manual_review_recommended=assessment.manual_review_recommended,
        )


class TransactionAssessmentResponse(_ResponseModel):
    inspection: TransactionInspectionResponse
    assessment: RiskAssessmentView
    report_origin: Literal["client_supplied_unverified"] = Field(
        description="Any reports come from the client and were not verified by ChainShield."
    )

    @classmethod
    def from_domain(
        cls, inspection: TransactionInspection, assessment: TransactionRiskAssessment
    ) -> "TransactionAssessmentResponse":
        return cls(
            inspection=TransactionInspectionResponse.from_inspection(inspection),
            assessment=RiskAssessmentView.from_domain(assessment),
            report_origin="client_supplied_unverified",
        )
