"""Explicit mapping of domain and provider errors to safe HTTP responses.

Public responses carry a stable code and a fixed message only: never the
exception text (which could mention internal details), a traceback, the RPC
URL, an API key or request content.
"""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.auth import AuthenticationError, AuthenticationNotConfiguredError
from app.api.concurrency_limit import AnalysisCapacityExceededError
from app.api.rate_limit import RateLimitExceededError
from app.api.schemas import ErrorBody, ErrorDetail, ErrorResponse
from app.providers.base import (
    ChainMismatchError,
    ExecutionResultUnknownError,
    MalformedResponseError,
    ProviderConfigurationError,
    ProviderError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    ReceiptUnavailableError,
    RpcError,
    TransactionNotFoundError,
    TransactionPendingError,
    TransactionUnconfirmedError,
    UnsupportedTransactionError,
)
from app.providers.tron import TronApiError
from app.risk.address_evidence import ConflictingReportError
from app.services.transaction_analysis import InconsistentAnalysisError

_INCONSISTENT = (
    502,
    "inconsistent_provider_data",
    "Provider data was inconsistent or changed during the analysis. Retry later.",
)

# Most specific first: the first matching class wins.
ERROR_MAPPING: tuple[tuple[type[Exception], int, str, str], ...] = (
    (ProviderConfigurationError, 503, "provider_not_configured",
     "The blockchain provider for this network is not configured."),
    (ProviderTimeoutError, 504, "provider_timeout",
     "The blockchain provider did not answer in time."),
    (ProviderUnavailableError, 503, "provider_unavailable",
     "The blockchain provider is unavailable or rate limited. Retry later."),
    (ReceiptUnavailableError, 503, "receipt_unavailable",
     "The transaction execution data is not available yet. Retry later."),
    (ChainMismatchError, 502, "provider_wrong_network",
     "The blockchain provider is connected to an unexpected network."),
    (ExecutionResultUnknownError, 502, "execution_result_unknown",
     "The provider data does not establish the execution result."),
    (UnsupportedTransactionError, 422, "unsupported_transaction",
     "This transaction type is not supported."),
    (InconsistentAnalysisError, *_INCONSISTENT),
    (TransactionNotFoundError, *_INCONSISTENT),
    (TransactionPendingError, *_INCONSISTENT),
    (TransactionUnconfirmedError, *_INCONSISTENT),
    (MalformedResponseError, 502, "provider_malformed_response",
     "The blockchain provider returned malformed data."),
    (RpcError, 502, "provider_rpc_error",
     "The blockchain provider returned an error."),
    (TronApiError, 502, "provider_api_error",
     "The blockchain provider returned an error."),
    (ProviderError, 502, "provider_error",
     "The blockchain provider request failed."),
)

_INTERNAL = (500, "internal_error", "An internal error occurred.")
_KNOWN_FIELDS = frozenset(
    {
        "kind",
        "network",
        "tx_hash",
        "reports",
        "address",
        "addresses",
        "tx_hashes",
        "source_address",
        "target_address",
    }
)
_CONFLICTING_REPORTS = (
    422,
    "conflicting_reports",
    "Several supplied reports share the same source and report identifiers "
    "with different content.",
)
_UNAUTHORIZED = (401, "unauthorized", "Authentication required.")
_AUTH_NOT_CONFIGURED = (503, "auth_not_configured", "API authentication is not configured.")
_RATE_LIMITED = (429, "rate_limited", "Too many requests. Retry later.")
_SERVICE_BUSY = (503, "service_busy", "Analysis capacity is temporarily exhausted.")


def _error_response(
    status: int, code: str, message: str, details: list[ErrorDetail] | None = None
) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=message, details=details))
    return JSONResponse(status_code=status, content=body.model_dump(exclude_none=True))


def _provider_error_handler(request: Request, exc: Exception) -> JSONResponse:
    for error_type, status, code, message in ERROR_MAPPING:
        if isinstance(exc, error_type):
            return _error_response(status, code, message)
    return _error_response(*_INTERNAL)


def _validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Only the schema field name and error type are exposed: no input values,
    # no validator messages and no client-chosen keys (e.g. unexpected fields).
    details = []
    errors = exc.errors() if isinstance(exc, RequestValidationError) else []
    for error in errors:
        loc = error.get("loc", ())
        field = loc[1] if len(loc) > 1 and loc[1] in _KNOWN_FIELDS else "body"
        details.append(ErrorDetail(field=str(field), type=str(error.get("type", "invalid"))))
    return _error_response(
        422, "invalid_request", "The request is invalid.", details or None
    )


def _conflicting_reports_handler(request: Request, exc: Exception) -> JSONResponse:
    # Fixed message: the conflicting identifiers are client data and are not echoed.
    return _error_response(*_CONFLICTING_REPORTS)


def _authentication_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Same code and message whatever the cause: absent, malformed or wrong token.
    response = _error_response(*_UNAUTHORIZED)
    response.headers["WWW-Authenticate"] = "Bearer"
    return response


def _auth_not_configured_handler(request: Request, exc: Exception) -> JSONResponse:
    return _error_response(*_AUTH_NOT_CONFIGURED)


def _rate_limited_handler(request: Request, exc: Exception) -> JSONResponse:
    # Only the whole-second delay is exposed, never the internal timestamps.
    response = _error_response(*_RATE_LIMITED)
    retry_after = exc.retry_after if isinstance(exc, RateLimitExceededError) else 1
    response.headers["Retry-After"] = str(max(1, retry_after))
    return response


def _service_busy_handler(request: Request, exc: Exception) -> JSONResponse:
    # Fixed body and delay: nothing about the slots in use is exposed.
    response = _error_response(*_SERVICE_BUSY)
    response.headers["Retry-After"] = "1"
    return response


def _unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
    return _error_response(*_INTERNAL)


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(AuthenticationError, _authentication_error_handler)
    app.add_exception_handler(AuthenticationNotConfiguredError, _auth_not_configured_handler)
    app.add_exception_handler(RateLimitExceededError, _rate_limited_handler)
    app.add_exception_handler(AnalysisCapacityExceededError, _service_busy_handler)
    app.add_exception_handler(ProviderError, _provider_error_handler)
    app.add_exception_handler(ConflictingReportError, _conflicting_reports_handler)
    app.add_exception_handler(Exception, _unexpected_error_handler)
