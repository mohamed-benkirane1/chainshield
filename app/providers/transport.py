"""HTTP transport for JSON-RPC, injectable for tests.

Error messages raised here never include the endpoint URL, which commonly
embeds an API key.
"""

import json
import urllib.error
import urllib.request
from typing import Any, Protocol

from app.providers.base import (
    MalformedResponseError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)

MAX_RESPONSE_BYTES = 5 * 1024 * 1024


class JsonRpcTransport(Protocol):
    def post_json(self, url: str, payload: dict[str, Any], timeout: float) -> Any:
        """POST ``payload`` as JSON and return the decoded JSON body.

        Raises ``ProviderTimeoutError``, ``ProviderUnavailableError`` or
        ``MalformedResponseError``.
        """
        ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    # A redirect would silently turn the POST into a GET elsewhere.
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class UrllibTransport:
    """Standard-library transport: no redirects, bounded response size."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirectHandler)

    def post_json(self, url: str, payload: dict[str, Any], timeout: float) -> Any:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise ProviderUnavailableError(
                f"RPC endpoint returned HTTP {exc.code}"
            ) from None
        except TimeoutError:
            raise ProviderTimeoutError("RPC request timed out") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise ProviderTimeoutError("RPC request timed out") from None
            raise ProviderUnavailableError("RPC endpoint is unreachable") from None
        except OSError:
            raise ProviderUnavailableError("RPC endpoint is unreachable") from None

        if len(body) > MAX_RESPONSE_BYTES:
            raise MalformedResponseError("RPC response exceeds the size limit")
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise MalformedResponseError("RPC response is not valid JSON") from None
