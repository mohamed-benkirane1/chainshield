"""Bearer-token authentication of the analysis endpoints (shared secret, v1).

The expected token is read from ``CHAINSHIELD_API_TOKEN`` on each request and
is never defined in the code. A missing or invalid configuration fails closed
(``AuthenticationNotConfiguredError``, HTTP 503). Missing, malformed, duplicated
or wrong credentials all raise the same ``AuthenticationError`` (HTTP 401).

No user accounts, permissions or token rotation: one secret shared by all
clients, suitable for this development phase only.
"""

import hmac
import os
from collections.abc import Mapping
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

API_TOKEN_ENV_VAR = "CHAINSHIELD_API_TOKEN"
MIN_TOKEN_LENGTH = 32


class AuthenticationError(Exception):
    """Credentials are missing, malformed, duplicated or do not match."""


class AuthenticationNotConfiguredError(Exception):
    """No valid API token is configured on the server."""


# auto_error=False: every failure goes through AuthenticationError and its
# handler, so the response keeps the API error format. Also documents the
# HTTP Bearer scheme in OpenAPI.
_bearer = HTTPBearer(auto_error=False, description=f"Shared API token ({API_TOKEN_ENV_VAR}).")


def configured_api_token(environ: Mapping[str, str] | None = None) -> str:
    """The expected token, or ``AuthenticationNotConfiguredError``.

    Requires at least 32 visible ASCII characters (no space, no control
    character). The value is never trimmed nor included in the error.
    """
    env = os.environ if environ is None else environ
    token = env.get(API_TOKEN_ENV_VAR, "")
    if len(token) < MIN_TOKEN_LENGTH or not all("!" <= char <= "~" for char in token):
        raise AuthenticationNotConfiguredError()
    return token


async def require_api_token(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    """Router dependency: runs before the endpoint's own dependencies."""
    expected = configured_api_token()
    headers = request.headers.getlist("authorization")
    if credentials is None or len(headers) != 1:
        raise AuthenticationError()
    # HTTPBearer strips the token; compare the raw header value instead so that
    # nothing is normalized. Header values are latin-1, so encoding never fails.
    _, _, presented = headers[0].partition(" ")
    if not hmac.compare_digest(presented.encode("latin-1"), expected.encode("ascii")):
        raise AuthenticationError()
