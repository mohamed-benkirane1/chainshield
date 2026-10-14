"""Pure ASGI middleware bounding the size of HTTP request bodies.

The limit is an operational safeguard against unbounded work and memory use,
not a risk threshold.

The body is read before the application runs, counting the bytes actually
received (never trusting ``Content-Length`` alone) and buffering at most
``max_body_bytes``. A declared ``Content-Length`` above the limit is rejected
without reading anything. If the limit is exceeded the application is not
called: no dependency, service, provider or risk engine runs. If the client
disconnects before the body is complete, the application is not called and
nothing is sent. Otherwise the buffered body is replayed once, unchanged, to
the application.

A single ASGI message is already in memory when it is received, so peak
memory is the limit plus one server chunk (typically 64 KiB with uvicorn).
"""

from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from app.api.schemas import ErrorBody, ErrorResponse

MAX_BODY_BYTES = 262_144  # 256 KiB

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_TOO_LARGE_BODY = (
    ErrorResponse(
        error=ErrorBody(code="request_too_large", message="Request body is too large.")
    )
    .model_dump_json(exclude_none=True)
    .encode("ascii")
)


_MAX_LENGTH_DIGITS = 18
_HUGE_LENGTH = 10**_MAX_LENGTH_DIGITS


def _declared_length(scope: Scope) -> int | None:
    """Largest valid Content-Length header, or None. Only a preliminary check.

    Longer digit strings count as huge instead of being converted: int() refuses
    more than 4300 digits, and the header is client-controlled.
    """
    lengths = [
        int(digits) if len(digits) <= _MAX_LENGTH_DIGITS else _HUGE_LENGTH
        for name, value in scope.get("headers", [])
        if name.lower() == b"content-length" and (digits := value.strip()).isdigit()
    ]
    return max(lengths) if lengths else None


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_body_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = _declared_length(scope)
        if declared is not None and declared > self.max_body_bytes:
            await self._reject(send)
            return

        chunks: list[bytes] = []
        received = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return  # client gone before the body was complete: nothing to answer
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            received += len(chunk)
            if received > self.max_body_bytes:
                await self._reject(send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()  # e.g. waiting for a later http.disconnect

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(_TOO_LARGE_BODY)).encode("ascii")),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": _TOO_LARGE_BODY})
