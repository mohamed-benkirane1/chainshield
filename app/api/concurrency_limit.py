"""Bound on the number of analyses running at the same time, per process (v1).

The rate limit bounds how many analyses start per minute, not how many run at
once: slow providers could still pile up work. At most ``max_concurrent``
analyses hold a slot; another request is refused at once with
``AnalysisCapacityExceededError`` (HTTP 503), it never waits.

The slot is taken by an async ``yield`` dependency with ``scope="function"``:
it is held while the later dependencies, the endpoint and the response
serialization run, then released in ``finally`` before the response is sent,
whatever happens (success, validation error, provider error, any exception or
cancellation). Async on purpose: a sync generator dependency does not run its
exit code on cancellation, and the non-blocking acquisition never blocks the
event loop.

In memory and per process only: workers and instances do not share slots.
"""

import threading
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends

MAX_CONCURRENT_ANALYSES = 8


class AnalysisCapacityExceededError(Exception):
    """Every analysis slot is taken; the request was not admitted."""


class ConcurrencyLimiter:
    def __init__(self, max_concurrent: int = MAX_CONCURRENT_ANALYSES) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")
        self.max_concurrent = max_concurrent
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def try_acquire(self) -> bool:
        """Take a slot if one is free, atomically and without waiting."""
        return self._slots.acquire(blocking=False)

    def release(self) -> None:
        """Give a slot back; releasing more than was acquired raises ValueError."""
        self._slots.release()


_default_limiter = ConcurrencyLimiter()


async def get_concurrency_limiter() -> ConcurrencyLimiter:
    """The process-wide limiter, built once (override in tests to change it)."""
    return _default_limiter


async def hold_analysis_slot(
    limiter: Annotated[ConcurrencyLimiter, Depends(get_concurrency_limiter)],
) -> AsyncIterator[None]:
    """Router dependency: holds one slot for the whole analysis, or refuses."""
    if not limiter.try_acquire():
        raise AnalysisCapacityExceededError()
    try:
        yield
    finally:
        limiter.release()
