"""In-memory sliding-window rate limiting of the analysis endpoints (v1).

Authentication v1 relies on one shared secret, so there is no client identity
to key a quota on: a single quota, per process, is shared by every
authenticated caller and by every analysis route. Client headers such as
``X-Forwarded-For`` or ``Forwarded`` are never read.

Sliding-window log: the monotonic timestamps of the admissions of the last
``window_seconds`` are kept in a deque bounded by ``max_requests``. A request
is admitted while fewer than ``max_requests`` admissions are in the window; an
admission at ``t`` leaves the window at exactly ``t + window_seconds``.
Rejected requests are not recorded, so they never extend the blocking.

Counters live in memory only: they reset on restart and are independent
between workers or instances. This is not a limit on concurrent requests.
"""

import math
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends

MAX_REQUESTS = 30
WINDOW_SECONDS = 60.0


class RateLimitExceededError(Exception):
    """The shared quota is exhausted; ``retry_after`` is in whole seconds (>= 1)."""

    def __init__(self, retry_after: int) -> None:
        super().__init__()
        self.retry_after = retry_after


class SlidingWindowRateLimiter:
    def __init__(
        self,
        max_requests: int = MAX_REQUESTS,
        window_seconds: float = WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_requests < 1 or not window_seconds > 0:
            raise ValueError("max_requests must be >= 1 and window_seconds > 0")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clock = clock
        self._admissions: deque[float] = deque(maxlen=max_requests)
        self._lock = threading.Lock()

    def acquire(self, cost: int = 1) -> None:
        """Admit and record ``cost`` units at once, or raise ``RateLimitExceededError``.

        All-or-nothing: either every unit is recorded or none is. The check and
        the recording happen under one lock, so concurrent callers can never
        be admitted beyond the quota. On refusal, ``retry_after`` is the delay
        until enough admissions have left the window for ``cost`` units to fit.
        """
        if type(cost) is not int or not 1 <= cost <= self.max_requests:
            raise ValueError("cost must be an integer between 1 and max_requests")
        with self._lock:
            now = self._clock()
            expired_before = now - self.window_seconds
            while self._admissions and self._admissions[0] <= expired_before:
                self._admissions.popleft()
            excess = len(self._admissions) + cost - self.max_requests
            if excess <= 0:
                self._admissions.extend([now] * cost)
                return
            # The ``excess`` oldest admissions must expire first.
            wait = self._admissions[excess - 1] + self.window_seconds - now
        raise RateLimitExceededError(retry_after=max(1, math.ceil(wait)))

    def reset(self) -> None:
        """Forget every admission (tests, or an operator restart of the quota)."""
        with self._lock:
            self._admissions.clear()


_default_limiter = SlidingWindowRateLimiter()


def get_rate_limiter() -> SlidingWindowRateLimiter:
    """The process-wide limiter, built once (override in tests to change it)."""
    return _default_limiter


def enforce_rate_limit(
    limiter: Annotated[SlidingWindowRateLimiter, Depends(get_rate_limiter)],
) -> None:
    """Router dependency, declared after authentication: only authenticated
    requests consume the quota, and a rejected one never reaches the service."""
    limiter.acquire()
