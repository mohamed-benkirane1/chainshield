from collections.abc import Iterator

import pytest

from app.api.rate_limit import get_rate_limiter


@pytest.fixture(autouse=True)
def _fresh_rate_limit_quota() -> Iterator[None]:
    # The real process-wide limiter stays active; each test starts with a full quota
    # instead of inheriting the admissions of the tests that ran before it.
    get_rate_limiter().reset()
    yield
    get_rate_limiter().reset()
