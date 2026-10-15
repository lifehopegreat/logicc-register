"""Shared monotonic budgets and payload-free protocol timings."""
from contextlib import contextmanager
import time


class DeadlineExceeded(TimeoutError):
    """The transaction's budget, rather than an individual socket, expired."""


class MailboxTimeout(TimeoutError):
    """The OTP wait expired before the parent transaction deadline."""


def deadline_after(timeout: float, parent: float | None = None) -> float:
    end = time.monotonic() + max(0.0, float(timeout))
    return min(end, parent) if parent is not None else end


def remaining(deadline: float | None, cap: float = 60.0) -> float:
    seconds = min(float(cap), deadline - time.monotonic()) if deadline is not None else float(cap)
    if seconds <= 0:
        raise DeadlineExceeded("protocol deadline exceeded")
    return seconds


@contextmanager
def measure(timings: dict, name: str):
    started = time.monotonic()
    try:
        yield
    finally:
        key = name + "_ms"
        timings[key] = round(timings.get(key, 0.0) + (time.monotonic() - started) * 1000, 3)
        key = name + "_count"
        timings[key] = timings.get(key, 0) + 1
