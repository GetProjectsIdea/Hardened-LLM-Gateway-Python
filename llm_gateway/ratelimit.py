"""Token-bucket rate limiting per key plus a daily token budget."""
from __future__ import annotations

import threading
import time
from typing import Callable


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}  # id -> (tokens, last)
        self._lock = threading.Lock()

    def allow(self, ident: str, rpm: int) -> tuple[bool, float]:
        """Consume one request. Returns (allowed, retry_after_seconds)."""
        now = self._clock()
        cap = float(max(1, rpm))
        rate = cap / 60.0
        with self._lock:
            tokens, last = self._buckets.get(ident, (cap, now))
            tokens = min(cap, tokens + (now - last) * rate)
            if tokens >= 1.0:
                self._buckets[ident] = (tokens - 1.0, now)
                return True, 0.0
            self._buckets[ident] = (tokens, now)
            return False, round((1.0 - tokens) / rate, 2)


class TokenBudget:
    """Counts prompt+completion tokens per key per UTC day."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._used: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def _day(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self._clock()))

    def used(self, ident: str) -> int:
        return self._used.get((ident, self._day()), 0)

    def remaining(self, ident: str, budget: int) -> int:
        return max(0, budget - self.used(ident))

    def add(self, ident: str, tokens: int) -> int:
        with self._lock:
            k = (ident, self._day())
            self._used[k] = self._used.get(k, 0) + max(0, int(tokens))
            return self._used[k]


class IpFailureTracker:
    """Temporarily blocks client IPs after repeated authentication failures."""

    def __init__(self, max_failures: int = 10, window: float = 300.0, block_for: float = 900.0,
                 clock: Callable[[], float] = time.monotonic):
        self.max_failures, self.window, self.block_for = max_failures, window, block_for
        self._clock = clock
        self._fails: dict[str, list[float]] = {}
        self._blocked: dict[str, float] = {}
        self._lock = threading.Lock()

    def blocked(self, ip: str) -> bool:
        until = self._blocked.get(ip)
        if until is None:
            return False
        if self._clock() >= until:
            self._blocked.pop(ip, None)
            return False
        return True

    def fail(self, ip: str) -> bool:
        """Record a failure; return True if the IP is now blocked."""
        now = self._clock()
        with self._lock:
            lst = [t for t in self._fails.get(ip, []) if now - t < self.window] + [now]
            self._fails[ip] = lst
            if len(lst) >= self.max_failures:
                self._blocked[ip] = now + self.block_for
                self._fails[ip] = []
                return True
        return False

    def success(self, ip: str) -> None:
        self._fails.pop(ip, None)
