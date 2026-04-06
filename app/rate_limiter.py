import time
import threading
from collections import defaultdict
from typing import Tuple


class RateLimiter:
    def __init__(self):
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._max_requests: int = 10
        self._window: int = 60
        self._lock = threading.Lock()

    def init(self, max_requests: int = 10, window: int = 60):
        self._max_requests = max_requests
        self._window = window

    def is_allowed(self, ip: str) -> Tuple[bool, int]:
        """
        Returns (allowed, retry_after_seconds).
        """
        now = time.time()
        with self._lock:
            timestamps = self._requests[ip]
            # Remove old entries outside the window
            self._requests[ip] = [t for t in timestamps if now - t < self._window]
            if len(self._requests[ip]) >= self._max_requests:
                oldest = self._requests[ip][0]
                retry_after = int(self._window - (now - oldest)) + 1
                return False, retry_after
            self._requests[ip].append(now)
            return True, 0

    def remaining(self, ip: str) -> int:
        now = time.time()
        with self._lock:
            timestamps = [t for t in self._requests[ip] if now - t < self._window]
            return max(0, self._max_requests - len(timestamps))
