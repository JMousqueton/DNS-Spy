import time
import threading
from typing import Any, Optional


class Cache:
    def __init__(self):
        self._store: dict[str, tuple[Any, float]] = {}
        self._ttl: int = 300
        self._lock = threading.Lock()

    def init(self, ttl: int = 300):
        self._ttl = ttl

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.time() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        with self._lock:
            expiry = time.time() + (ttl if ttl is not None else self._ttl)
            self._store[key] = (value, expiry)

    def delete(self, key: str):
        with self._lock:
            self._store.pop(key, None)

    def clear(self):
        with self._lock:
            self._store.clear()

    def cleanup(self):
        """Remove expired entries."""
        now = time.time()
        with self._lock:
            expired = [k for k, (_, exp) in self._store.items() if now > exp]
            for k in expired:
                del self._store[k]
