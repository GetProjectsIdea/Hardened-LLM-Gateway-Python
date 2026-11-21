"""Per-user API keys, hashed at rest.

* Keys look like ``lgw_<key_id>_<secret>``. The full key is shown exactly once,
  when it is created. Only an HMAC-SHA256 of the key (keyed with a server-side
  pepper that is NOT stored in the key file) is written to disk.
* There is no default key, no master key and no "admin/admin" account. A fresh
  gateway has zero keys and rejects every request until you create one.
* Each key has an owner, an optional expiry, an allowed-model list, a
  requests-per-minute limit and a daily token budget.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

KEY_PREFIX = "lgw_"
KEY_RE = re.compile(r"^lgw_([a-f0-9]{12})_([A-Za-z0-9_\-]{32,})$")


class KeyError_(Exception):
    """Raised for invalid key-store operations."""


@dataclass
class ApiKey:
    key_id: str
    user: str
    key_hash: str
    created: float
    expires: float | None = None
    revoked: bool = False
    models: list[str] = field(default_factory=list)  # empty = gateway default list
    rpm: int = 30
    daily_tokens: int = 200_000
    note: str = ""
    last_used: float | None = None

    def public(self) -> dict:
        d = asdict(self)
        d.pop("key_hash")
        d["status"] = self.status()
        return d

    def status(self, now: float | None = None) -> str:
        now = time.time() if now is None else now
        if self.revoked:
            return "revoked"
        if self.expires is not None and now >= self.expires:
            return "expired"
        return "active"


def hash_key(pepper: str, full_key: str) -> str:
    return hmac.new(pepper.encode(), full_key.encode(), hashlib.sha256).hexdigest()


class KeyStore:
    """JSON file of hashed keys. Writes are atomic and the file is chmod 600."""

    def __init__(self, path: str | os.PathLike, pepper: str):
        if not pepper:
            raise KeyError_("a key pepper is required")
        self.path = Path(path)
        self._pepper = pepper
        self._lock = threading.Lock()
        self._keys: dict[str, ApiKey] = {}
        self._mtime = None
        self.load()

    # ---------- persistence ----------
    def _file_mtime(self):
        try:
            st = self.path.stat()
            return (st.st_ino, st.st_mtime_ns, st.st_size)  # atomic replace -> new inode
        except OSError:
            return None

    def load(self) -> None:
        self._mtime = self._file_mtime()
        if not self.path.exists():
            self._keys = {}
            return
        data = json.loads(self.path.read_text() or "{}")
        seen = {k: v.last_used for k, v in self._keys.items() if v.last_used}
        self._keys = {k["key_id"]: ApiKey(**k) for k in data.get("keys", [])}
        for k, t in seen.items():  # last_used is kept in memory between reloads
            if k in self._keys and (self._keys[k].last_used or 0) < t:
                self._keys[k].last_used = t

    def refresh(self) -> None:
        """Reload if another process (e.g. the CLI) changed the file, so new
        keys and revocations take effect in a running gateway immediately."""
        if self._file_mtime() != self._mtime:
            with self._lock:
                self.load()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"version": 1, "keys": [asdict(k) for k in self._keys.values()]}, indent=2)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".keys-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(payload)
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(tmp, self.path)
            self._mtime = self._file_mtime()
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # ---------- management ----------
    def create(self, user: str, *, models: list[str] | None = None, rpm: int = 30,
               daily_tokens: int = 200_000, ttl_days: float | None = 90, note: str = "") -> tuple[str, ApiKey]:
        user = (user or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._@\-]{1,64}", user):
            raise KeyError_("user must be 1-64 chars: letters, digits, . _ @ -")
        if rpm < 1 or daily_tokens < 1:
            raise KeyError_("rpm and daily_tokens must be positive")
        with self._lock:
            key_id = secrets.token_hex(6)
            while key_id in self._keys:
                key_id = secrets.token_hex(6)
            full = f"{KEY_PREFIX}{key_id}_{secrets.token_urlsafe(32)}"
            now = time.time()
            rec = ApiKey(key_id=key_id, user=user, key_hash=hash_key(self._pepper, full), created=now,
                         expires=(now + ttl_days * 86400) if ttl_days else None,
                         models=list(models or []), rpm=rpm, daily_tokens=daily_tokens, note=note)
            self._keys[key_id] = rec
            self.save()
        return full, rec

    def revoke(self, key_id: str) -> ApiKey:
        self.refresh()
        with self._lock:
            rec = self._keys.get(key_id)
            if not rec:
                raise KeyError_(f"no such key: {key_id}")
            rec.revoked = True
            self.save()
            return rec

    def rotate(self, key_id: str) -> tuple[str, ApiKey]:
        """Revoke *key_id* and issue a new key with the same settings."""
        old = self.revoke(key_id)
        ttl = None
        if old.expires:
            ttl = max(1.0, (old.expires - old.created) / 86400)
        return self.create(old.user, models=old.models, rpm=old.rpm, daily_tokens=old.daily_tokens,
                           ttl_days=ttl, note=f"rotated from {key_id}")

    def list(self) -> list[ApiKey]:
        self.refresh()
        return sorted(self._keys.values(), key=lambda k: k.created)

    def get(self, key_id: str) -> ApiKey | None:
        return self._keys.get(key_id)

    def __len__(self) -> int:
        return len(self._keys)

    def active_count(self) -> int:
        return sum(1 for k in self._keys.values() if k.status() == "active")

    # ---------- authentication ----------
    def verify(self, presented: str | None, now: float | None = None) -> tuple[ApiKey | None, str]:
        """Return (key, "ok") or (None|key, reason). Constant-time hash compare."""
        self.refresh()
        if not presented:
            return None, "missing_key"
        m = KEY_RE.match(presented.strip())
        if not m:
            return None, "malformed_key"
        rec = self._keys.get(m.group(1))
        expected = rec.key_hash if rec else hash_key(self._pepper, "decoy")
        ok = hmac.compare_digest(expected, hash_key(self._pepper, presented.strip()))
        if not rec or not ok:
            return None, "unknown_key"
        st = rec.status(now)
        if st != "active":
            return rec, f"{st}_key"
        rec.last_used = time.time() if now is None else now
        return rec, "ok"


def file_is_private(path: str | os.PathLike) -> bool:
    """True if group/other have no permissions on *path* (POSIX only)."""
    if os.name != "posix" or not os.path.exists(path):
        return True
    return (os.stat(path).st_mode & 0o077) == 0
