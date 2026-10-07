"""SQLite-backed TTL cache for IOC lookups.

Avoids burning external API rate limits by remembering recent verdicts.

Author : USER-Bi (Rg-Red)
Version: 1.0.0
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

DEFAULT_DB_PATH = "ioc_cache.db"
DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24 hours

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ioc_cache (
    cache_key   TEXT PRIMARY KEY,
    ioc_value   TEXT NOT NULL,
    ioc_type    TEXT NOT NULL,
    provider    TEXT NOT NULL,
    payload     TEXT NOT NULL,
    fetched_at  REAL NOT NULL,
    expires_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ioc_cache_expires ON ioc_cache (expires_at);
"""


@dataclass(frozen=True)
class CacheEntry:
    """A single cached provider response."""

    cache_key: str
    ioc_value: str
    ioc_type: str
    provider: str
    payload: dict
    fetched_at: float
    expires_at: float

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    @property
    def age_seconds(self) -> float:
        return max(0.0, time.time() - self.fetched_at)


def make_cache_key(provider: str, ioc_type: str, ioc_value: str) -> str:
    """Build a deterministic cache key for a provider/type/value triple."""
    return f"{provider.lower()}:{ioc_type.lower()}:{ioc_value.lower()}"


class CacheManager:
    """Thin wrapper around a SQLite file used as a TTL cache.

    Safe to use as a context manager; also closes cleanly via :meth:`close`.
    """

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.db_path = str(db_path)
        self.ttl_seconds = ttl_seconds
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def __enter__(self) -> "CacheManager":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        finally:
            cur.close()

    def get(self, provider: str, ioc_type: str, ioc_value: str) -> Optional[CacheEntry]:
        """Return a non-expired :class:`CacheEntry`, or ``None`` on miss/expiry."""
        key = make_cache_key(provider, ioc_type, ioc_value)
        with self._cursor() as cur:
            cur.execute(
                "SELECT cache_key, ioc_value, ioc_type, provider, payload, fetched_at, expires_at "
                "FROM ioc_cache WHERE cache_key = ?",
                (key,),
            )
            row = cur.fetchone()

        if row is None:
            return None

        entry = CacheEntry(
            cache_key=row[0],
            ioc_value=row[1],
            ioc_type=row[2],
            provider=row[3],
            payload=json.loads(row[4]),
            fetched_at=row[5],
            expires_at=row[6],
        )
        if entry.is_expired:
            self.delete(provider, ioc_type, ioc_value)
            return None
        return entry

    def set(
        self,
        provider: str,
        ioc_type: str,
        ioc_value: str,
        payload: dict,
        ttl_seconds: Optional[int] = None,
    ) -> CacheEntry:
        """Insert or replace a cache row for a provider/type/value triple."""
        ttl = self.ttl_seconds if ttl_seconds is None else ttl_seconds
        now = time.time()
        key = make_cache_key(provider, ioc_type, ioc_value)
        entry = CacheEntry(
            cache_key=key,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            provider=provider,
            payload=payload,
            fetched_at=now,
            expires_at=now + ttl,
        )
        with self._cursor() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO ioc_cache "
                "(cache_key, ioc_value, ioc_type, provider, payload, fetched_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.cache_key,
                    entry.ioc_value,
                    entry.ioc_type,
                    entry.provider,
                    json.dumps(payload),
                    entry.fetched_at,
                    entry.expires_at,
                ),
            )
        return entry

    def delete(self, provider: str, ioc_type: str, ioc_value: str) -> None:
        key = make_cache_key(provider, ioc_type, ioc_value)
        with self._cursor() as cur:
            cur.execute("DELETE FROM ioc_cache WHERE cache_key = ?", (key,))

    def purge_expired(self) -> int:
        """Delete all expired rows; returns the number of rows removed."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM ioc_cache WHERE expires_at <= ?", (time.time(),))
            return cur.rowcount

    def clear(self) -> None:
        """Wipe the entire cache table."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM ioc_cache")

    def count(self) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM ioc_cache")
            return cur.fetchone()[0]
