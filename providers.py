"""Threat intelligence provider clients.

Includes AbuseIPDB (IPv4 reputation), VirusTotal v3 (file hashes), and a
deterministic MockProvider used for offline/CI testing without API keys.

Author : USER-Bi (Rg-Red)
Version: 1.0.0
"""
from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

import requests

from validator import IPV4, MD5, SHA1, SHA256

CLEAN = "CLEAN"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS = "MALICIOUS"
ERROR = "ERROR"

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
DEFAULT_TIMEOUT = 10


class ProviderError(RuntimeError):
    """Base class for all provider-side failures."""


class MissingAPIKeyError(ProviderError):
    """Raised when a provider needs a key that was never configured."""


class RateLimitError(ProviderError):
    """Raised on HTTP 429 from an upstream API."""


class ProviderTimeoutError(ProviderError):
    """Raised when the upstream connection times out."""


@dataclass
class LookupResult:
    """Normalized verdict returned by every provider, mock or real."""

    ioc_value: str
    ioc_type: str
    provider: str
    verdict: str
    score: int = 0
    detections: int = 0
    total_engines: int = 0
    detail: str = ""
    error: Optional[str] = None
    raw: dict = field(default_factory=dict)
    from_cache: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None

    def as_dict(self) -> dict:
        return {
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "provider": self.provider,
            "verdict": self.verdict,
            "score": self.score,
            "detections": self.detections,
            "total_engines": self.total_engines,
            "detail": self.detail,
            "error": self.error,
            "from_cache": self.from_cache,
        }


def score_to_verdict(score: int) -> str:
    """Map an AbuseIPDB-style 0-100 confidence score to a risk verdict."""
    if score > 50:
        return MALICIOUS
    if score >= 11:
        return SUSPICIOUS
    return CLEAN


def detections_to_verdict(detections: int) -> str:
    """Map a VirusTotal-style engine detection count to a risk verdict."""
    if detections > 3:
        return MALICIOUS
    if detections >= 1:
        return SUSPICIOUS
    return CLEAN


class BaseProvider(ABC):
    """Common interface implemented by every provider."""

    name: str = "base"
    handles: frozenset[str] = frozenset()

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.handles

    @abstractmethod
    def lookup(self, ioc_value: str, ioc_type: str) -> LookupResult:
        ...

    def _error_result(self, ioc_value: str, ioc_type: str, message: str) -> LookupResult:
        return LookupResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            provider=self.name,
            verdict=ERROR,
            detail=message,
            error=message,
        )


class AbuseIPDBProvider(BaseProvider):
    """Queries AbuseIPDB's /check endpoint for IPv4 reputation."""

    name = "abuseipdb"
    handles = frozenset({IPV4})

    def __init__(self, api_key: Optional[str], timeout: int = DEFAULT_TIMEOUT, session: Optional[requests.Session] = None):
        self.api_key = api_key
        self.timeout = timeout
        self.session = session or requests.Session()

    def lookup(self, ioc_value: str, ioc_type: str) -> LookupResult:
        if not self.api_key:
            return self._error_result(
                ioc_value, ioc_type, "AbuseIPDB API key missing (set ABUSEIPDB_API_KEY)"
            )
        try:
            response = self.session.get(
                ABUSEIPDB_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ioc_value, "maxAgeInDays": 90},
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout:
            return self._error_result(ioc_value, ioc_type, "connection timed out contacting AbuseIPDB")
        except requests.exceptions.RequestException as exc:
            return self._error_result(ioc_value, ioc_type, f"network error contacting AbuseIPDB: {exc}")

        if response.status_code == 429:
            return self._error_result(ioc_value, ioc_type, "AbuseIPDB rate limit exceeded (HTTP 429)")
        if response.status_code == 401:
            return self._error_result(ioc_value, ioc_type, "AbuseIPDB rejected the API key (HTTP 401)")
        if response.status_code != 200:
            return self._error_result(
                ioc_value, ioc_type, f"AbuseIPDB returned HTTP {response.status_code}"
            )

        try:
            payload = response.json().get("data", {})
        except ValueError:
            return self._error_result(ioc_value, ioc_type, "AbuseIPDB returned invalid JSON")

        score = int(payload.get("abuseConfidenceScore", 0))
        reports = int(payload.get("totalReports", 0))
        return LookupResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            provider=self.name,
            verdict=score_to_verdict(score),
            score=score,
            detections=reports,
            total_engines=0,
            detail=f"{reports} community report(s), confidence score {score}/100",
            raw=payload,
        )


class VirusTotalProvider(BaseProvider):
    """Queries VirusTotal v3 for file hash reputation."""

    name = "virustotal"
    handles = frozenset({MD5, SHA1, SHA256})

    def __init__(self, api_key: Optional[str], timeout: int = DEFAULT_TIMEOUT, session: Optional[requests.Session] = None):
        self.api_key = api_key
        self.timeout = timeout
        self.session = session or requests.Session()

    def lookup(self, ioc_value: str, ioc_type: str) -> LookupResult:
        if not self.api_key:
            return self._error_result(
                ioc_value, ioc_type, "VirusTotal API key missing (set VT_API_KEY)"
            )
        url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
        try:
            response = self.session.get(
                url,
                headers={"x-apikey": self.api_key},
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout:
            return self._error_result(ioc_value, ioc_type, "connection timed out contacting VirusTotal")
        except requests.exceptions.RequestException as exc:
            return self._error_result(ioc_value, ioc_type, f"network error contacting VirusTotal: {exc}")

        if response.status_code == 429:
            return self._error_result(ioc_value, ioc_type, "VirusTotal rate limit exceeded (HTTP 429)")
        if response.status_code == 401:
            return self._error_result(ioc_value, ioc_type, "VirusTotal rejected the API key (HTTP 401)")
        if response.status_code == 404:
            return LookupResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                provider=self.name,
                verdict=CLEAN,
                detail="hash not present in VirusTotal corpus (unseen file)",
            )
        if response.status_code != 200:
            return self._error_result(
                ioc_value, ioc_type, f"VirusTotal returned HTTP {response.status_code}"
            )

        try:
            attributes = response.json().get("data", {}).get("attributes", {})
        except ValueError:
            return self._error_result(ioc_value, ioc_type, "VirusTotal returned invalid JSON")

        stats = attributes.get("last_analysis_stats", {})
        detections = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        total_engines = sum(int(v) for v in stats.values()) if stats else 0
        return LookupResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            provider=self.name,
            verdict=detections_to_verdict(detections),
            score=detections,
            detections=detections,
            total_engines=total_engines,
            detail=f"{detections}/{total_engines} engines flagged this file" if total_engines else "no engine stats available",
            raw=attributes,
        )


class MockProvider(BaseProvider):
    """Deterministic, offline-only provider used for demos and tests.

    The verdict is derived from a hash of the IOC value, so repeated runs
    against the same indicator always return the same result without any
    network access or API key.
    """

    name = "mock"
    handles = frozenset({IPV4, MD5, SHA1, SHA256})

    _KNOWN_MALICIOUS = {
        "185.220.101.1",
        "d41d8cd98f00b204e9800998ecf8427e",
        "44d88612fea8a8f36de82e1278abb02f",
    }
    _KNOWN_CLEAN = {
        "8.8.8.8",
        "1.1.1.1",
    }

    def __init__(self, latency: float = 0.0):
        self.latency = latency

    def lookup(self, ioc_value: str, ioc_type: str) -> LookupResult:
        if self.latency:
            time.sleep(self.latency)

        digest = hashlib.sha256(ioc_value.lower().encode("utf-8")).hexdigest()
        bucket = int(digest[:4], 16) % 100

        if ioc_value.lower() in self._KNOWN_MALICIOUS:
            bucket = 90
        elif ioc_value.lower() in self._KNOWN_CLEAN:
            bucket = 0

        if ioc_type == IPV4:
            score = bucket
            verdict = score_to_verdict(score)
            return LookupResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                provider=self.name,
                verdict=verdict,
                score=score,
                detections=0 if verdict == CLEAN else (2 if verdict == SUSPICIOUS else 8),
                detail=f"[MOCK] deterministic confidence score {score}/100",
                raw={"mock": True, "bucket": bucket},
            )

        detections = min(bucket // 12, 20)
        total_engines = 70
        verdict = detections_to_verdict(detections)
        return LookupResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            provider=self.name,
            verdict=verdict,
            score=detections,
            detections=detections,
            total_engines=total_engines,
            detail=f"[MOCK] deterministic {detections}/{total_engines} engine detections",
            raw={"mock": True, "bucket": bucket},
        )


def build_providers(
    mock: bool = False,
    abuseipdb_key: Optional[str] = None,
    virustotal_key: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[BaseProvider]:
    """Assemble the provider list used by the CLI for a given run."""
    if mock:
        return [MockProvider()]
    return [
        AbuseIPDBProvider(abuseipdb_key, timeout=timeout),
        VirusTotalProvider(virustotal_key, timeout=timeout),
    ]


def select_provider(providers: list[BaseProvider], ioc_type: str) -> Optional[BaseProvider]:
    """Pick the first provider in the list that handles ``ioc_type``."""
    for provider in providers:
        if provider.supports(ioc_type):
            return provider
    return None
