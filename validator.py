"""IOC validation, refanging and bogon/private-range filtering.

Part of Threat-Intel-IOC-Checker, a SOC Tier-1 triage helper.

Author : USER-Bi (Rg-Red)
Version: 1.0.0
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

__all__ = [
    "TOOL_NAME",
    "AUTHOR",
    "VERSION",
    "IPV4",
    "MD5",
    "SHA1",
    "SHA256",
    "UNKNOWN",
    "PUBLIC_IP",
    "INTERNAL_IP",
    "PRIVATE_IP",
    "LOOPBACK_IP",
    "BOGON_IP",
    "NULL_IP",
    "MULTICAST_IP",
    "RESERVED_IP",
    "INTERNAL_CLASSIFICATIONS",
    "IOCRecord",
    "refang",
    "normalize",
    "classify_ip",
    "is_internal_ip",
    "classify_ioc",
    "classify_batch",
    "filter_iocs",
    "dedupe",
]

TOOL_NAME = "Threat-Intel-IOC-Checker"
AUTHOR = "USER-Bi (Rg-Red)"
VERSION = "1.0.0"

# --- IOC types -----------------------------------------------------------
IPV4 = "ipv4"
MD5 = "md5"
SHA1 = "sha1"
SHA256 = "sha256"
UNKNOWN = "unknown"

HASH_TYPES = frozenset({MD5, SHA1, SHA256})

# --- IP classifications --------------------------------------------------
PUBLIC_IP = "PUBLIC_IP"
INTERNAL_IP = "INTERNAL_IP"
PRIVATE_IP = "PRIVATE_IP"
LOOPBACK_IP = "LOOPBACK_IP"
BOGON_IP = "BOGON_IP"
NULL_IP = "NULL_IP"
MULTICAST_IP = "MULTICAST_IP"
RESERVED_IP = "RESERVED_IP"

#: Any tag in here means "do not burn an API call on this address".
INTERNAL_CLASSIFICATIONS = frozenset(
    {PRIVATE_IP, LOOPBACK_IP, BOGON_IP, NULL_IP, MULTICAST_IP, RESERVED_IP}
)

_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Order matters: the first matching network wins, so the most specific
# classification (loopback > private > bogon) is checked first.
_CLASSIFICATION_NETWORKS: tuple[tuple[str, str], ...] = (
    (LOOPBACK_IP, "127.0.0.0/8"),
    (LOOPBACK_IP, "::1/128"),
    (NULL_IP, "0.0.0.0/8"),
    (NULL_IP, "::/128"),
    (PRIVATE_IP, "10.0.0.0/8"),
    (PRIVATE_IP, "172.16.0.0/12"),
    (PRIVATE_IP, "192.168.0.0/16"),
    (PRIVATE_IP, "fc00::/7"),
    (BOGON_IP, "100.64.0.0/10"),
    (BOGON_IP, "169.254.0.0/16"),
    (BOGON_IP, "192.0.0.0/24"),
    (BOGON_IP, "192.0.2.0/24"),
    (BOGON_IP, "198.18.0.0/15"),
    (BOGON_IP, "198.51.100.0/24"),
    (BOGON_IP, "203.0.113.0/24"),
    (BOGON_IP, "fe80::/10"),
    (BOGON_IP, "2001:db8::/32"),
    (MULTICAST_IP, "224.0.0.0/4"),
    (MULTICAST_IP, "ff00::/8"),
    (RESERVED_IP, "240.0.0.0/4"),
    (RESERVED_IP, "255.255.255.255/32"),
)

_REFANG_RULES: tuple[tuple[str, str], ...] = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[:]", ":"),
    ("hxxps", "https"),
    ("hxxp", "http"),
)

_NETWORKS_CACHE: list[tuple[str, ipaddress._BaseNetwork]] | None = None


def _networks() -> list[tuple[str, ipaddress._BaseNetwork]]:
    """Compile the classification table once, on first use."""
    global _NETWORKS_CACHE
    if _NETWORKS_CACHE is None:
        _NETWORKS_CACHE = [
            (tag, ipaddress.ip_network(cidr)) for tag, cidr in _CLASSIFICATION_NETWORKS
        ]
    return _NETWORKS_CACHE


def refang(value: str) -> str:
    """Undo common SOC defanging: ``1.2.3.4`` written as ``1[.]2[.]3[.]4``."""
    if not value:
        return ""
    result = value
    for needle, replacement in _REFANG_RULES:
        result = result.replace(needle, replacement)
    return result


def normalize(raw: str) -> str:
    """Trim, refang and strip decoration (quotes, angle brackets, list commas)."""
    if raw is None:
        return ""
    value = refang(str(raw)).strip()
    value = value.strip("\"'`<>,;[]{}() \t")
    return value.rstrip(";,").strip()


def classify_ip(value: str):
    """Return ``(classification_tag, ip_object)`` for an IP literal.

    ``ip_object`` is ``None`` when the input is not a valid IP address.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return UNKNOWN, None

    for tag, network in _networks():
        if ip.version == network.version and ip in network:
            return tag, ip

    return (PUBLIC_IP, ip) if ip.is_global else (RESERVED_IP, ip)


def is_internal_ip(value: str) -> bool:
    """True for RFC 1918 / RFC 5735 style addresses that must never be queried."""
    tag, _ = classify_ip(normalize(value))
    return tag in INTERNAL_CLASSIFICATIONS


@dataclass(frozen=True)
class IOCRecord:
    """A normalized indicator plus its classification tags."""

    raw: str
    value: str
    ioc_type: str
    classification: str
    is_internal: bool = False
    detail: str = ""

    @property
    def is_valid(self) -> bool:
        return self.ioc_type != UNKNOWN

    @property
    def is_queryable(self) -> bool:
        """True when the indicator is worth spending an API call on."""
        if self.ioc_type in HASH_TYPES:
            return True
        return self.ioc_type == IPV4 and not self.is_internal

    def as_dict(self) -> dict:
        return {
            "raw": self.raw,
            "value": self.value,
            "type": self.ioc_type,
            "classification": self.classification,
            "is_internal": self.is_internal,
            "is_queryable": self.is_queryable,
            "detail": self.detail,
        }


def _unknown(raw: str, value: str, detail: str) -> IOCRecord:
    return IOCRecord(
        raw=raw,
        value=value,
        ioc_type=UNKNOWN,
        classification=UNKNOWN,
        is_internal=False,
        detail=detail,
    )


def classify_ioc(raw: str) -> IOCRecord:
    """Classify a single raw indicator into an :class:`IOCRecord`."""
    value = normalize(raw)
    if not value:
        return _unknown(raw, value, "empty input")

    if _SHA256_RE.match(value):
        return IOCRecord(raw, value.lower(), SHA256, SHA256, False, "sha256 file hash")
    if _SHA1_RE.match(value):
        return IOCRecord(raw, value.lower(), SHA1, SHA1, False, "sha1 file hash")
    if _MD5_RE.match(value):
        return IOCRecord(raw, value.lower(), MD5, MD5, False, "md5 file hash")

    tag, ip = classify_ip(value)
    if ip is None:
        return _unknown(raw, value, "not a recognised IPv4 address or hash")

    if ip.version != 4:
        internal = tag in INTERNAL_CLASSIFICATIONS
        return IOCRecord(
            raw,
            value,
            UNKNOWN,
            tag,
            internal,
            "IPv6 indicators are classified but not queried by this build",
        )

    internal = tag in INTERNAL_CLASSIFICATIONS
    detail = f"{tag}: non-routable, never sent to external APIs" if internal else "publicly routable address"
    return IOCRecord(raw, value, IPV4, tag, internal, detail)


def classify_batch(values) -> list[IOCRecord]:
    """Classify an iterable of raw indicators, preserving order."""
    return [classify_ioc(value) for value in values]


def filter_iocs(values) -> tuple[list[IOCRecord], list[IOCRecord]]:
    """Split an iterable of raw indicators into ``(valid, invalid)`` records."""
    valid: list[IOCRecord] = []
    invalid: list[IOCRecord] = []
    for record in classify_batch(values):
        (valid if record.is_valid else invalid).append(record)
    return valid, invalid


def dedupe(records) -> list[IOCRecord]:
    """Drop duplicate indicators (case-insensitive) while keeping order."""
    seen: set[str] = set()
    unique: list[IOCRecord] = []
    for record in records:
        key = record.value.lower() if isinstance(record, IOCRecord) else str(record).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(record)
    return unique
