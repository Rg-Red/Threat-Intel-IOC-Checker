# Threat-Intel-IOC-Checker

SOC Tier-1 indicator-of-compromise (IOC) triage CLI. Classifies IPv4
addresses and file hashes (MD5/SHA1/SHA256), filters out internal/bogon
IPs before ever calling an external API, checks reputation against
AbuseIPDB and VirusTotal v3 (or a deterministic offline MockProvider),
caches results in SQLite with a TTL, and renders a rich terminal report
or a JSON export.

- **Author:** USER-Bi (Rg-Red)
- **Version:** 1.0.0
- **Requires:** Python 3.13+

## Install

```powershell
pip install -r requirements.txt
```

## Usage

```powershell
# Single indicator, offline/deterministic mock mode
python ioc_checker.py 185.220.101.1 --mock

# Batch file, one IOC per line (# comments and blank lines ignored)
python ioc_checker.py --file iocs.txt --mock -o reports/output.json

# Live lookups (requires API keys)
$env:ABUSEIPDB_API_KEY = "..."
$env:VT_API_KEY = "..."
python ioc_checker.py 8.8.8.8

# Suppress the banner, force a cache refresh
python ioc_checker.py 8.8.8.8 --no-banner --refresh
```

## CLI Flags

| Flag | Description |
| --- | --- |
| `ioc` | Single IOC to check (positional, mutually exclusive with `--file`) |
| `--file, -f` | Path to a file with one IOC per line |
| `--mock` | Use the deterministic offline `MockProvider` (no network/API key needed) |
| `-o, --output` | Write a JSON report to the given path |
| `--no-banner` | Suppress the startup banner |
| `--refresh` | Bypass the cache and force a fresh lookup |
| `--no-cache` | Disable the SQLite cache entirely |
| `--cache-db` | Path to the SQLite cache database (default `ioc_cache.db`) |
| `--ttl` | Cache TTL in seconds (default `86400` / 24h) |
| `--timeout` | HTTP timeout in seconds for live providers |
| `--abuseipdb-key` / `--virustotal-key` | Override `ABUSEIPDB_API_KEY` / `VT_API_KEY` env vars |

## Risk Scoring

| Verdict | AbuseIPDB score | VirusTotal detections | Color |
| --- | --- | --- | --- |
| `CLEAN` | 0-10 | 0 | green |
| `SUSPICIOUS` | 11-50 | 1-3 | yellow |
| `MALICIOUS` | >50 | >3 | red |

Private, loopback, and bogon IPs (RFC 1918 / RFC 5735) are tagged
`INTERNAL_IP` and never sent to an external API.

## Exit Codes

- `0` - completed, no malicious verdicts
- `1` - no valid IOCs found
- `2` - input file not found
- `3` - completed, at least one `MALICIOUS` verdict

## Testing

```powershell
python -m unittest test_ioc_checker -v
```

45 offline unit tests cover validation/refanging, bogon and private-range
filtering, SQLite cache TTL/expiry, `MockProvider` determinism, verdict
scoring boundaries, and CLI/JSON integration. No network access or API
keys are required.
