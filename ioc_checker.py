#!/usr/bin/env python3
"""Threat-Intel-IOC-Checker - SOC Tier-1 indicator triage CLI.

Author : USER-Bi (Rg-Red)
Version: 1.0.0
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cache_manager import DEFAULT_TTL_SECONDS, CacheManager
from providers import (
    BaseProvider,
    CLEAN,
    ERROR,
    LookupResult,
    MALICIOUS,
    SUSPICIOUS,
    build_providers,
    select_provider,
)
from validator import (
    AUTHOR,
    INTERNAL_IP,
    IOCRecord,
    TOOL_NAME,
    VERSION,
    classify_batch,
    dedupe,
)

VERDICT_STYLE = {
    CLEAN: "bold green",
    SUSPICIOUS: "bold yellow",
    MALICIOUS: "bold red",
    ERROR: "bold magenta",
    INTERNAL_IP: "bold cyan",
}

BANNER = r"""
 _____ _               _     ___       _       _   ___ ___   _____
|_   _| |_  _ _ ___ __ _| |_ |_ _|_ _  | |_ ___| | |_ _/ _ \ / __\ \
  | | | ' \| '_/ -_) _` |  _| | || ' \ |  _/ -_) |  | | (_) | (__ ) )
  |_| |_||_|_| \___\__,_|\__||___|_||_| \__\___|_| |___\___/ \___/_/

        Checker  --  SOC Tier-1 IOC Triage CLI
"""

console = Console()


def print_banner() -> None:
    body = Text(BANNER.strip("\n"), style="bold cyan")
    footer = Text.from_markup(
        f"[dim]v{VERSION}[/dim]   [bold]{TOOL_NAME}[/bold]   "
        f"[dim]by[/dim] [bold magenta]{AUTHOR}[/bold magenta]"
    )
    console.print(Panel.fit(body, border_style="cyan", padding=(0, 2)))
    console.print(footer, justify="center")
    console.print()


def read_iocs_from_file(path: str) -> list[str]:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"IOC file not found: {path}")
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def get_api_keys(args: argparse.Namespace) -> tuple[Optional[str], Optional[str]]:
    abuseipdb_key = args.abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY")
    virustotal_key = args.virustotal_key or os.environ.get("VT_API_KEY")
    return abuseipdb_key, virustotal_key


def resolve_ioc(
    record: IOCRecord,
    providers: list[BaseProvider],
    cache: Optional[CacheManager],
    ttl_seconds: int,
    refresh: bool,
) -> LookupResult:
    """Resolve one IOCRecord into a LookupResult, using cache when possible."""
    if record.is_internal:
        return LookupResult(
            ioc_value=record.value,
            ioc_type=record.ioc_type,
            provider="local",
            verdict=INTERNAL_IP,
            detail=f"{record.classification}: internal/non-routable address, not queried",
        )

    if not record.is_queryable:
        return LookupResult(
            ioc_value=record.value,
            ioc_type=record.ioc_type,
            provider="local",
            verdict=ERROR,
            detail=record.detail or "indicator type not supported for lookup",
            error="unsupported indicator type",
        )

    provider = select_provider(providers, record.ioc_type)
    if provider is None:
        return LookupResult(
            ioc_value=record.value,
            ioc_type=record.ioc_type,
            provider="local",
            verdict=ERROR,
            detail="no provider configured for this indicator type",
            error="no provider available",
        )

    if cache is not None and not refresh:
        cached = cache.get(provider.name, record.ioc_type, record.value)
        if cached is not None:
            result = LookupResult(**{**cached.payload, "from_cache": True})
            return result

    result = provider.lookup(record.value, record.ioc_type)

    if cache is not None and result.ok:
        cache.set(provider.name, record.ioc_type, record.value, result.as_dict(), ttl_seconds)

    return result


def verdict_style(verdict: str) -> str:
    return VERDICT_STYLE.get(verdict, "white")


def render_table(rows: list[tuple[IOCRecord, LookupResult]]) -> Table:
    table = Table(title="IOC Triage Results", show_lines=False, expand=True)
    table.add_column("Indicator", style="bold white", overflow="fold")
    table.add_column("Type", style="cyan")
    table.add_column("Verdict", justify="center")
    table.add_column("Score/Det.", justify="right")
    table.add_column("Provider", style="dim")
    table.add_column("Detail", overflow="fold")

    for record, result in rows:
        style = verdict_style(result.verdict)
        score_text = f"{result.score}" if result.ioc_type != "unknown" else "-"
        if result.total_engines:
            score_text = f"{result.detections}/{result.total_engines}"
        cache_tag = " [dim](cached)[/dim]" if result.from_cache else ""
        table.add_row(
            record.raw,
            record.ioc_type if record.ioc_type != "unknown" else record.classification,
            Text(result.verdict, style=style),
            score_text,
            result.provider,
            Text.from_markup(result.detail + cache_tag),
        )
    return table


def render_summary(rows: list[tuple[IOCRecord, LookupResult]], invalid: list[IOCRecord]) -> Panel:
    counts = {CLEAN: 0, SUSPICIOUS: 0, MALICIOUS: 0, ERROR: 0, INTERNAL_IP: 0}
    for _, result in rows:
        counts[result.verdict] = counts.get(result.verdict, 0) + 1

    summary = Text()
    summary.append(f"Total checked: {len(rows)}   ", style="bold")
    summary.append(f"Clean: {counts.get(CLEAN, 0)}  ", style="green")
    summary.append(f"Suspicious: {counts.get(SUSPICIOUS, 0)}  ", style="yellow")
    summary.append(f"Malicious: {counts.get(MALICIOUS, 0)}  ", style="red")
    summary.append(f"Internal: {counts.get(INTERNAL_IP, 0)}  ", style="cyan")
    summary.append(f"Errors: {counts.get(ERROR, 0)}", style="magenta")
    if invalid:
        summary.append(f"\nSkipped (unrecognised): {len(invalid)}", style="dim")
    return Panel(summary, title="Summary", border_style="white")


def export_json(path: str, rows: list[tuple[IOCRecord, LookupResult]], invalid: list[IOCRecord]) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "author": AUTHOR,
        "results": [
            {**record.as_dict(), "lookup": result.as_dict()} for record, result in rows
        ],
        "skipped": [record.as_dict() for record in invalid],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc_checker.py",
        description=f"{TOOL_NAME} v{VERSION} - SOC Tier-1 IOC triage CLI by {AUTHOR}",
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("ioc", nargs="?", help="Single IOC to check (IPv4, MD5, SHA1, or SHA256)")
    target_group.add_argument("--file", "-f", dest="file", help="Path to a file with one IOC per line")

    parser.add_argument("--mock", action="store_true", help="Use the deterministic offline MockProvider")
    parser.add_argument("-o", "--output", dest="output", help="Write JSON report to this path")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the startup banner")
    parser.add_argument("--refresh", action="store_true", help="Bypass cache and force a fresh lookup")
    parser.add_argument("--no-cache", action="store_true", help="Disable the SQLite cache entirely")
    parser.add_argument("--cache-db", default="ioc_cache.db", help="Path to the SQLite cache database")
    parser.add_argument(
        "--ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help="Cache TTL in seconds (default: 86400 / 24h)",
    )
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds for live providers")
    parser.add_argument("--abuseipdb-key", help="AbuseIPDB API key (overrides ABUSEIPDB_API_KEY env var)")
    parser.add_argument("--virustotal-key", help="VirusTotal API key (overrides VT_API_KEY env var)")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return parser


def run(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.no_banner:
        print_banner()

    try:
        if args.file:
            raw_iocs = read_iocs_from_file(args.file)
        else:
            raw_iocs = [args.ioc]
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 2

    records = dedupe(classify_batch(raw_iocs))
    valid = [r for r in records if r.is_valid]
    invalid = [r for r in records if not r.is_valid]

    if not valid:
        console.print("[bold red]No valid IOCs to check.[/bold red]")
        return 1

    abuseipdb_key, virustotal_key = get_api_keys(args)
    providers = build_providers(
        mock=args.mock,
        abuseipdb_key=abuseipdb_key,
        virustotal_key=virustotal_key,
        timeout=args.timeout,
    )

    cache: Optional[CacheManager] = None
    if not args.no_cache:
        cache = CacheManager(db_path=args.cache_db, ttl_seconds=args.ttl)

    rows: list[tuple[IOCRecord, LookupResult]] = []
    try:
        for record in valid:
            result = resolve_ioc(record, providers, cache, args.ttl, args.refresh)
            rows.append((record, result))
    finally:
        if cache is not None:
            cache.close()

    console.print(render_table(rows))
    console.print(render_summary(rows, invalid))

    if invalid:
        skipped = ", ".join(r.raw for r in invalid)
        console.print(f"[dim]Skipped unrecognised input(s): {skipped}[/dim]")

    if args.output:
        export_json(args.output, rows, invalid)
        console.print(f"[bold green]JSON report written to:[/bold green] {args.output}")

    has_malicious = any(result.verdict == MALICIOUS for _, result in rows)
    return 3 if has_malicious else 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
