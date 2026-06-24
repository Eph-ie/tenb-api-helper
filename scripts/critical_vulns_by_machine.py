#!/usr/bin/env python3
"""
critical_vulns_by_machine.py
----------------------------
Export critical-severity vulnerability findings for Windows and Linux assets,
grouped by machine and sorted high-to-low by CVSS score. Includes vulnerability
name, CVSS score, and VPR score.

Uses the recommended asynchronous /vulns/export endpoint. Works with Tenable
Vulnerability Management and Tenable One licences.

Usage:
    export TIO_ACCESS_KEY=...
    export TIO_SECRET_KEY=...

    # Verify credentials (no data pulled):
    python scripts/critical_vulns_by_machine.py --dry-run

    # Export to CSV (default):
    python scripts/critical_vulns_by_machine.py --out critical_by_machine.csv

    # Include only Windows machines:
    python scripts/critical_vulns_by_machine.py --os windows --out windows_critical.csv

    # Full export since epoch (all findings, not just last 30 days):
    python scripts/critical_vulns_by_machine.py --out critical_by_machine.csv --verbose
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time as _time
from typing import Any, Dict, List, Optional, Tuple

from tenable_client import (
    TenableClient,
    AuthError,
    LicenseOrPermissionError,
    TenableError,
)

LOG = logging.getLogger("critical_vulns_by_machine")

# ---------------------------------------------------------------------------
# Output columns
# ---------------------------------------------------------------------------
CSV_FIELDS = [
    "asset_fqdn",
    "asset_ipv4",
    "operating_system",
    "plugin_id",
    "plugin_name",
    "cvss3_base_score",
    "cvss2_base_score",
    "vpr_score",
    "cve",
    "state",
    "first_found",
    "last_found",
]


# ---------------------------------------------------------------------------
# OS detection helpers
# ---------------------------------------------------------------------------
def _os_strings(finding: Dict[str, Any]) -> List[str]:
    """Return the OS strings for a finding's asset (normalised to lower-case)."""
    asset = finding.get("asset") or {}
    raw = asset.get("operating_system") or []
    if isinstance(raw, str):
        raw = [raw]
    return [s.lower() for s in raw if s]


def _is_windows(finding: Dict[str, Any]) -> bool:
    return any("windows" in s for s in _os_strings(finding))


def _is_linux(finding: Dict[str, Any]) -> bool:
    # Covers "Linux", "Ubuntu", "CentOS", "Red Hat", "Debian", etc.
    linux_keywords = ("linux", "ubuntu", "debian", "centos", "red hat", "rhel",
                      "fedora", "suse", "amazon linux", "oracle linux", "alpine")
    return any(kw in s for s in _os_strings(finding) for kw in linux_keywords)


def _matches_os_filter(finding: Dict[str, Any], os_filter: str) -> bool:
    """
    os_filter: "windows" | "linux" | "both"
    Returns True if the finding's asset OS matches.
    """
    if os_filter == "windows":
        return _is_windows(finding)
    if os_filter == "linux":
        return _is_linux(finding)
    # "both" — accept Windows or Linux, exclude unknowns/other OS
    return _is_windows(finding) or _is_linux(finding)


# ---------------------------------------------------------------------------
# CVSS sort key
# ---------------------------------------------------------------------------
def _cvss_sort_key(row: Dict[str, Any]) -> float:
    """
    Sort key for CVSS score: prefer CVSSv3, fall back to CVSSv2.
    Returns a float; missing scores sort to the bottom (0.0).
    """
    v3 = row.get("cvss3_base_score")
    v2 = row.get("cvss2_base_score")
    try:
        if v3 not in (None, "", "N/A"):
            return float(v3)
        if v2 not in (None, "", "N/A"):
            return float(v2)
    except (ValueError, TypeError):
        pass
    return 0.0


# ---------------------------------------------------------------------------
# Record conversion
# ---------------------------------------------------------------------------
def _finding_to_row(finding: Dict[str, Any]) -> Dict[str, Any]:
    asset = finding.get("asset") or {}
    plugin = finding.get("plugin") or {}
    vpr = plugin.get("vpr") or {}

    os_list = asset.get("operating_system") or []
    if isinstance(os_list, str):
        os_list = [os_list]
    os_display = "; ".join(os_list)

    cvss3 = plugin.get("cvss3_base_score")
    cvss2 = plugin.get("cvss_base_score")  # API field for CVSSv2

    return {
        "asset_fqdn": asset.get("fqdn") or asset.get("hostname") or "",
        "asset_ipv4": asset.get("ipv4") or "",
        "operating_system": os_display,
        "plugin_id": plugin.get("id", ""),
        "plugin_name": plugin.get("name", ""),
        "cvss3_base_score": cvss3 if cvss3 is not None else "N/A",
        "cvss2_base_score": cvss2 if cvss2 is not None else "N/A",
        "vpr_score": vpr.get("score", "N/A"),
        "cve": "; ".join(plugin.get("cve") or []),
        "state": finding.get("state", ""),
        "first_found": finding.get("first_found", ""),
        "last_found": finding.get("last_found", ""),
    }


def _asset_sort_key(row: Dict[str, Any]) -> Tuple[str, float]:
    """Primary sort: asset FQDN/IP ascending. Secondary: CVSS descending (negated)."""
    ident = row.get("asset_fqdn") or row.get("asset_ipv4") or ""
    return (ident.lower(), -_cvss_sort_key(row))


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------
def write_csv(rows: List[Dict[str, Any]], out_path: str) -> int:
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)


def write_json(rows: List[Dict[str, Any]], out_path: str) -> int:
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)
    return len(rows)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export critical vulnerabilities by machine (Windows/Linux), "
                    "sorted high-to-low by CVSS score."
    )
    parser.add_argument("--format", choices=["csv", "json"], default="csv",
                        help="Output format (default: csv)")
    parser.add_argument("--out", default=None,
                        help="Output file path (default: critical_by_machine.<format>)")
    parser.add_argument(
        "--os",
        choices=["windows", "linux", "both"],
        default="both",
        help="Limit to Windows machines, Linux machines, or both (default: both)",
    )
    parser.add_argument("--num-assets", type=int, default=500,
                        help="Chunk size for export (assets per chunk, default 500)")
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Only findings seen in the last N days. Omit for ALL findings.",
    )
    parser.add_argument(
        "--since",
        type=int,
        default=None,
        help="Unix epoch (seconds): only findings updated on/after this time. "
             "Overrides --days.",
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Verify credentials and exit without pulling data.")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    # --- credentials ---
    try:
        client = TenableClient()
    except AuthError as e:
        print(f"Auth error: {e}", file=sys.stderr)
        return 2

    # --- probe ---
    try:
        who = client.whoami()
        print(f"Connected as: {who.get('username', 'unknown')} "
              f"(access level: {client.describe_access()})")
    except LicenseOrPermissionError as e:
        print(f"Access problem: {e}", file=sys.stderr)
        return 3
    except TenableError as e:
        print(f"Connectivity problem: {e}", file=sys.stderr)
        return 4

    if args.dry_run:
        print("Dry run OK — credentials valid and reachable.")
        return 0

    # --- build filters ---
    filters: Dict[str, Any] = {"severity": ["critical"]}

    # Bypass Tenable's silent 30-day default window (see api-gotchas.md #1)
    if args.since is not None:
        filters["since"] = args.since
    elif args.days is not None:
        filters["since"] = int(_time.time()) - args.days * 86400
    else:
        filters["since"] = 0  # full export — all findings ever seen

    if args.verbose:
        window = "ALL findings (since=0)" if filters["since"] == 0 else f"since epoch {filters['since']}"
        print(f"Export window: {window}")
        print(f"OS filter: {args.os}")

    out_path = args.out or f"critical_by_machine.{args.format}"

    # --- export ---
    print("Requesting export from Tenable (this may take a few minutes)…")
    try:
        raw_findings = list(
            client.export_vulnerabilities(
                num_assets=args.num_assets,
                filters=filters,
            )
        )
    except LicenseOrPermissionError as e:
        print(f"Access problem during export: {e}", file=sys.stderr)
        return 3
    except TenableError as e:
        print(f"Export failed: {e}", file=sys.stderr)
        return 4

    total_raw = len(raw_findings)

    # --- filter to Windows/Linux ---
    matched = [f for f in raw_findings if _matches_os_filter(f, args.os)]

    if args.verbose:
        print(f"Total critical findings received: {total_raw}")
        print(f"Findings on {args.os} assets: {len(matched)}")

    if not matched:
        print(
            f"No critical findings found for OS filter '{args.os}'. "
            "Check that assets have operating_system data populated in Tenable."
        )
        return 0

    # --- convert and sort ---
    rows = [_finding_to_row(f) for f in matched]
    rows.sort(key=_asset_sort_key)

    # --- write ---
    try:
        written = write_csv(rows, out_path) if args.format == "csv" else write_json(rows, out_path)
    except OSError as e:
        print(f"Failed to write output: {e}", file=sys.stderr)
        return 4

    print(f"Exported {written} critical findings ({args.os} assets) → {out_path}")
    print("Sorted by: machine name (A→Z), then CVSS score (high→low) within each machine.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
