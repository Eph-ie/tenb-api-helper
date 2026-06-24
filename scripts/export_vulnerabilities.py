#!/usr/bin/env python3
"""
export_vulnerabilities.py
-------------------------
Export vulnerability findings from Tenable Vulnerability Management (works for VM
and Tenable One licences) to CSV or JSON, using the recommended asynchronous
export API. Same shape as export_assets.py -- see docs/export_vulnerabilities.md.

Usage:
    export TIO_ACCESS_KEY=...
    export TIO_SECRET_KEY=...
    python export_vulnerabilities.py --severity critical high --out vulns.csv
    python export_vulnerabilities.py --dry-run
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from typing import Any, Dict, List

from tenable_client import (
    TenableClient,
    AuthError,
    LicenseOrPermissionError,
    TenableError,
)

CSV_FIELDS = [
    "asset_fqdn",
    "asset_ipv4",
    "plugin_id",
    "plugin_name",
    "severity",
    "cve",
    "state",
    "first_found",
    "last_found",
]


def _row_to_csv(finding: Dict[str, Any]) -> Dict[str, Any]:
    asset = finding.get("asset", {}) or {}
    plugin = finding.get("plugin", {}) or {}
    return {
        "asset_fqdn": asset.get("fqdn", ""),
        "asset_ipv4": asset.get("ipv4", ""),
        "plugin_id": plugin.get("id", ""),
        "plugin_name": plugin.get("name", ""),
        "severity": finding.get("severity", ""),
        "cve": "; ".join(plugin.get("cve", []) or []),
        "state": finding.get("state", ""),
        "first_found": finding.get("first_found", ""),
        "last_found": finding.get("last_found", ""),
    }


def write_csv(rows: List[Dict[str, Any]], out_path: str) -> int:
    n = 0
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for finding in rows:
            writer.writerow(_row_to_csv(finding))
            n += 1
    return n


def write_json(rows: List[Dict[str, Any]], out_path: str) -> int:
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)
    return len(rows)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export Tenable vulnerability findings (read-only).")
    parser.add_argument("--format", choices=["csv", "json"], default="csv")
    parser.add_argument("--out", default=None)
    parser.add_argument(
        "--severity",
        nargs="*",
        choices=["info", "low", "medium", "high", "critical"],
        help="Filter by severity, e.g. --severity critical high",
    )
    parser.add_argument("--num-assets", type=int, default=500)
    parser.add_argument(
        "--days",
        type=int,
        default=None,
        help="Only findings seen in the last N days. Omit to export ALL findings "
             "(the script then sends since=0 to bypass Tenable's silent 30-day default).",
    )
    parser.add_argument(
        "--since",
        type=int,
        default=None,
        help="Unix epoch (seconds): only findings seen on/after this time. "
             "Overrides --days.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        client = TenableClient()
    except AuthError as e:
        print(f"Auth error: {e}", file=sys.stderr)
        return 2

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
        print("Dry run OK -- credentials valid and vuln export endpoint reachable.")
        return 0

    filters: Dict[str, Any] = {}
    if args.severity:
        filters["severity"] = args.severity

    # IMPORTANT: Tenable's vuln export silently restricts results to findings
    # found/fixed in the LAST 30 DAYS unless a time-based filter is supplied.
    # To export everything we must send an explicit `since`. Default to 0 (epoch)
    # for a full pull; honour --since / --days when given.
    import time as _time
    if args.since is not None:
        filters["since"] = args.since
    elif args.days is not None:
        filters["since"] = int(_time.time()) - args.days * 86400
    else:
        filters["since"] = 0  # full export -- bypass the 30-day default window
    if args.verbose:
        window = "ALL findings (since=0)" if filters["since"] == 0 else f"since epoch {filters['since']}"
        print(f"Export window: {window}")

    out_path = args.out or f"vulns.{args.format}"
    try:
        rows = list(
            client.export_vulnerabilities(num_assets=args.num_assets, filters=filters or None)
        )
    except LicenseOrPermissionError as e:
        print(f"Access problem during export: {e}", file=sys.stderr)
        return 3
    except TenableError as e:
        print(f"Export failed: {e}", file=sys.stderr)
        return 4

    written = write_csv(rows, out_path) if args.format == "csv" else write_json(rows, out_path)
    print(f"Exported {written} findings to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())