#!/usr/bin/env python3
"""
get_scan_results.py
-------------------
List your scans, or pull the results summary for one scan, from Tenable
Vulnerability Management. Demonstrates the SCOPED, SYNCHRONOUS path (a plain GET)
as opposed to the bulk async exports.

Usage:
    export TIO_ACCESS_KEY=...
    export TIO_SECRET_KEY=...
    python get_scan_results.py                       # list scans (pick an id)
    python get_scan_results.py --scan-id 32          # results summary for scan 32
    python get_scan_results.py --scan-id 32 --out scan32.csv
    python get_scan_results.py --dry-run

Note: GET /scans/{id} returns limited data for scans older than 35 days
("archived"). For full archived results use the scan export endpoint instead.
The scan-details endpoint needs the Scan Operator [24] role (or VM_SCAN.READ).
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

from tenable_client import (
    TenableClient,
    AuthError,
    LicenseOrPermissionError,
    TenableError,
)


def _ts(epoch: Any) -> str:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return ""


def list_scans(client: TenableClient) -> int:
    scans = client.list_scans()
    if not scans:
        print("No scans visible to this key.")
        return 0
    print(f"\n{'ID':>8}  {'Status':<12} {'Last run':<17} Name")
    print("-" * 70)
    for s in sorted(scans, key=lambda x: x.get("last_modification_date", 0), reverse=True):
        print(f"{str(s.get('id','')):>8}  {str(s.get('status','')):<12} "
              f"{_ts(s.get('last_modification_date')):<17} {s.get('name','')}")
    print(f"\n{len(scans)} scan(s). Re-run with --scan-id <ID> for results.")
    return 0


def scan_summary(client: TenableClient, scan_id: str, out: str | None, fmt: str) -> int:
    data = client.get_scan_details(scan_id)
    info = data.get("info", {}) or {}
    hosts = data.get("hosts", []) or []
    vulns = data.get("vulnerabilities", []) or []

    print(f"\nScan: {info.get('name','?')}  (status: {info.get('status','?')})")
    print(f"Hosts: {info.get('hostcount','?')}   "
          f"Run: {_ts(info.get('scan_start'))} -> {_ts(info.get('scan_end'))}")

    if info.get("is_archived"):
        print("\n⚠️  This scan is ARCHIVED (>35 days old): host/vulnerability detail is "
              "omitted by this endpoint. Use the scan export endpoint for full data.")

    # Severity totals across hosts
    totals = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for h in hosts:
        for k in totals:
            totals[k] += int(h.get(k, 0) or 0)
    if hosts:
        print("\nFindings by severity (sum across hosts):")
        for k in ("critical", "high", "medium", "low", "info"):
            print(f"  {k:<9} {totals[k]}")

    sev_name = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    rows = [{
        "plugin_id": v.get("plugin_id", ""),
        "plugin_name": v.get("plugin_name", ""),
        "severity": sev_name.get(v.get("severity"), v.get("severity", "")),
        "plugin_family": v.get("plugin_family", ""),
        "count": v.get("count", ""),
    } for v in vulns]

    if rows:
        top = sorted(rows, key=lambda r: r["count"] if isinstance(r["count"], int) else 0, reverse=True)[:10]
        print("\nTop plugins by host count:")
        for r in top:
            print(f"  [{r['severity']:<8}] {str(r['plugin_name'])[:50]:<50} x{r['count']}")

    if out and rows:
        if fmt == "json":
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        else:
            with open(out, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
        print(f"\nWrote scan results to {out}")
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="List scans or get one scan's results (read-only).")
    parser.add_argument("--scan-id", default=None, help="Scan id (or schedule_uuid) to summarise.")
    parser.add_argument("--format", choices=["csv", "json"], default="csv")
    parser.add_argument("--out", default=None)
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
        print("Dry run OK -- credentials valid and scans endpoint reachable.")
        return 0

    try:
        if args.scan_id:
            return scan_summary(client, args.scan_id, args.out, args.format)
        return list_scans(client)
    except LicenseOrPermissionError as e:
        print(f"Access problem: {e}\n(Scan details need the Scan Operator [24] role "
              "or VM_SCAN.READ.)", file=sys.stderr)
        return 3
    except TenableError as e:
        print(f"Request failed: {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
