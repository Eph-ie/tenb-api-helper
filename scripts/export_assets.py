#!/usr/bin/env python3
"""
export_assets.py
----------------
Reference implementation: export all assets from Tenable Vulnerability
Management (works for VM and Tenable One licences) to CSV or JSON.

This is the canonical example of the asynchronous export pattern. Other scripts
in this toolkit reuse TenableClient the same way.

Usage:
    export TIO_ACCESS_KEY=...   # never hardcode
    export TIO_SECRET_KEY=...
    python export_assets.py --format csv --out assets.csv
    python export_assets.py --dry-run          # check connectivity + access only
    python export_assets.py --format json --out assets.json --chunk-size 5000
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

# A small, stable subset of common asset fields for CSV output. JSON keeps
# everything. Adjust to taste.
CSV_FIELDS = [
    "id",
    "has_agent",
    "last_seen",
    "first_seen",
    "operating_systems",
    "ipv4s",
    "fqdns",
    "hostnames",
    "tags",
]


def _flatten(value: Any) -> str:
    """Turn lists/dicts into a compact, CSV-friendly string."""
    if value is None:
        return ""
    if isinstance(value, list):
        return "; ".join(_flatten(v) for v in value)
    if isinstance(value, dict):
        # tags come as {"key":..., "value":...}
        if "key" in value and "value" in value:
            return f"{value['key']}={value['value']}"
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def write_csv(rows: List[Dict[str, Any]], out_path: str) -> int:
    n = 0
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _flatten(row.get(k)) for k in CSV_FIELDS})
            n += 1
    return n


def write_json(rows: List[Dict[str, Any]], out_path: str) -> int:
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)
    return len(rows)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export Tenable assets (read-only).")
    parser.add_argument("--format", choices=["csv", "json"], default="csv")
    parser.add_argument("--out", default=None, help="Output file path.")
    parser.add_argument("--chunk-size", type=int, default=1000)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Check connectivity and access level only; export nothing.",
    )
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

    # Capability probe -- fail fast with a human message.
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
        print("Dry run OK -- credentials valid and asset export endpoint reachable.")
        return 0

    out_path = args.out or f"assets.{args.format}"
    try:
        rows = list(client.export_assets(chunk_size=args.chunk_size))
    except LicenseOrPermissionError as e:
        print(f"Access problem during export: {e}", file=sys.stderr)
        return 3
    except TenableError as e:
        print(f"Export failed: {e}", file=sys.stderr)
        return 4

    written = write_csv(rows, out_path) if args.format == "csv" else write_json(rows, out_path)
    print(f"Exported {written} assets to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
