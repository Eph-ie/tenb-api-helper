#!/usr/bin/env python3
"""
get_exposure_score.py
---------------------
Retrieve your Cyber Exposure Score (CES) and Exposure View cards from
Tenable One. TENABLE ONE ONLY -- needs the Exposure View / Lumin licence.

Unlike the export scripts this is SYNCHRONOUS: one GET, score comes straight
back. It also demonstrates the licence probe -- a VM-only key gets a clear
"requires Tenable One" message (exit 3), not a crash.

NOTE: The Exposure View API is currently BETA; its response shape may change.

Usage:
    export TIO_ACCESS_KEY=...
    export TIO_SECRET_KEY=...
    python get_exposure_score.py                 # global (Tenable-provided) cards
    python get_exposure_score.py --all-cards      # include custom cards too
    python get_exposure_score.py --out ces.csv    # also write a CSV
    python get_exposure_score.py --dry-run
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


def _summarise(card: Dict[str, Any]) -> Dict[str, Any]:
    ces = card.get("ces_score") or {}
    trend = card.get("ces_trend") or []
    return {
        "name": card.get("name", ""),
        "card_type": card.get("card_type", ""),
        "ces_score": ces.get("score", ""),
        "grade": ces.get("grade", ""),
        "sla_percentage": card.get("sla_percentage", ""),
        "exposure_class": "; ".join(card.get("exposure_class", []) or []),
        "latest_trend_date": (trend[-1].get("date", "") if trend else ""),
        "card_id": card.get("id", ""),
    }


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Get Tenable One Cyber Exposure Score (read-only).")
    parser.add_argument("--format", choices=["csv", "json"], default="csv")
    parser.add_argument("--out", default=None, help="Optional file to write; otherwise console only.")
    parser.add_argument("--all-cards", action="store_true",
                        help="Include user-created custom cards (default: global cards only).")
    parser.add_argument("--card-id", default=None, help="Fetch full detail for one card id.")
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
        print("Dry run OK -- credentials valid (Exposure View access checked on real run).")
        return 0

    try:
        if args.card_id:
            cards = [client.get_exposure_card(args.card_id)]
        else:
            is_global = None if args.all_cards else True
            resp = client.exposure_view_cards(is_global=is_global)
            cards = resp.get("data", []) or []
    except LicenseOrPermissionError:
        print("This requires a Tenable One licence (Exposure View / Lumin). Your key "
              "doesn't have access to the Exposure Management API.", file=sys.stderr)
        return 3
    except TenableError as e:
        print(f"Request failed: {e}", file=sys.stderr)
        return 4

    if not cards:
        print("No exposure view cards returned.")
        return 0

    rows = [_summarise(c) for c in cards]

    # Console table
    print(f"\n{'Card':<32} {'CES':>5} {'Grade':>5} {'SLA%':>7}  Class")
    print("-" * 70)
    for r in rows:
        print(f"{str(r['name'])[:32]:<32} {str(r['ces_score']):>5} "
              f"{str(r['grade']):>5} {str(r['sla_percentage']):>7}  {r['exposure_class']}")

    if args.out:
        if args.format == "json":
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(cards, fh, indent=2)  # full records
        else:
            with open(args.out, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
        print(f"\nWrote {len(rows)} card(s) to {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
