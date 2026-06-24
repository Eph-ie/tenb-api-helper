# Get Scan Results — what it does, why, and how to use it

## What it does

`scripts/get_scan_results.py` does two things:

1. With no arguments, it **lists your scans** (id, status, last run, name) so you
   can find the one you want.
2. With `--scan-id <id>`, it pulls that scan's **results summary** — host count,
   findings totalled by severity, and the top plugins by host count — and
   optionally writes CSV/JSON.

Works for Tenable VM and Tenable One.

## Why it's built this way

This is the **scoped, synchronous** path — a plain `GET /scans/{id}` returns the
results for one scan directly, no export job. It's the right tool when you want
*one* scan, not your whole environment. (For everything across the tenant, use
`export_vulnerabilities.py`.)

## ⚠️ Two gotchas

- **Archived scans (>35 days).** `GET /scans/{id}` returns only summary `info` for
  scans older than 35 days — the per-host and per-vuln arrays are dropped and
  `info.is_archived` is `true`. The script warns you when this happens. For full
  archived detail you need the scan **export** endpoint instead.
- **Permission.** Listing scans needs Basic [16] + Can View on the scan. Scan
  *details* need the **Scan Operator [24]** role (or the `VM_SCAN.READ` custom
  privilege). A lower-privileged key gets a clear exit-code-3 message.

## Prerequisites

- Python 3.9+, `pip install -r requirements.txt`
- A Tenable VM/One API key with at least Can View on the scans you want.

## How to run it

```bash
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"

python scripts/get_scan_results.py                  # list scans, note an ID
python scripts/get_scan_results.py --scan-id 32     # summary for scan 32
python scripts/get_scan_results.py --scan-id 32 --out scan32.csv
```

## How to read the output

The scan list is sorted most-recent-run first. The per-scan summary shows the
severity totals across all hosts and the ten plugins affecting the most hosts.
CSV contains one row per plugin (id, name, severity, family, host count); JSON
contains the full scan-details response.

## Exit codes

0 success / dry-run · 2 bad keys · 3 no permission/role · 4 other error.
