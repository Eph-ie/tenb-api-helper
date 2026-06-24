# Critical Vulns by Machine — what it does, why, and how to use it

## What it does

`scripts/critical_vulns_by_machine.py` pulls **critical-severity** vulnerability
findings from your Tenable tenant and writes them to CSV or JSON. The output is
grouped by machine (sorted A→Z by hostname/IP) and within each machine the
findings are sorted **highest CVSS score first**. Each row includes the
vulnerability name, CVSSv3 score (with CVSSv2 fallback), and VPR score.

Only **Windows and Linux** assets are included by default. You can narrow to one
OS with `--os windows` or `--os linux`.

Works with both **Tenable VM** and **Tenable One** licences — no Tenable One
required.

## Why it's built this way

The script uses the async `/vulns/export` endpoint (same as
`export_vulnerabilities.py`) because it's the only path Tenable recommends for
bulk retrieval. OS filtering is done client-side after the export because the
export API doesn't provide an OS-based filter natively — the asset's
`operating_system` field is present in every finding record, so filtering
post-download is both safe and accurate.

CVSS sort prefers **CVSSv3** (`plugin.cvss3_base_score`) and falls back to
**CVSSv2** (`plugin.cvss_base_score`) when v3 is absent. VPR comes from
`plugin.vpr.score`.

## Prerequisites

- Python 3.9+
- `pip install requests` (or `pip install -r requirements.txt`)
- A Tenable API key pair — a **Read-Only** role is sufficient and recommended.

## How to run it

```bash
# 1. Set your credentials
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"

# 2. Verify credentials (no data pulled)
python scripts/critical_vulns_by_machine.py --dry-run

# 3. Export all critical findings for Windows + Linux machines
python scripts/critical_vulns_by_machine.py --out critical_by_machine.csv

# 4. Windows only
python scripts/critical_vulns_by_machine.py --os windows --out windows_critical.csv

# 5. Linux only
python scripts/critical_vulns_by_machine.py --os linux --out linux_critical.csv

# 6. Only findings from the last 30 days
python scripts/critical_vulns_by_machine.py --days 30 --out critical_30d.csv

# 7. JSON output with verbose logging
python scripts/critical_vulns_by_machine.py --format json --out critical_by_machine.json --verbose
```

## How to read the output

The CSV has one row per finding. Columns:

| Column | Description |
|---|---|
| `asset_fqdn` | Hostname / fully qualified domain name |
| `asset_ipv4` | IPv4 address of the asset |
| `operating_system` | OS string(s) as reported by Tenable |
| `plugin_id` | Tenable plugin ID |
| `plugin_name` | Vulnerability / plugin name |
| `cvss3_base_score` | CVSSv3 base score (0.0–10.0), or `N/A` if unavailable |
| `cvss2_base_score` | CVSSv2 base score (0.0–10.0), or `N/A` if unavailable |
| `vpr_score` | Tenable VPR score (0.0–10.0), or `N/A` if unavailable |
| `cve` | CVE identifier(s), semicolon-separated |
| `state` | `open`, `reopened`, or `fixed` |
| `first_found` | Timestamp the finding was first detected |
| `last_found` | Timestamp the finding was most recently confirmed |

Rows are sorted by `asset_fqdn` ascending, then `cvss3_base_score` descending
within each machine. Findings with no CVSS score sort to the bottom.

Example output:

```
Connected as: jbarnes (access level: Read-Only [0])
Requesting export from Tenable (this may take a few minutes)…
Exported 1,847 critical findings (both assets) → critical_by_machine.csv
Sorted by: machine name (A→Z), then CVSS score (high→low) within each machine.
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Missing or invalid API keys |
| 3 | Keys valid but lack licence / permission for this endpoint |
| 4 | Connectivity or export processing error |

## ⚠️ Gotchas

**30-day default window:** Tenable's vuln export silently limits results to the
last 30 days unless you supply a time filter. This script defaults to `since=0`
(full export). Use `--days N` if you only want recent findings (see
`reference/api-gotchas.md` #1).

**OS field depends on scan coverage:** If an asset has never had its OS
identified by a scan (e.g. unauthenticated scans only), `operating_system` will
be empty and the finding will be excluded from the output. Use `--verbose` to see
the total raw count vs the post-filter count.

**VPR availability:** VPR scores require Tenable's research data to be
associated with the plugin. Plugins without a VPR score show `N/A` — this is
expected for less-common or non-CVE findings.

## Engineer notes

- `TenableClient.export_vulnerabilities` is a generator — you can swap the
  `list(...)` call for a streaming sink in pipeline use-cases.
- The `--since` flag accepts a raw Unix epoch, useful for automation/cron jobs
  that want incremental pulls.
- To add extra columns (e.g. `asset_uuid`, `severity`), extend `CSV_FIELDS` and
  `_finding_to_row` — the raw finding dict is passed through unchanged.
