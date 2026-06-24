# Export Vulnerabilities — what it does, why, and how to use it

## What it does

`scripts/export_vulnerabilities.py` pulls vulnerability **findings** (a plugin
result on an asset) from your Tenable tenant and writes them to CSV or JSON. You
can filter by severity. Works for Tenable VM and Tenable One — no Tenable One
licence required.

## Why it's built this way

Same rationale as the asset export: it uses the **asynchronous `/vulns/export`
endpoint**, which Tenable recommends over the workbenches for retrieving data,
and it reuses the shared `TenableClient` so it inherits the `429`/`retry-after`
backoff and sequential-request behaviour.

The one difference worth knowing: the vuln export sizes its chunks by **number of
assets** (`num_assets`), not by record count. A finding is per-asset-per-plugin,
so one asset can contribute many findings to a chunk.

## Prerequisites

- Python 3.9+, `pip install -r requirements.txt`
- A Tenable API key pair (a **Read-Only** role key is enough and safest).

## How to run it

```bash
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"

# Verify access first:
python scripts/export_vulnerabilities.py --dry-run

# Critical + high findings to CSV:
python scripts/export_vulnerabilities.py --severity critical high --out vulns.csv

# Everything, full records, to JSON:
python scripts/export_vulnerabilities.py --format json --out vulns.json
```

## How to read the output

- **CSV** is a flat, analyst-friendly view: asset FQDN/IP, plugin id/name,
  severity, CVE(s), state, and first/last found timestamps. Edit `CSV_FIELDS` /
  `_row_to_csv` in the script to change columns.
- **JSON** is the complete finding records as Tenable returns them.

Example success output:

```
Connected as: jbarnes (access level: Read-Only [0])
Exported 3,902 findings to vulns.csv
```

## Exit codes

Identical to `export_assets.py`: 0 success, 2 bad/missing keys, 3 no
licence/permission, 4 connectivity/processing error.

## Engineer notes

- `TenableClient.export_vulnerabilities` is a generator — point it at your own
  sink for pipelines.
- For incremental pulls use `filters={"since": <epoch>}` to get only findings
  updated since a timestamp (see Tenable's "Refine Vulnerability Export Requests").
- Useful filters include `severity`, `state` (`open`, `reopened`, `fixed`), and
  `plugin_id`.
