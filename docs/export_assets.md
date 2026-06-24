# Export Assets — what it does, why, and how to use it

## What it does

`scripts/export_assets.py` pulls **every asset** from your Tenable tenant and
writes it to a CSV or JSON file. It works whether you have Tenable Vulnerability
Management or full Tenable One — assets are a core VM object, so no Tenable One
licence is required.

## Why it's built this way

**It uses the asynchronous export API, not the workbenches.** Tenable explicitly
recommends the `/assets/export` endpoint over the workbenches endpoints for
retrieving data, because the export pipeline is optimised for volume and won't
trip rate limits the way repeated workbench paging will. The flow is:

1. `POST /assets/export` — you ask for an export and get back an `export_uuid`.
2. `GET /assets/export/{uuid}/status` — you poll until the status is `FINISHED`,
   collecting chunk IDs as they become `available`.
3. `GET /assets/export/{uuid}/chunks/{id}` — you download each chunk and stitch
   them together.

The script streams chunks as they're ready rather than waiting for the whole job,
and yields one asset at a time so a large tenant doesn't blow up memory.

**It honours rate and concurrency limits.** Tenable's rate limit is dynamic — it
isn't a fixed number, it depends on current platform load. When you exceed it you
get a `429` with a `retry-after` header telling you how long to wait. The shared
client (`tenable_client.py`) catches that and waits exactly that long. It also
runs requests **sequentially** — Tenable specifically advises against
multi-threading the API.

**Keys come from the environment, never the code.** This keeps secrets out of
source control and out of your shell history if you use a `.env` loader.

## Prerequisites

- Python 3.9+
- `pip install -r requirements.txt`
- A Tenable API key pair. A **Read-Only** role key is sufficient for this script
  and is the safest choice — see `docs/00-start-here.md`.

## How to run it

```bash
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"
# Optional, for non-US/other regions:
# export TIO_BASE_URL="https://cloud.tenable.com"

# Check it works before pulling data:
python scripts/export_assets.py --dry-run

# Export to CSV (default):
python scripts/export_assets.py --out assets.csv

# Export full records to JSON:
python scripts/export_assets.py --format json --out assets.json

# Larger chunks for very large tenants:
python scripts/export_assets.py --chunk-size 5000 --verbose
```

## How to read the output

- **CSV** contains a curated, flat subset of the most useful fields (id, IPs,
  FQDNs, OS, first/last seen, tags). Lists are joined with `; ` and tags render
  as `key=value`. Edit `CSV_FIELDS` in the script to add columns.
- **JSON** contains the complete asset records exactly as Tenable returns them.

On success you'll see, e.g.:

```
Connected as: jbarnes (access level: Read-Only [0])
Exported 12,431 assets to assets.csv
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (or dry-run OK) |
| 2 | Missing/invalid API keys |
| 3 | Valid key but no licence/permission for this data (403/404) |
| 4 | Connectivity or export-processing error |

## Engineer notes

- The retrieval logic lives in `TenableClient.export_assets`, a generator — wrap
  it in your own sink (database, S3, message queue) instead of the CSV/JSON writers.
- For incremental pulls, pass `filters={"last_seen": <epoch>}` (see Tenable's
  "Refine Asset Export Requests" doc) to only fetch assets seen since a timestamp.
