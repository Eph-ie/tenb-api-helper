# Get Exposure Score — what it does, why, and how to use it

## What it does

`scripts/get_exposure_score.py` retrieves your **Cyber Exposure Score (CES)** and
Exposure View cards from Tenable One — the same numbers shown on the Exposure View
dashboard — and prints them as a table, optionally writing CSV/JSON. **Tenable One
only.**

## Why it's built this way

This is the counterpoint to the export scripts: it's **synchronous**. The
Exposure View `cards` endpoint returns the score, grade, SLA %, and a 30-day trend
inline in a single GET — no export job, no polling. So the script just calls it
and formats the result.

It also demonstrates the **licence probe**: if your key belongs to a VM-only
tenant, the Exposure Management API returns `403`, and the script prints a clear
"requires a Tenable One licence" message and exits with code 3 — rather than
throwing a traceback. This is the behaviour the whole toolkit uses to stay usable
for both VM and Tenable One customers.

## ⚠️ Beta endpoint

The Exposure View API is currently **beta** — Tenable notes the response structure
may change. If a field goes missing, check the current spec at
`https://developer.tenable.com/reference/exposure-view-cards-search` and update
`_summarise()` in the script.

## Prerequisites

- Python 3.9+, `pip install -r requirements.txt`
- A **Tenable One** API key (Basic [16] role or `LUMIN_EXPOSURE_VIEW.EXPOSURE_CARD.READ`).

## How to run it

```bash
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"

python scripts/get_exposure_score.py            # Tenable-provided global cards
python scripts/get_exposure_score.py --all-cards # include custom cards
python scripts/get_exposure_score.py --out ces.csv
python scripts/get_exposure_score.py --card-id <id>   # full detail for one card
```

## How to read the output

The console prints one row per card: name, CES (0–1000, lower is better), letter
grade (A–F), SLA %, and exposure class (VM / IDENTITY / CLOUD / WAS / OT / ALL).
CSV gives the same flattened summary; JSON gives the complete card records
including the full `ces_trend` array for charting.

## Exit codes

0 success / dry-run · 2 bad keys · 3 no Tenable One licence/permission · 4 other error.
