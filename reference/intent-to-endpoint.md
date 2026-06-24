# Intent → endpoint → licence map

This is the routing table the skill/scripts follow. Keep it in sync with
Tenable's machine-readable index at https://developer.tenable.com/llms.txt
(every endpoint there has its own OpenAPI `.md` file and a permission callout).

| User intent (natural language) | API family | Method / endpoint | Sync vs async | Licence | Script |
| --- | --- | --- | --- | --- | --- |
| "Who am I / can I connect?" | Platform | `GET /session` | sync | any | (probe, all scripts) |
| "Export all my assets" | Vulnerability Management | `POST /assets/export` → status → chunks | **async** | VM or T1 | `export_assets.py` |
| "Export my vulnerabilities / findings" | Vulnerability Management | `POST /vulns/export` → status → chunks | **async** | VM or T1 | `export_vulnerabilities.py` |
| "Critical vulns by machine / Windows / Linux, sorted by CVSS, with VPR score" | Vulnerability Management | `POST /vulns/export` → status → chunks | **async** | VM or T1 | `critical_vulns_by_machine.py` |
| "Show me a small/scoped slice of vulns" | Vulnerability Management | `GET /workbenches/vulnerabilities` (capped) | sync | VM or T1 | (future) |
| "List my scans" / "results of a specific scan" | Vulnerability Management | `GET /scans`, `GET /scans/{id}` | sync | VM or T1 | `get_scan_results.py` |
| "What's my Cyber Exposure Score?" | Exposure Management | `GET /api/v1/t1/exposure-view/cards` | sync (BETA) | **Tenable One** | `get_exposure_score.py` |
| "Export my asset inventory (T1)" | Exposure Management | `inventory-export-assets` → status → download | **async (BETA)** | **Tenable One** | (future) |
| "Show my attack paths" | Exposure Management | `apa-*` (export top attack paths) | async | **Tenable One** | (future) |

## Routing rules

1. **Probe before pulling.** Hit the cheapest endpoint the request needs. A
   `200` means go; a `403`/`404` means the licence/permission isn't there —
   surface a plain-English message, don't crash.
2. **Scope decides sync vs async.** A small, filtered ask can use a synchronous
   endpoint; "export everything" must use the async export pipeline.
3. **Exports over workbenches for bulk.** Tenable explicitly recommends the
   export endpoints and warns against multi-threading. Workbenches are for small
   scoped reads only and are capped.
4. **Tenable One endpoints are licence-gated and some are beta.** The inventory
   export endpoints' response shape may change — version any parser built on them.

## Why a map instead of hardcoding

Endpoints and permission requirements drift. By keeping this table as the single
routing source and re-syncing it against `llms.txt`, the scripts stay thin and the
maintenance is one file, not many.
