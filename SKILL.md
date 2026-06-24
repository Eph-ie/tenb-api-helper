---
name: tenable-one-api-helper
description: >-
  Helps Tenable customers build and run read-only Python scripts against the
  Tenable Vulnerability Management and Tenable One (Exposure Management) APIs to
  retrieve, manipulate, and export their data — without needing access to the
  Tenable One UI ("Hexa"). Use when a user wants to pull assets, vulnerabilities,
  scan results, exposure scores, or attack-path data out of Tenable and into a
  file or another system. Triggers on requests like "export my vulnerabilities",
  "get my exposure score", "dump my assets to CSV", "pull scan results via the
  Tenable API".
version: 0.2.0
license: MIT
# Read-only v1. Write/CRUD is intentionally out of scope for this version.
---

# Tenable One API Helper

## What this skill is

A guided toolkit that lets a Tenable customer describe what data they want in
plain language and get back a **read-only Python script** (plus a plain-English
explanation) that retrieves it from the Tenable API and writes it to a requested
format (CSV / JSON) or prepares it to be fed into another system.

It is aimed at customers who **do not have access to the Tenable One UI** because
of licensing, but who still hold valid API keys. It works for both:

- **Tenable Vulnerability Management (VM)** customers, and
- **full Tenable One** customers (who additionally get Exposure Management endpoints).

## What this skill is NOT (v1 scope boundary)

- **Read-only.** It does not create, update, or delete anything in the tenant.
  Write/CRUD is a deliberately separate future module with its own guardrails.
- Not a replacement for pyTenable or official Tenable support.
- Not a hosted service — it generates scripts the user runs locally with their own keys.

## Audience

Mixed. Default to writing for a security analyst who can run a script and edit a
config file but is not a developer. Include clearly-marked "Engineer notes" for
DevOps users who want terser, automation-oriented guidance.

## Inputs the skill needs from the user

1. **What they want** (intent) — e.g. "all critical vulns", "exposure score trend".
2. **API keys** — `accessKey` and `secretKey`, supplied via environment variables
   (`TIO_ACCESS_KEY`, `TIO_SECRET_KEY`). NEVER hardcoded, never logged.
3. **Region / base URL** — default `https://cloud.tenable.com`.
4. **Desired output format** — CSV (default) or JSON, and a destination path.

## Operating procedure (follow this when triggered)

1. **Confirm credentials are available.** The user must have `TIO_ACCESS_KEY` and
   `TIO_SECRET_KEY` set as environment variables (optionally `TIO_BASE_URL`). If
   not, point them to `docs/00-start-here.md` and stop. Never accept keys pasted
   into chat; never print or log them.
2. **Identify the intent** and map it to a script using the table below
   (backed by `reference/intent-to-endpoint.md`).
3. **Probe first.** Run the chosen script with `--dry-run`. This calls only
   `/session` and confirms the keys work and the access level. A `403`/`404` here
   or on the real run means the license/role doesn't cover the request — explain
   in plain language what's required (see Licensing) rather than treating it as an
   error.
4. **Confirm scope before large pulls.** A full asset/vuln export can be huge.
   For vuln exports, remember the 30-day default trap (see `reference/api-gotchas.md`)
   — the scripts send `since=0` for a full pull unless the user wants a window.
5. **Run the script** with the right flags and output path.
6. **Present the result**: state what was produced (row count, file path) in one
   line and surface the file to the user. Don't dump the data into chat.

## Request → script → command

| If the user wants… | Run | Licence |
| --- | --- | --- |
| All assets to a file | `python scripts/export_assets.py --out assets.csv` | VM or T1 |
| All / filtered vulnerability findings | `python scripts/export_vulnerabilities.py --severity critical high --out vulns.csv` | VM or T1 |
| Exposure to a specific CVE (e.g. Log4Shell) | `python scripts/export_vulnerabilities.py --cve CVE-2021-44228 --out cve.csv` | VM or T1 |
| CISA Known Exploited (KEV) report | `python scripts/export_vulnerabilities.py --kev --out kev.csv` | VM or T1 |
| Remediation tracking (fixed vs open) | `python scripts/export_vulnerabilities.py --state fixed --days 30 --out fixed.csv` | VM or T1 |
| Cyber Exposure Score / Exposure View | `python scripts/get_exposure_score.py --out ces.csv` | **Tenable One** |
| A list of scans, or one scan's results | `python scripts/get_scan_results.py` then `--scan-id <id>` | VM or T1 |
| Just to verify access | any script with `--dry-run` | any |

All scripts accept `--format {csv,json}`, `--out <path>`, `--dry-run`, `--verbose`.

## When no existing script fits: generate one

For a request none of the above covers (e.g. "list software on my assets",
"export attack paths"), write a **new read-only script** rather than forcing a
poor fit:

1. Find the endpoint in `https://developer.tenable.com/llms.txt` (per-endpoint
   OpenAPI `.md`); note its method, params, response shape, licence and whether
   it's sync or an async export.
2. Build on `tenable_client.py` — reuse `get`/`post` (429 backoff + auth come
   free), and follow `export_assets.py` (async) or `get_exposure_score.py` (sync)
   as the pattern.
3. Read-only only: `GET`, or `POST` solely to *request an export*. Never
   create/update/delete.
4. Include the same `--dry-run` probe and exit codes (0/2/3/4).
5. Check it against `reference/api-gotchas.md` before running.

### REQUIRED deliverables for EVERY script you generate

A script on its own is an incomplete answer. Whenever you create or modify a
script, you MUST produce ALL of the following in the same response — never just
the `.py` file:

1. **The script** (`scripts/<name>.py`).
2. **A companion doc** (`docs/<name>.md`) — this is mandatory, not optional. Use
   the exact structure of the existing companion docs (e.g.
   `docs/export_assets.md`): `## What it does`, `## Why it's built this way`,
   `## Prerequisites`, `## How to run it` (with copy-paste commands), `## How to
   read the output`, `## Exit codes`, and any relevant `⚠️ gotcha` callout.
3. **A usage summary in chat** — after creating the files, tell the user in 2–4
   sentences what it does, the exact command(s) to run it, what licence/role it
   needs, and what output to expect. Surface the files; don't paste the code body.
4. **Register it** by adding a row to `reference/intent-to-endpoint.md` so the
   request maps to the new script next time.

If you cannot produce the companion doc (for example you're unsure of the output
shape), say so explicitly rather than silently shipping a bare script.

## Licensing / endpoint availability (critical)

| Capability | Endpoint family | Available to |
| --- | --- | --- |
| Asset & vuln exports | Vulnerability Management (`/assets/export`, `/vulns/export`) | VM and Tenable One |
| Scan results | Vulnerability Management (`/scans`) | VM and Tenable One |
| Scoped queries | Workbenches (capped; use only for small pulls) | VM and Tenable One |
| Exposure View / Cyber Exposure Score | Exposure Management | Tenable One only |
| Asset Inventory export (BETA) | Exposure Management (`inventory-export-*`) | Tenable One only |
| Attack Path Analysis | Exposure Management (`apa-*`) | Tenable One only |

> The skill never assumes the license — the **API response is the source of truth**.
> Probe, then route. A 403 is a licensing/permission answer, not a bug.

> NOTE: The Tenable One inventory/findings export endpoints are currently **beta**
> ("response structure subject to change"). Pin parser versions and warn the user.

## Technical guardrails baked into the shared client

- **Honour `429` + `retry-after`.** Rate limiting is dynamic, not a fixed quota.
- **Single-threaded, sequential requests.** Tenable explicitly says do not multi-thread.
- **Respect the separate concurrency limit.**
- **Async export pattern** handled centrally: request → poll status → download &
  reassemble chunks. This is the officially recommended bulk-retrieval path.
- **Auth from env vars only.** Recommend a least-privilege (Read-Only role) key.

## Repo layout

```
SKILL.md                     <- this file
README.md                    <- public-facing overview
scripts/
  tenable_client.py          <- shared auth, paging, async-export, 429 backoff
  export_assets.py           <- reference implementation (async export)
  export_vulnerabilities.py  <- async export (note 30-day default trap)
  get_scan_results.py        <- scoped synchronous retrieval
  get_exposure_score.py      <- Tenable One only (synchronous, BETA endpoint)
tests/
  test_tenable_client.py     <- offline mocked tests (no keys needed)
docs/
  00-start-here.md           <- generate API keys, least-privilege, env setup
  <script>.md                <- one companion doc per script (what/why/how)
reference/
  intent-to-endpoint.md      <- NL request -> API family -> license tier -> endpoint
  api-gotchas.md             <- the traps (30-day window, key invalidation, rate limits, beta)
```

## Maintenance

Source of truth for endpoint behaviour is Tenable's machine-readable index at
`https://developer.tenable.com/llms.txt` (per-endpoint OpenAPI `.md` files).
Re-sync `reference/intent-to-endpoint.md` against it rather than hardcoding.

## Future: write module (NOT in v1)

If/when writes are added, keep them as a separate opt-in module that:
1. Preflight-checks permissions via `GET /users/{user_id}` and
   `GET /api/v3/access-control/permissions/current-user`.
2. Warns the user before attempting if their role/privilege string is insufficient.
3. Requires explicit per-action confirmation.
4. Still relies on server-side RBAC (a read-only key cannot write) as the backstop.
