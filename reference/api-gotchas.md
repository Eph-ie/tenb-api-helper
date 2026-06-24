# Tenable API gotchas

Hard-won traps that cost people time. Each script in this toolkit defends against
the relevant ones, but if you write your own, keep these in mind.

## 1. Vuln export silently limits to the last 30 days

The `/vulns/export` endpoint **only returns findings found or fixed in the last
30 days** unless you send a time-based filter (`since`, `first_found`,
`last_found`, `last_fixed`, or `indexed_at`). With no filter, a tenant whose last
scan was over 30 days ago returns **zero findings** and finishes instantly — even
if the console shows thousands.

- **Fix:** send `since: 0` for a full export, or a real timestamp for an
  incremental one. `export_vulnerabilities.py` defaults to `since=0`.
- The **asset** export has no such window, which is why assets work but vulns
  look "broken."

## 2. Regenerating an API key invalidates the old one immediately

Each user can hold only one key pair at a time. Generating a new one in the UI
kills the existing key the moment you confirm. If a script suddenly returns
`401`, someone may have regenerated the key. Use a dedicated integration user so
you don't disrupt others.

## 3. A 401 vs a partial/over-long paste

`401 Unauthorized` means the keys reached Tenable and were rejected — usually a
mis-copied key (extra/missing characters), or access and secret swapped. Both
keys should be ~64 characters. An *empty* env var gives a different error
("Missing API keys"), not a 401.

## 4. Rate limiting is dynamic, not a fixed quota

The platform calculates an allowed request rate from current load. When exceeded
you get `429` with a `retry-after` header — honour it exactly. Do **not**
multi-thread requests; Tenable explicitly advises against it and you'll trip the
limit faster. There's also a separate per-container **concurrency limit** on
export jobs.

## 5. Use exports, not workbenches, for bulk

Workbench endpoints are convenient for small, scoped reads but are capped and
will hit rate limits if you page through everything. Tenable recommends the
asynchronous export endpoints for any real volume.

## 6. Tenable One export endpoints are beta

The Exposure Management inventory/findings export endpoints are marked **beta** —
"response structure subject to change." Pin/version any parser built on them and
expect occasional schema drift.

## 7. Duplicate export requests are rejected

If an export with identical filters from the same user is already `PROCESSING`
(within the last 3 days), a new identical request returns `409` with the
`active_job_id` of the running job rather than starting a new one.

## 8. Export chunks expire after 3 days

Completed export chunks are downloadable for three days, then they expire and you
must re-submit the export. Don't queue an export and download it a week later.

## 9. Region / base URL

Most tenants use `https://cloud.tenable.com`. If you get connection failures
(not 401s) check whether your tenant lives on a region-specific host and set
`TIO_BASE_URL` accordingly.

## 10. Vuln export defaults to licensed assets only

By default the vuln export excludes unlicensed assets. Set `include_unlicensed:
true` in the request body if you need them.
