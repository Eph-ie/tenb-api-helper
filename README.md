# Tenable One API Helper

> Read-only Python scripts to get your data **out** of Tenable Vulnerability
> Management and Tenable One — even if you don't have access to the Tenable One UI.

**New here?** See [EXAMPLES.md](EXAMPLES.md) for the kinds of reports you can ask
for, and [docs/00-start-here.md](docs/00-start-here.md) to set up your keys.

## Who this is for

Tenable customers who hold valid API keys but want to pull, reshape, and export
their data programmatically. Works for **Tenable VM** customers and **full
Tenable One** customers alike. You do **not** need UI access to the Exposure
Management ("Hexa") views to use the VM scripts.

## What it does (and doesn't)

- ✅ Retrieves assets, vulnerabilities, scan results, exposure scores, and
  attack-path data.
- ✅ Writes to CSV or JSON, or prepares data to feed another system.
- ✅ Tells you up front if your license/permissions don't cover a request.
- ❌ Does **not** create, modify, or delete anything in your tenant. This release
  is strictly read-only.

## Quick start

1. **Generate API keys.** In Tenable, create keys for a **least-privilege user**
   (Read-Only role is enough for everything here). See
   [Generate an API Key](https://developer.tenable.com/docs/api-access).
2. **Set environment variables** (never hardcode keys):
   ```bash
   export TIO_ACCESS_KEY="<your access key>"
   export TIO_SECRET_KEY="<your secret key>"
   ```
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Run a script:**
   ```bash
   python scripts/export_assets.py --format csv --out assets.csv
   ```

## What you can run depends on your license

| Script | Needs |
| --- | --- |
| `export_assets.py`, `export_vulnerabilities.py`, `get_scan_results.py` | Tenable VM (or Tenable One) |
| `get_exposure_score.py`, attack-path scripts | Tenable One |

If you run a Tenable One script without the license, you'll get a clear message
explaining what's required — not a stack trace.

## How it handles the Tenable API safely

- Honours `429` rate-limit responses and the `retry-after` header.
- Single-threaded, sequential requests (per Tenable's guidance).
- Uses the recommended **asynchronous export** flow for bulk data.

## Notes & caveats

- Tenable One inventory/findings export endpoints are currently **beta**; their
  output structure may change.
- This is a community helper, not an official Tenable product, and not a
  substitute for [pyTenable](https://github.com/tenable/pyTenable) or Tenable support.

## Security

- Keys are read from environment variables only and are never logged.
- Use a least-privilege, read-only API key. A read-only key cannot modify your
  tenant even if a script tried to.

## License

MIT — see [LICENSE](LICENSE).

## Engineer notes

<!-- Terser automation guidance, CI usage, scheduling, etc. -->
