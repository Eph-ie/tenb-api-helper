# Start here

This guide gets you from zero to a working data pull in about five minutes.

## 1. Generate an API key (use least privilege)

1. Sign in to Tenable.
2. Go to your profile → **My Account → API Keys → Generate**.
3. Ideally generate the key under a **Read-Only** role user. Everything in this
   toolkit is read-only, so a Read-Only key is all you need — and it means the
   key physically cannot change anything in your tenant.
4. Copy the **Access Key** and **Secret Key**. Tenable shows the secret only once.

See Tenable's own guide: https://developer.tenable.com/docs/api-access

> ⚠️ Generating a new key invalidates any existing key for that user. Use a
> dedicated integration user so you don't disrupt someone else.

## 2. Provide the keys (recommended: a .env file — set once, no exporting)

Never put keys in the scripts or in version control.

**Easiest — a `.env` file (works in your terminal *and* the Cowork window):**

```bash
cp .env.example .env
# then edit .env and paste your keys
chmod 600 .env
```

The scripts **auto-load `.env`** from the project folder, so you don't have to
`export` anything every session. The included `.gitignore` keeps `.env` out of git.

`.env` contents (the `export ` prefix is optional — both forms work):

```
TIO_ACCESS_KEY=your-access-key
TIO_SECRET_KEY=your-secret-key
# Only if you are NOT on the default US cloud:
# TIO_BASE_URL=https://cloud.tenable.com
```

**Alternative — real environment variables** (these always win over `.env`):

```bash
export TIO_ACCESS_KEY="your-access-key"
export TIO_SECRET_KEY="your-secret-key"
```

To persist those across terminal sessions on macOS, add the `export` lines to
`~/.zshrc` (or `~/.bash_profile`). But `.env` is simpler and is the only option
the Cowork sandbox can see, so it's the recommended route.

## 3. Install and verify

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v      # 6 offline tests, no keys needed
python scripts/export_assets.py --dry-run     # live check: reads/writes nothing
```

A successful dry run prints your username and access level.

## 4. Pull data

```bash
python scripts/export_assets.py --out assets.csv
python scripts/export_vulnerabilities.py --severity critical high --out vulns.csv
```

## What you can run depends on your licence

| Script | Requires |
| --- | --- |
| `export_assets.py`, `export_vulnerabilities.py` | Tenable VM or Tenable One |
| (future) exposure-score / attack-path scripts | Tenable One |

If a script needs a licence you don't have, you'll get a clear message
(exit code 3), not a stack trace.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `keys MISSING` / exit 2 | Env vars not set in this shell |
| `401 Unauthorized` | Wrong keys, or wrong region — check `TIO_BASE_URL` |
| Exit code 3 | Key valid but lacks licence/permission for that data |
| Hangs then times out | Very large tenant — raise `--chunk-size`, be patient; the export is async |
