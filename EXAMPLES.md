# What you can ask for — example reports

This skill is a **read-only data-extraction tool** for vulnerability managers and
analysts: it pulls data out of Tenable so you can report on it and analyse it. It
never changes anything in your tenant.

Below are common things to ask, grouped by how you'd use them. Just describe what
you want in plain language — the skill picks the right script (or writes a new one
if your request is more specific). Every pull ends with a file (CSV or JSON) you
can open in Excel/BI or feed to another system.

> First time? See `docs/00-start-here.md` to generate an API key and create your
> `.env`. A read-only key is all you need.

## Quick health check

- "Check my Tenable API access." — confirms your keys work and shows your access level.

## Weekly / operational reporting

- "Export all my open critical and high vulnerabilities."
- "What new vulnerabilities showed up in the last 7 days?"
- "Show me everything still open at critical severity."
- "List my scans and when they last ran." — spot scans that have gone stale.

## Reactive — 'are we exposed to X?'

- "Are we exposed to Log4Shell? Pull every finding for CVE-2021-44228."
- "Report on all vulnerabilities in the CISA Known Exploited (KEV) catalogue."
- "Do we have anything matching CVE-2024-3094?"

## Remediation & SLA tracking

- "What's been fixed in the last 30 days?"
- "Show open vs fixed criticals so I can report remediation progress."

## Asset & coverage reporting

- "Give me a CSV of every asset we have."
- "List assets we haven't seen in over 90 days." — coverage gaps / stale hosts.

## Executive / board reporting (Tenable One)

- "What's our Cyber Exposure Score and how is it trending?"
- "Show the exposure score by category (VM, identity, cloud, web apps)."

## Prioritisation & deep-dives

- "Which 20 vulnerabilities affect the most assets?"
- "Break down our critical vulnerabilities by business unit." (uses your asset tags)
- "Give me the results of scan <name/id>."

---

## Good to know

- **Output, not action.** Everything here extracts data. Asking it to create,
  change, or delete (scans, tags, assets) will be declined — that's outside this
  tool's read-only scope.
- **Licensing.** Asset/vulnerability/scan reports work for Tenable Vulnerability
  Management and Tenable One. Exposure Score / Exposure View reports need a
  Tenable One licence — if you don't have it, you'll get a clear message rather
  than an error.
- **Big pulls take a moment.** A full vulnerability export streams in the
  background and reassembles automatically; large environments just take longer.
- **Don't see your exact report?** Ask anyway — if it's not a built-in, the skill
  will write a small read-only script for it and explain how to use it.
