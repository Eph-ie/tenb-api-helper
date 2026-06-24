---
name: "Tenable API Helper"
author: "Joel Barnes"
github_url: "https://github.com/Eph-ie/cyberagent-tenb"
description: "A self correcting API script creator for use with Tenable SaaS Solutions"
license: "MIT"
category: "agent"
tier: "unreviewed"
tags: ["tenable", "vulnerability-management", "tenable-one", "exposure-management", "api", "python"]
framework: "Claude SKILL"
integrations: ["Tenable"]
date_added: 2026-01-01
---

Generate and run read-only Python scripts against the Tenable Vulnerability
Management and Tenable One APIs — describe what data you want in plain language
and get back a working, documented script plus the file it produces. Built for
customers who hold valid API keys but don't have access to the Tenable One UI,
and works equally for VM-only and full Tenable One tenants.

## What it does

Tenable API Helper turns a plain-language request ("export my critical vulns",
"what's my Cyber Exposure Score", "list my scans") into a read-only Python script
that pulls the data and writes it to CSV/JSON or hands it off to another system.

It ships with proven example scripts covering the main patterns — bulk asynchronous
exports of assets and vulnerabilities, scoped synchronous scan retrieval, and the
Tenable One Exposure View / Cyber Exposure Score endpoint — all sharing one client
(`tenable_client.py`) that handles authentication, rate-limit backoff, and the
async export polling loop. When a request isn't covered by an example, the skill
writes a new script to the same pattern rather than forcing a poor fit.

Scope is deliberately **read-only**: it retrieves and reshapes data, never creates,
modifies, or deletes anything in the tenant. A least-privilege API key is all it
needs, and server-side RBAC is the backstop.

## How it works

The skill is **self-correcting and probe-first**. Before pulling anything it runs
a cheap `--dry-run` that calls `/session` to confirm the keys work and report the
account's access level. Because endpoint availability depends on licence, it lets
the API be the source of truth: a `403`/`404` is interpreted as "your licence or
role doesn't include this" and explained in plain language (for example, Exposure
View requires Tenable One), instead of failing with a traceback.

It also encodes Tenable's real-world traps so users don't lose time to them — most
notably the vulnerability export's silent 30-day default window (the scripts send
`since=0` for a full pull), dynamic rate limiting with `retry-after` backoff, the
35-day scan archive cutoff, and the beta status of the Tenable One export
endpoints. Endpoint behaviour is kept current by referencing Tenable's
machine-readable API index (`developer.tenable.com/llms.txt`) rather than
hardcoding assumptions.

The result is a small, testable toolkit (offline mocked tests, one companion doc
per script, a gotchas reference) that a security analyst can run with minimal
editing and a DevOps user can drop into a pipeline. Full code and documentation
live in the GitHub repo.
