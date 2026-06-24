"""
tenable_client.py
-----------------
Shared, read-only client for the Tenable Vulnerability Management / Tenable One
(Exposure Management) APIs.

Design goals (see docs/ for the "why"):
  * Auth from environment variables only -- never hardcode or log keys.
  * Honour 429 rate limiting via the `retry-after` header.
  * Single-threaded, sequential requests (Tenable explicitly advises against
    multi-threading the API).
  * Provide the asynchronous export pattern (request -> poll status -> download
    chunks -> reassemble) as the recommended bulk-retrieval path.
  * Provide a cheap capability/permission probe so callers can fail fast with a
    human-readable message instead of a stack trace.

This module is deliberately dependency-light: only `requests`.
"""

from __future__ import annotations

import os
import time
import logging
from typing import Any, Dict, Iterator, List, Optional

import requests

LOG = logging.getLogger("tenable_client")

DEFAULT_BASE_URL = "https://cloud.tenable.com"

# Tenable user role values (from developer.tenable.com/docs/roles).
# Used only to produce friendly pre-flight messages; the server is the real
# authority on what a key may do.
ROLE_NAMES = {
    0: "Read-Only",
    16: "Basic",
    24: "Scan Operator",
    32: "Standard",
    40: "Scan Manager",
    64: "Administrator",
}


class TenableError(RuntimeError):
    """Base error for client problems."""


class AuthError(TenableError):
    """Missing or rejected credentials."""


class LicenseOrPermissionError(TenableError):
    """The key is valid but lacks the license/permission for this request (403/404)."""


class TenableClient:
    def __init__(
        self,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        base_url: Optional[str] = None,
        *,
        max_retries: int = 5,
        timeout: int = 60,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.access_key = access_key or os.environ.get("TIO_ACCESS_KEY")
        self.secret_key = secret_key or os.environ.get("TIO_SECRET_KEY")
        if not self.access_key or not self.secret_key:
            raise AuthError(
                "Missing API keys. Set TIO_ACCESS_KEY and TIO_SECRET_KEY "
                "environment variables (do not hardcode them)."
            )
        self.base_url = (base_url or os.environ.get("TIO_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.max_retries = max_retries
        self.timeout = timeout
        self.session = session or requests.Session()
        # X-ApiKeys auth header. Secret is never logged.
        self.session.headers.update(
            {
                "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}",
                "Accept": "application/json",
                # A descriptive User-Agent is recommended by Tenable.
                "User-Agent": "tenable-one-api-helper/0.1 (+read-only)",
            }
        )

    # ----------------------------------------------------------------- core
    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Single request with 429-aware retry. Sequential by design."""
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        kwargs.setdefault("timeout", self.timeout)
        attempt = 0
        while True:
            attempt += 1
            resp = self.session.request(method, url, **kwargs)

            if resp.status_code == 429:
                if attempt > self.max_retries:
                    raise TenableError(f"Rate limited; exceeded {self.max_retries} retries.")
                wait = int(resp.headers.get("retry-after", "30"))
                LOG.warning("429 received; honouring retry-after=%ss (attempt %s)", wait, attempt)
                time.sleep(wait)
                continue

            if resp.status_code in (401,):
                raise AuthError("401 Unauthorized -- check your API keys / region (TIO_BASE_URL).")
            if resp.status_code in (403, 404):
                raise LicenseOrPermissionError(
                    f"{resp.status_code} for {method} {path}. Your key's license or "
                    "permissions likely don't include this capability. "
                    "If this is a Tenable One endpoint, it requires a Tenable One license."
                )
            if resp.status_code >= 500:
                if attempt > self.max_retries:
                    resp.raise_for_status()
                back = min(2 ** attempt, 60)
                LOG.warning("%s server error; backing off %ss", resp.status_code, back)
                time.sleep(back)
                continue

            resp.raise_for_status()
            return resp

    def get(self, path: str, **kwargs: Any) -> Any:
        return self._request("GET", path, **kwargs).json()

    def post(self, path: str, **kwargs: Any) -> Any:
        return self._request("POST", path, **kwargs).json()

    # ------------------------------------------------------------ probes
    def whoami(self) -> Dict[str, Any]:
        """Return the current session user (cheap connectivity + identity check)."""
        return self.get("/session")

    def current_role(self) -> Optional[int]:
        """Best-effort role lookup for friendly pre-flight messaging."""
        try:
            data = self.whoami()
        except TenableError:
            return None
        return data.get("permissions")  # /session returns the role value here.

    def describe_access(self) -> str:
        role = self.current_role()
        if role is None:
            return "unknown role"
        return f"{ROLE_NAMES.get(role, 'Custom/Unknown')} [{role}]"

    # ------------------------------------------------------- async export
    def export_assets(
        self,
        *,
        chunk_size: int = 1000,
        filters: Optional[Dict[str, Any]] = None,
        poll_interval: int = 5,
        max_poll_seconds: int = 3600,
    ) -> Iterator[Dict[str, Any]]:
        """
        Yield asset records using the recommended asynchronous export flow:
            POST /assets/export            -> export_uuid
            GET  /assets/export/{uuid}/status      (poll until FINISHED)
            GET  /assets/export/{uuid}/chunks/{id} (download + reassemble)

        Yields one asset dict at a time so large tenants stream rather than
        loading everything into memory.
        """
        body: Dict[str, Any] = {"chunk_size": chunk_size}
        if filters:
            body["filters"] = filters

        start = self.post("/assets/export", json=body)
        uuid = start["export_uuid"]
        LOG.info("Asset export requested: %s", uuid)

        downloaded: set[int] = set()
        waited = 0
        while True:
            status = self.get(f"/assets/export/{uuid}/status")
            state = status.get("status")
            available = [c for c in status.get("chunks_available", []) if c not in downloaded]

            for chunk_id in available:
                rows = self.get(f"/assets/export/{uuid}/chunks/{chunk_id}")
                downloaded.add(chunk_id)
                for row in rows:
                    yield row

            if state == "FINISHED" and not [
                c for c in status.get("chunks_available", []) if c not in downloaded
            ]:
                LOG.info("Asset export %s finished (%s chunks).", uuid, len(downloaded))
                return
            if state in ("CANCELLED", "ERROR"):
                raise TenableError(f"Export {uuid} ended with status {state}.")

            time.sleep(poll_interval)
            waited += poll_interval
            if waited > max_poll_seconds:
                raise TenableError(f"Export {uuid} timed out after {max_poll_seconds}s.")

    def export_vulnerabilities(
        self,
        *,
        num_assets: int = 500,
        filters: Optional[Dict[str, Any]] = None,
        poll_interval: int = 5,
        max_poll_seconds: int = 3600,
    ) -> Iterator[Dict[str, Any]]:
        """
        Yield vulnerability finding records via the asynchronous export flow:
            POST /vulns/export             -> export_uuid
            GET  /vulns/export/{uuid}/status       (poll until FINISHED)
            GET  /vulns/export/{uuid}/chunks/{id}  (download + reassemble)

        `num_assets` controls how many assets' findings go in each chunk (the
        vuln export sizes chunks by assets, not by record count).
        Common filter: {"severity": ["critical", "high"]}.
        """
        body: Dict[str, Any] = {"num_assets": num_assets}
        if filters:
            body["filters"] = filters

        start = self.post("/vulns/export", json=body)
        uuid = start["export_uuid"]
        LOG.info("Vulnerability export requested: %s", uuid)

        downloaded: set[int] = set()
        waited = 0
        while True:
            status = self.get(f"/vulns/export/{uuid}/status")
            state = status.get("status")

            for chunk_id in [c for c in status.get("chunks_available", []) if c not in downloaded]:
                rows = self.get(f"/vulns/export/{uuid}/chunks/{chunk_id}")
                downloaded.add(chunk_id)
                for row in rows:
                    yield row

            if state == "FINISHED" and not [
                c for c in status.get("chunks_available", []) if c not in downloaded
            ]:
                LOG.info("Vulnerability export %s finished (%s chunks).", uuid, len(downloaded))
                return
            if state in ("CANCELLED", "ERROR"):
                raise TenableError(f"Export {uuid} ended with status {state}.")

            time.sleep(poll_interval)
            waited += poll_interval
            if waited > max_poll_seconds:
                raise TenableError(f"Export {uuid} timed out after {max_poll_seconds}s.")

    # --------------------------------------------------- scans (synchronous)
    def list_scans(self, **params: Any) -> List[Dict[str, Any]]:
        """Return the list of scans the key can view (GET /scans)."""
        data = self.get("/scans", params={k: v for k, v in params.items() if v is not None})
        return data.get("scans", []) or []

    def get_scan_details(self, scan_id: Any, history_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Return results for a single scan (GET /scans/{scan_id}). Synchronous.

        NOTE: results older than 35 days are 'archived' -- the response then omits
        the hosts/vulnerabilities arrays and `info.is_archived` is true. For full
        archived data you must use the scan export endpoint instead.
        """
        params = {"history_id": history_id} if history_id is not None else None
        return self.get(f"/scans/{scan_id}", params=params)

    # -------------------------------------- Tenable One: Exposure View (BETA)
    def exposure_view_cards(
        self,
        *,
        is_global: Optional[bool] = None,
        text_query: Optional[str] = None,
        limit: int = 25,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        Return Exposure View cards incl. Cyber Exposure Score (CES) and trend.
        GET /api/v1/t1/exposure-view/cards  (Tenable One only; BETA endpoint).

        Each card includes ces_score {score 0-1000, grade A-F}, sla_percentage,
        and ces_trend [{date, ces_score}]. limit max is 25.
        """
        params: Dict[str, Any] = {"limit": min(limit, 25), "offset": offset}
        if is_global is not None:
            params["is_global_card"] = str(is_global).lower()
        if text_query:
            params["text_query"] = text_query
        return self.get("/api/v1/t1/exposure-view/cards", params=params)

    def get_exposure_card(self, card_id: str) -> Dict[str, Any]:
        """Return details for one Exposure View card (BETA, Tenable One only)."""
        return self.get(f"/api/v1/t1/exposure-view/cards/{card_id}")
