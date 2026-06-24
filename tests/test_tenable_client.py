"""
Offline tests for tenable_client. No live keys or network required.

We inject a fake requests.Session that returns scripted responses, so we can
exercise the full async export flow, 429 backoff, and 403 handling
deterministically.

Run:  python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from tenable_client import (  # noqa: E402
    TenableClient,
    AuthError,
    LicenseOrPermissionError,
)


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.headers = headers or {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(f"unexpected raise_for_status {self.status_code}")


class FakeSession:
    """Returns scripted responses keyed by (METHOD, path-suffix)."""

    def __init__(self, script):
        self.headers = {}
        self._script = script  # list of (matcher_fn, FakeResponse)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url))
        for matcher, responses in self._script:
            if matcher(method, url):
                # responses may be a list (consumed in order) or a single resp
                if isinstance(responses, list):
                    return responses.pop(0) if len(responses) > 1 else responses[0]
                return responses
        raise AssertionError(f"No scripted response for {method} {url}")


def _client(session):
    return TenableClient(
        access_key="ak", secret_key="sk", base_url="https://x", session=session
    )


class TestAuth(unittest.TestCase):
    def test_missing_keys_raises(self):
        # Neutralise .env auto-loading so a real project .env doesn't supply keys.
        with mock.patch("tenable_client.load_dotenv", return_value=None):
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(AuthError):
                    TenableClient()


class TestRateLimit(unittest.TestCase):
    def test_429_then_success_honours_retry_after(self):
        script = [
            (
                lambda m, u: u.endswith("/session"),
                [
                    FakeResponse(429, headers={"retry-after": "0"}),
                    FakeResponse(200, {"username": "joel", "permissions": 0}),
                ],
            )
        ]
        client = _client(FakeSession(script))
        with mock.patch("tenable_client.time.sleep") as slept:
            data = client.whoami()
        self.assertEqual(data["username"], "joel")
        slept.assert_called()  # we backed off on the 429


class TestPermissions(unittest.TestCase):
    def test_403_raises_license_error(self):
        script = [(lambda m, u: u.endswith("/session"), FakeResponse(403))]
        client = _client(FakeSession(script))
        with self.assertRaises(LicenseOrPermissionError):
            client.whoami()

    def test_describe_access_maps_role(self):
        script = [(lambda m, u: u.endswith("/session"),
                   FakeResponse(200, {"username": "j", "permissions": 64}))]
        client = _client(FakeSession(script))
        self.assertEqual(client.describe_access(), "Administrator [64]")


class TestAssetExport(unittest.TestCase):
    def test_full_async_flow_reassembles_chunks(self):
        def is_post_export(m, u):
            return m == "POST" and u.endswith("/assets/export")

        def is_status(m, u):
            return m == "GET" and u.endswith("/status")

        def is_chunk1(m, u):
            return u.endswith("/chunks/1")

        def is_chunk2(m, u):
            return u.endswith("/chunks/2")

        script = [
            (is_post_export, FakeResponse(200, {"export_uuid": "abc"})),
            (
                is_status,
                [
                    FakeResponse(200, {"status": "PROCESSING", "chunks_available": [1]}),
                    FakeResponse(200, {"status": "FINISHED", "chunks_available": [1, 2]}),
                ],
            ),
            (is_chunk1, FakeResponse(200, [{"id": "a1"}, {"id": "a2"}])),
            (is_chunk2, FakeResponse(200, [{"id": "a3"}])),
        ]
        client = _client(FakeSession(script))
        with mock.patch("tenable_client.time.sleep"):
            rows = list(client.export_assets(poll_interval=0))
        self.assertEqual([r["id"] for r in rows], ["a1", "a2", "a3"])


class TestVulnExport(unittest.TestCase):
    def test_full_async_flow_reassembles_chunks(self):
        script = [
            (lambda m, u: m == "POST" and u.endswith("/vulns/export"),
             FakeResponse(200, {"export_uuid": "v1"})),
            (lambda m, u: m == "GET" and u.endswith("/status"),
             [
                 FakeResponse(200, {"status": "PROCESSING", "chunks_available": [1]}),
                 FakeResponse(200, {"status": "FINISHED", "chunks_available": [1, 2]}),
             ]),
            (lambda m, u: u.endswith("/chunks/1"),
             FakeResponse(200, [{"plugin": {"id": 1}}, {"plugin": {"id": 2}}])),
            (lambda m, u: u.endswith("/chunks/2"),
             FakeResponse(200, [{"plugin": {"id": 3}}])),
        ]
        client = _client(FakeSession(script))
        with mock.patch("tenable_client.time.sleep"):
            rows = list(client.export_vulnerabilities(poll_interval=0))
        self.assertEqual([r["plugin"]["id"] for r in rows], [1, 2, 3])


class TestDotenv(unittest.TestCase):
    def test_env_loaded_from_file_without_overwriting(self):
        import tempfile, os as _os
        from tenable_client import load_dotenv
        with tempfile.TemporaryDirectory() as d:
            with open(_os.path.join(d, ".env"), "w") as fh:
                fh.write("# comment\nexport TIO_ACCESS_KEY=\"fromfile\"\nTIO_SECRET_KEY=secret\n")
            cwd = _os.getcwd()
            try:
                _os.chdir(d)
                with mock.patch.dict(_os.environ, {"TIO_ACCESS_KEY": "preset"}, clear=True):
                    load_dotenv()
                    # existing var preserved, missing var filled from file
                    self.assertEqual(_os.environ["TIO_ACCESS_KEY"], "preset")
                    self.assertEqual(_os.environ["TIO_SECRET_KEY"], "secret")
            finally:
                _os.chdir(cwd)


class TestVulnFilters(unittest.TestCase):
    def _bf(self, **kw):
        import importlib
        ev = importlib.import_module("export_vulnerabilities")
        return ev.build_filters(**kw)

    def test_defaults_to_full_pull(self):
        self.assertEqual(self._bf().get("since"), 0)

    def test_cve_uppercased(self):
        f = self._bf(cve=["cve-2021-44228"])
        self.assertEqual(f["cve_id"], ["CVE-2021-44228"])

    def test_kev_sets_category(self):
        self.assertEqual(self._bf(kev=True)["cve_category"], ["cisa known exploitable"])

    def test_state_uppercased(self):
        self.assertEqual(self._bf(state=["fixed", "open"])["state"], ["FIXED", "OPEN"])

    def test_days_window_not_zero(self):
        self.assertNotEqual(self._bf(days=7)["since"], 0)


class TestScans(unittest.TestCase):
    def test_list_scans_returns_array(self):
        script = [(lambda m, u: u.endswith("/scans"),
                   FakeResponse(200, {"scans": [{"id": 1}, {"id": 2}], "folders": []}))]
        client = _client(FakeSession(script))
        self.assertEqual([s["id"] for s in client.list_scans()], [1, 2])

    def test_get_scan_details(self):
        script = [(lambda m, u: u.endswith("/scans/32"),
                   FakeResponse(200, {"info": {"name": "X"}, "hosts": [{"critical": 5}]}))]
        client = _client(FakeSession(script))
        d = client.get_scan_details(32)
        self.assertEqual(d["info"]["name"], "X")


class TestExposureView(unittest.TestCase):
    def test_cards_returns_ces(self):
        script = [(lambda m, u: u.endswith("/exposure-view/cards"),
                   FakeResponse(200, {"data": [
                       {"name": "Global", "ces_score": {"score": 481, "grade": "C"}}
                   ], "pagination": {"total_record_count": 1}}))]
        client = _client(FakeSession(script))
        resp = client.exposure_view_cards(is_global=True)
        self.assertEqual(resp["data"][0]["ces_score"]["score"], 481)

    def test_card_403_is_license_error(self):
        script = [(lambda m, u: "/exposure-view/cards" in u, FakeResponse(403))]
        client = _client(FakeSession(script))
        with self.assertRaises(LicenseOrPermissionError):
            client.exposure_view_cards()


if __name__ == "__main__":
    unittest.main(verbosity=2)
