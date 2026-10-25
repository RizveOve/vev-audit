"""API + scan orchestration tests using a fake browser engine (fast, offline)."""

import asyncio
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from tests.conftest import fake_resolver
from tests.helpers import sample_findings
from vev_audit.config import Settings
from vev_audit.main import create_app
from vev_audit.scanner.engine import PageResult
from vev_audit.security.url_policy import UrlPolicy


class FakeContext:
    async def close(self):
        pass


class FakeEngine:
    """Stands in for ScanEngine: returns canned axe results and a small link graph."""

    LINKS = {
        "https://example.com/": ["/a", "/b", "/private/x", "https://other.org/", "/a"],
        "https://example.com/a": ["/c"],
    }

    def __init__(self):
        self.policy = UrlPolicy(resolver=fake_resolver({"example.com": ["93.184.215.14"]}))
        self.scanned: list[str] = []

    async def new_scan_context(self):
        return FakeContext()

    async def fetch_text(self, context, url, max_bytes=512_000):
        if url.endswith("/robots.txt"):
            return "User-agent: *\nDisallow: /private/\nSitemap: https://example.com/sitemap.xml\n"
        if url == "https://example.com/sitemap.xml":
            return (
                "<urlset><url><loc>https://example.com/from-sitemap</loc></url>"
                "<url><loc>https://example.com/private/hidden</loc></url>"
                "<url><loc>https://elsewhere.org/x</loc></url></urlset>"
            )
        return None

    async def scan_page(self, context, url, depth, on_rendered=None):
        self.scanned.append(url)
        if url.endswith("/b"):
            return PageResult(url=url, depth=depth, error="The server responded with HTTP 500.", status_code=500)
        return PageResult(
            url=url,
            depth=depth,
            final_url=url,
            title=f"Title {url}",
            status_code=200,
            load_time_ms=120,
            findings=sample_findings(),
            passes_count=25,
            links=self.LINKS.get(url, []),
            engine={"name": "axe-core", "version": "4.14.0"},
        )

    async def render_pdf(self, html, footer_label):
        assert "Vevkraft" in html
        return b"%PDF-1.7 fake"


@pytest.fixture
def settings(tmp_path):
    return Settings(
        database_path=tmp_path / "api.db",
        screenshot_dir=tmp_path / "shots",
        rate_limit_scans=5,
        page_delay_s=0,
        cors_origins=["https://vev.netlify.app"],
    )


@pytest.fixture
def engine():
    return FakeEngine()


@pytest.fixture
def client(settings, engine):
    with TestClient(create_app(settings, engine=engine)) as c:
        yield c


def wait_for(client, scan_id, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get(f"/api/scans/{scan_id}/status").json()
        if status["status"] in {"completed", "failed"}:
            return status
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_health_and_config(client):
    assert client.get("/api/health").json()["status"] == "ok"
    cfg = client.get("/api/config").json()
    assert cfg["max_pages_limit"] == 10 and cfg["brand_name"] == "Vevkraft"


def test_full_scan_flow(client, engine):
    resp = client.post("/api/scans", json={"url": "example.com", "max_pages": 4})
    assert resp.status_code == 202
    scan_id = resp.json()["id"]
    assert resp.json()["url"] == "https://example.com/"

    status = wait_for(client, scan_id)
    assert status["status"] == "completed"
    # Start page + /a + /b (+ /c discovered at depth 1). /private is robots-disallowed; other.org is off-site.
    assert engine.scanned == [
        "https://example.com/",
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/c",
    ]

    report = client.get(f"/api/scans/{scan_id}").json()
    assert report["summary"]["pages_scanned"] == 3
    assert report["summary"]["pages_failed"] == 1
    assert report["scan"]["engine"] == "axe-core 4.14.0"
    assert report["violations"][0]["rule_id"] == "image-alt"
    assert report["violations"][0]["page_count"] == 3
    assert report["needs_review"][0]["kind"] == "needs_review"

    history = client.get("/api/scans").json()
    assert history["total"] == 1 and history["items"][0]["summary"]["violation_issues"] == 3


def test_scan_all_pages_uses_sitemap_and_server_cap(client, engine):
    resp = client.post("/api/scans", json={"url": "https://example.com", "scan_all": True})
    scan_id = resp.json()["id"]
    wait_for(client, scan_id)
    report = client.get(f"/api/scans/{scan_id}").json()
    assert report["scan"]["options"]["scan_all"] is True
    assert report["scan"]["options"]["max_pages"] == 200
    assert "https://example.com/from-sitemap" in engine.scanned
    assert not any("private" in u or "elsewhere" in u for u in engine.scanned)
    assert set(engine.scanned) >= {"https://example.com/a", "https://example.com/c"}
    assert client.get("/api/config").json()["max_pages_all"] == 200


def test_screenshot_endpoint_and_cleanup(client):
    scan_id = client.post("/api/scans", json={"url": "https://example.com", "max_pages": 1}).json()["id"]
    wait_for(client, scan_id)
    store = client.app.state.store
    store.save(scan_id, "p1-image-alt-0.jpg", b"\xff\xd8\xff fake jpeg")
    resp = client.get(f"/api/scans/{scan_id}/screenshots/p1-image-alt-0.jpg")
    assert resp.status_code == 200 and resp.headers["content-type"] == "image/jpeg"
    for bad in ["..%2F..%2Fapi.db", "missing.jpg", "x.png", "%2Fetc%2Fpasswd"]:
        assert client.get(f"/api/scans/{scan_id}/screenshots/{bad}").status_code == 404, bad
    assert client.delete(f"/api/scans/{scan_id}").status_code == 204
    assert store.path(scan_id, "p1-image-alt-0.jpg") is None


def test_report_downloads(client):
    scan_id = client.post("/api/scans", json={"url": "https://example.com", "max_pages": 1}).json()["id"]
    wait_for(client, scan_id)

    j = client.get(f"/api/scans/{scan_id}/report.json")
    assert j.status_code == 200 and j.json()["scan"]["id"] == scan_id
    assert 'attachment; filename="vev-audit_example-com_' in j.headers["content-disposition"]

    h = client.get(f"/api/scans/{scan_id}/report.html")
    assert h.headers["content-type"].startswith("text/html")
    assert "default-src 'none'" in h.headers["content-security-policy"]
    assert "Accessibility Audit Report" in h.text

    p = client.get(f"/api/scans/{scan_id}/report.pdf")
    assert p.headers["content-type"] == "application/pdf" and p.content.startswith(b"%PDF")

    assert client.get(f"/api/scans/{scan_id}/report.exe").status_code == 422


def test_rejects_unsafe_urls(client):
    for url in [
        "http://127.0.0.1",
        "http://localhost:8000",
        "file:///etc/passwd",
        "http://169.254.169.254/",
        "http://nope.invalid-host",
    ]:
        resp = client.post("/api/scans", json={"url": url})
        assert resp.status_code == 422, url
        assert isinstance(resp.json()["detail"], str)
    assert client.post("/api/scans", json={"url": "https://example.com", "max_pages": 0}).status_code == 422


def test_max_pages_is_capped_by_server(client):
    scan_id = client.post("/api/scans", json={"url": "https://example.com", "max_pages": 100}).json()["id"]
    assert client.get(f"/api/scans/{scan_id}").json()["scan"]["options"]["max_pages"] == 10


def test_rate_limit(client):
    for _ in range(5):
        assert client.post("/api/scans", json={"url": "https://example.com", "max_pages": 1}).status_code == 202
    resp = client.post("/api/scans", json={"url": "https://example.com", "max_pages": 1})
    assert resp.status_code == 429 and int(resp.headers["retry-after"]) > 0


def test_delete_and_not_found(client):
    scan_id = client.post("/api/scans", json={"url": "https://example.com", "max_pages": 1}).json()["id"]
    wait_for(client, scan_id)
    assert client.delete(f"/api/scans/{scan_id}").status_code == 204
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    assert client.get(f"/api/scans/{scan_id}/report.pdf").status_code == 404
    assert client.get("/api/scans/" + "x" * 100).status_code == 404


def test_security_and_cors_headers(client):
    resp = client.get("/api/health", headers={"Origin": "https://vev.netlify.app"})
    assert resp.headers["access-control-allow-origin"] == "https://vev.netlify.app"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    other = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in other.headers


def test_frontend_is_served(client):
    resp = client.get("/")
    assert resp.status_code == 200 and "Vev Audit" in resp.text
    assert client.get("/assets/js/app.js").status_code == 200


def test_api_only_mode(settings, engine):
    with TestClient(create_app(replace(settings, frontend_dir=None), engine=engine)) as c:
        assert c.get("/").status_code == 404
        assert c.get("/api/health").status_code == 200


def test_interrupted_scans_are_failed_on_startup(settings, engine):
    from vev_audit.database import Database

    db = Database(settings.database_path)
    stale = db.create_scan("https://example.com/", {})
    db.update_scan(stale["id"], status="running")
    db.close()
    with TestClient(create_app(settings, engine=engine)) as c:
        body = c.get(f"/api/scans/{stale['id']}/status").json()
        assert body["status"] == "failed" and "restart" in body["note"]


class ThrottlingEngine(FakeEngine):
    """Answers HTTP 429 for chosen URLs: a fixed number of times, or forever."""

    def __init__(self, throttle: dict[str, int]):
        super().__init__()
        self.throttle = throttle

    async def scan_page(self, context, url, depth, on_rendered=None):
        remaining = self.throttle.get(url, 0)
        if remaining:
            self.scanned.append(url)
            if remaining > 0:
                self.throttle[url] = remaining - 1
            return PageResult(url=url, depth=depth, status_code=429, retry_after=0, error="HTTP 429")
        return await super().scan_page(context, url, depth, on_rendered)


def test_rate_limited_page_is_retried(settings):
    engine = ThrottlingEngine({"https://example.com/a": 1})
    with TestClient(create_app(settings, engine=engine)) as c:
        scan_id = c.post("/api/scans", json={"url": "https://example.com", "max_pages": 4}).json()["id"]
        assert wait_for(c, scan_id)["status"] == "completed"
        report = c.get(f"/api/scans/{scan_id}").json()
    assert engine.scanned.count("https://example.com/a") == 2
    page_a = next(p for p in report["pages"] if p["url"] == "https://example.com/a")
    assert page_a["status_code"] == 200 and not page_a["error"]
    assert len(report["pages"]) == 4  # the retry is not recorded as an extra page


def test_scan_stops_when_site_keeps_rate_limiting(settings):
    forever = {f"https://example.com/{p}": -1 for p in ("a", "b", "c", "from-sitemap")}
    engine = ThrottlingEngine(forever)
    with TestClient(create_app(settings, engine=engine)) as c:
        scan_id = c.post("/api/scans", json={"url": "https://example.com", "scan_all": True}).json()["id"]
        status = wait_for(c, scan_id)
    assert status["status"] == "completed"
    assert "rate-limiting" in status["note"]


def test_concurrency_recovers_after_throttling(settings):
    from vev_audit.scanner import service as service_module

    links = {"https://example.com/": [f"/p{i}" for i in range(30)]}

    class Tracking(ThrottlingEngine):
        def __init__(self):
            super().__init__({"https://example.com/p0": 1})
            self.LINKS = links
            self.active = self.peak_after_throttle = 0
            self.throttled = False

        async def scan_page(self, context, url, depth, on_rendered=None):
            self.active += 1
            if self.throttled:
                self.peak_after_throttle = max(self.peak_after_throttle, self.active)
            try:
                await asyncio.sleep(0.01)
                result = await super().scan_page(context, url, depth, on_rendered)
                self.throttled = self.throttled or result.status_code == 429
                return result
            finally:
                self.active -= 1

    engine = Tracking()
    original = service_module.RAMP_UP_AFTER_OK_PAGES
    service_module.RAMP_UP_AFTER_OK_PAGES = 3
    try:
        with TestClient(create_app(replace(settings, max_pages_limit=31), engine=engine)) as c:
            scan_id = c.post("/api/scans", json={"url": "https://example.com", "max_pages": 31}).json()["id"]
            assert wait_for(c, scan_id)["status"] == "completed"
    finally:
        service_module.RAMP_UP_AFTER_OK_PAGES = original
    assert engine.throttled
    assert engine.peak_after_throttle > 1, "parallelism should ramp back up after the site stops throttling"


def test_stuck_page_is_skipped_not_waited_on(settings):
    class Hanging(FakeEngine):
        async def scan_page(self, context, url, depth, on_rendered=None):
            if url.endswith("/b"):
                self.scanned.append(url)
                await asyncio.sleep(3600)  # simulate a wedged tab
            return await super().scan_page(context, url, depth, on_rendered)

    engine = Hanging()
    started = time.time()
    with TestClient(create_app(replace(settings, page_timeout_s=1), engine=engine)) as c:
        scan_id = c.post("/api/scans", json={"url": "https://example.com", "max_pages": 4}).json()["id"]
        assert wait_for(c, scan_id)["status"] == "completed"
        report = c.get(f"/api/scans/{scan_id}").json()
    assert time.time() - started < 8
    stuck = next(p for p in report["pages"] if p["url"] == "https://example.com/b")
    assert "skipped" in stuck["error"]
    assert report["summary"]["pages_scanned"] == 3
