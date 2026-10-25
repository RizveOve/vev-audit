"""End-to-end scans in real headless Chromium against a local fixture site.

Loopback is normally blocked, so these tests use a policy that allows private
addresses but only on the fixture server's port — which also lets us prove the
egress proxy blocks pivots (redirects, iframes) to any other local service.
"""

import pytest

from vev_audit.config import Settings
from vev_audit.database import Database
from vev_audit.reports import build_report, render_pdf
from vev_audit.scanner.engine import ScanEngine
from vev_audit.scanner.service import ScanService
from vev_audit.security.url_policy import UrlPolicy

pytestmark = pytest.mark.browser


@pytest.fixture
async def stack(tmp_path, fixture_site):
    settings = Settings(
        database_path=tmp_path / "e2e.db", screenshot_dir=tmp_path / "shots", navigation_timeout_ms=15_000
    )
    policy = UrlPolicy(allow_private_networks=True, allowed_ports=frozenset({fixture_site.port}))
    engine = ScanEngine(settings, policy)
    await engine.start()
    db = Database(settings.database_path)
    yield settings, db, engine, ScanService(db, engine, settings)
    await engine.stop()
    db.close()


async def run_scan(db, service, url, **options):
    scan = db.create_scan(url, {"max_pages": 1, "respect_robots": True, **options})
    await service.submit(scan["id"])
    return scan["id"]


async def test_scan_detects_real_violations_and_crawls(stack, fixture_site):
    settings, db, engine, service = stack
    scan_id = await run_scan(db, service, f"{fixture_site.base}/index.html", max_pages=5)
    report = build_report(db, scan_id, settings)

    assert report["scan"]["status"] == "completed", report["scan"]["note"]
    assert report["scan"]["engine"].startswith("axe-core 4.")
    urls = [p["url"] for p in report["pages"]]
    assert urls[0] == f"{fixture_site.base}/index.html"
    assert f"{fixture_site.base}/about.html" in urls and f"{fixture_site.base}/contact.html" in urls
    assert not any("/private/" in u for u in urls), "robots.txt disallow must be respected"
    assert not any("example.org" in u or u.endswith(".pdf") for u in urls)
    assert len(urls) == len(set(urls)) <= 5

    rules = {v["rule_id"]: v for v in report["violations"]}
    for expected in ("image-alt", "label", "color-contrast", "html-has-lang", "button-name"):
        assert expected in rules, f"expected axe to flag {expected}; got {sorted(rules)}"
    assert rules["image-alt"]["impact"] == "critical"
    assert any(c["id"] == "1.4.3" for c in rules["color-contrast"]["wcag"])
    contrast_node = rules["color-contrast"]["occurrences"][0]["nodes"][0]
    assert contrast_node["contrast"]["foreground"].startswith("#")
    # The button is injected by client-side JavaScript: proves rendered-DOM scanning.
    assert any("<button" in n["html"] for o in rules["button-name"]["occurrences"] for n in o["nodes"])
    assert report["summary"]["passed_checks"] > 0

    # Annotated screenshots: close-ups of failing elements and a numbered full-page overview.
    image_node = rules["image-alt"]["occurrences"][0]["nodes"][0]
    assert image_node["element"]["tag"] == "img" and image_node["element"]["visible"]
    assert image_node["element"]["width"] == 40
    assert image_node["alternatives"] and "alt" in " ".join(image_node["alternatives"])
    shot = service.store.path(scan_id, image_node["screenshot"])
    assert shot is not None and shot.read_bytes()[:3] == b"\xff\xd8\xff"  # JPEG
    home = report["pages"][0]
    assert service.store.path(scan_id, home["screenshot"]) is not None
    legend_rules = {entry["rule_id"] for entry in home["legend"]}
    assert {"image-alt", "label", "color-contrast"} <= legend_rules
    html_lang = next(n for n in rules["html-has-lang"]["occurrences"][0]["nodes"])
    assert html_lang["element"]["page_level"] and "screenshot" not in html_lang

    pdf = await render_pdf(report, settings, engine, service.store)
    assert pdf.startswith(b"%PDF") and len(pdf) > 50_000


async def test_scan_all_pages_follows_sitemap_and_deep_links(stack, fixture_site):
    settings, db, engine, service = stack
    scan_id = await run_scan(db, service, f"{fixture_site.base}/index.html", scan_all=True)
    report = build_report(db, scan_id, settings)
    urls = {p["url"] for p in report["pages"]}
    assert f"{fixture_site.base}/sitemap-only.html" in urls, "pages listed only in sitemap.xml must be scanned"
    assert f"{fixture_site.base}/deeper.html" in urls, "full-site mode follows links beyond the normal depth"
    assert not any("/private/" in u or "other.example" in u for u in urls)
    assert len(urls) == len(report["pages"])


async def test_screenshots_can_be_disabled(stack, fixture_site):
    settings, db, engine, service = stack
    scan_id = await run_scan(db, service, f"{fixture_site.base}/index.html", screenshots=False)
    report = build_report(db, scan_id, settings)
    assert report["pages"][0]["screenshot"] is None
    assert not any(n.get("screenshot") for v in report["violations"] for o in v["occurrences"] for n in o["nodes"])


async def test_redirect_to_internal_service_is_blocked(stack, fixture_site, trap_server):
    settings, db, engine, service = stack
    scan_id = await run_scan(db, service, f"{fixture_site.base}/redirect-out?to={trap_server.base}/")
    report = build_report(db, scan_id, settings)
    assert report["scan"]["status"] == "failed"
    assert "network policy" in (report["pages"][0]["error"] or "")
    assert trap_server.hits == [], "the internal service must never receive a request"


async def test_iframe_to_internal_service_is_blocked(stack, fixture_site, trap_server):
    settings, db, engine, service = stack
    scan_id = await run_scan(db, service, f"{fixture_site.base}/iframe-out?to={trap_server.base}/")
    report = build_report(db, scan_id, settings)
    assert report["scan"]["status"] == "completed"
    assert trap_server.hits == []
    serialized = str(report)
    assert "internal secret" not in serialized


async def test_default_policy_refuses_loopback(tmp_path, fixture_site):
    settings = Settings(database_path=tmp_path / "strict.db", allowed_ports=frozenset({fixture_site.port}))
    engine = ScanEngine(settings)  # production policy: private networks blocked
    await engine.start()
    db = Database(settings.database_path)
    try:
        before = len(fixture_site.hits)
        scan_id = await run_scan(db, ScanService(db, engine, settings), f"{fixture_site.base}/index.html")
        report = build_report(db, scan_id, settings)
        assert report["scan"]["status"] == "failed"
        assert len(fixture_site.hits) == before
    finally:
        await engine.stop()
        db.close()


async def test_unreachable_page_is_reported(stack, fixture_site):
    settings, db, engine, service = stack
    scan_id = await run_scan(db, service, f"{fixture_site.base}/missing.html")
    report = build_report(db, scan_id, settings)
    assert report["scan"]["status"] == "failed"
    assert "HTTP 404" in report["pages"][0]["error"]
