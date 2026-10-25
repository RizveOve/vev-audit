import pytest

from tests.helpers import sample_findings
from vev_audit.database import Database
from vev_audit.security.rate_limit import RateLimiter
from vev_audit.summary import build_summary, group_findings, page_score


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "test.db")
    yield database
    database.close()


def _seed(db: Database) -> str:
    scan = db.create_scan("https://example.com/", {"max_pages": 2})
    db.add_page(
        scan["id"],
        {"url": "https://example.com/", "title": "Home", "status_code": 200, "passes_count": 30},
        sample_findings(),
    )
    db.add_page(
        scan["id"], {"url": "https://example.com/about", "status_code": 200, "passes_count": 20}, sample_findings()[:1]
    )
    db.add_page(scan["id"], {"url": "https://example.com/broken", "error": "HTTP 500"}, [])
    return scan["id"]


def test_scan_lifecycle(db):
    scan = db.create_scan("https://example.com/", {"max_pages": 3})
    assert scan["status"] == "queued" and scan["options"] == {"max_pages": 3}
    db.update_scan(scan["id"], status="running", pages_total=3, summary={"a": 1})
    got = db.get_scan(scan["id"])
    assert got["status"] == "running" and got["summary"] == {"a": 1}
    assert db.count_scans() == 1
    assert db.mark_interrupted_scans() == 1
    assert db.get_scan(scan["id"])["status"] == "failed"
    with pytest.raises(ValueError):
        db.update_scan(scan["id"], url="https://evil")


def test_delete_cascades(db):
    scan_id = _seed(db)
    assert len(db.get_findings(scan_id)) == 5
    assert db.delete_scan(scan_id)
    assert db.get_pages(scan_id) == [] and db.get_findings(scan_id) == []
    assert not db.delete_scan(scan_id)


def test_list_orders_newest_first(db):
    first = db.create_scan("https://a.example/", {})
    second = db.create_scan("https://b.example/", {})
    assert [s["id"] for s in db.list_scans()] == [second["id"], first["id"]]


def test_summary_counts_and_grouping(db):
    scan_id = _seed(db)
    pages, findings = db.get_pages(scan_id), db.get_findings(scan_id)
    s = build_summary(pages, findings)
    assert s["pages_scanned"] == 2 and s["pages_failed"] == 1
    assert s["issues_by_impact"] == {"critical": 1, "serious": 1, "moderate": 1, "minor": 0}
    assert s["elements_by_impact"]["critical"] == 4  # 2 images × 2 pages
    assert s["violation_issues"] == 3
    assert s["needs_review_issues"] == 1
    assert s["passed_checks"] == 50
    assert [c["id"] for c in s["wcag_criteria_failed"]] == ["1.1.1", "1.4.3"]
    assert 0 <= s["automated_score"] < 100

    grouped = group_findings(findings, pages, "violation")
    assert [g["rule_id"] for g in grouped] == ["image-alt", "color-contrast", "region"]
    image_alt = grouped[0]
    assert image_alt["page_count"] == 2 and image_alt["node_count"] == 4
    assert {o["page_url"] for o in image_alt["occurrences"]} == {"https://example.com/", "https://example.com/about"}
    assert grouped[2]["best_practice"]


def test_page_score_bounds():
    assert page_score([]) == 100
    heavy = [{"kind": "violation", "impact": "critical", "node_count": 1000}] * 10
    assert page_score(heavy) == 0
    review_only = [{"kind": "needs_review", "impact": "critical", "node_count": 50}]
    assert page_score(review_only) == 100


def test_rate_limiter_sliding_window():
    now = [0.0]
    limiter = RateLimiter(limit=2, window_s=60, clock=lambda: now[0])
    assert limiter.check("ip")[0] and limiter.check("ip")[0]
    allowed, retry = limiter.check("ip")
    assert not allowed and retry > 0
    assert limiter.check("other-ip")[0]
    now[0] = 61
    assert limiter.check("ip")[0]
    assert RateLimiter(limit=0, window_s=1).check("x") == (True, 0)
