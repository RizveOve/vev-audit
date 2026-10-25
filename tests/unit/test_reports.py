import json

import pytest

from tests.helpers import axe_node, axe_rule
from vev_audit.config import Settings
from vev_audit.database import Database
from vev_audit.reports import build_report, render_html, render_json, report_filename
from vev_audit.scanner.axe import normalize_rule
from vev_audit.summary import build_summary


@pytest.fixture
def seeded(tmp_path):
    settings = Settings(database_path=tmp_path / "r.db")
    db = Database(settings.database_path)
    scan = db.create_scan("https://example.com/", {"max_pages": 1, "respect_robots": True})
    hostile = normalize_rule(
        axe_rule(
            "button-name",
            "critical",
            ["wcag2a", "wcag412"],
            [
                axe_node(
                    '<button onclick="x()"><script>alert("xss")</script></button>',
                    ["button"],
                    summary="</div><script>alert(1)</script>",
                )
            ],
        ),
        "violation",
    )
    db.add_page(scan["id"], {"url": "https://example.com/", "title": "<b>Title</b>", "status_code": 200}, [hostile])
    db.update_scan(
        scan["id"],
        status="completed",
        finished_at="2026-10-23T10:00:00+00:00",
        summary=build_summary(db.get_pages(scan["id"]), db.get_findings(scan["id"])),
    )
    yield db, settings, scan["id"]
    db.close()


def test_build_report_structure(seeded):
    db, settings, scan_id = seeded
    report = build_report(db, scan_id, settings)
    assert report["scan"]["status"] == "completed"
    assert report["summary"]["issues_by_impact"]["critical"] == 1
    assert report["violations"][0]["rule_id"] == "button-name"
    assert report["manual_checks"] and "not a certification" in report["disclaimer"]
    assert build_report(db, "missing", settings) is None


def test_json_report_round_trips(seeded):
    db, settings, scan_id = seeded
    data = json.loads(render_json(build_report(db, scan_id, settings)))
    assert data["violations"][0]["occurrences"][0]["nodes"][0]["target"] == "button"


def test_html_report_escapes_scanned_content_and_is_branded(seeded):
    db, settings, scan_id = seeded
    out = render_html(build_report(db, scan_id, settings), settings)
    assert "<script>alert" not in out
    assert "&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;" in out
    assert "<b>Title</b>" not in out
    assert "Vevkraft" in out and "<svg" in out
    assert "Executive summary" in out and "Remediation recommendations" in out
    assert "not a certification" in out
    assert "Needs manual review" in out


def test_print_variant_limits_nodes(seeded):
    db, settings, scan_id = seeded
    assert "page-break-before" in render_html(build_report(db, scan_id, settings), settings, for_print=True)


def test_report_filename(seeded):
    db, settings, scan_id = seeded
    assert report_filename(build_report(db, scan_id, settings), "pdf") == "vev-audit_example-com_2026-10-23.pdf"
