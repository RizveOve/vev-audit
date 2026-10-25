"""Assemble the canonical report document for a scan.

The same structure powers the dashboard API response and the JSON, HTML and PDF
exports, so every surface shows identical numbers.
"""

from __future__ import annotations

from typing import Any

from .. import __version__
from ..config import Settings
from ..database import Database, utcnow
from ..scanner.wcag import IMPACT_ORDER, MANUAL_CHECKS
from ..summary import DISCLAIMER, build_summary, group_findings, page_score


def _page_issues(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [
        {
            "rule_id": f["rule_id"],
            "kind": f["kind"],
            "impact": f.get("impact") or "minor",
            "help": f["help"],
            "node_count": f.get("node_count") or len(f.get("nodes") or []),
        }
        for f in findings
    ]
    return sorted(rows, key=lambda r: (r["kind"] != "violation", IMPACT_ORDER.get(r["impact"], 9), -r["node_count"]))


def build_report(db: Database, scan_id: str, settings: Settings) -> dict[str, Any] | None:
    scan = db.get_scan(scan_id)
    if scan is None:
        return None
    pages = db.get_pages(scan_id)
    findings = db.get_findings(scan_id)
    summary = scan.get("summary") if scan["status"] in {"completed", "failed"} and scan.get("summary") else None
    summary = summary or build_summary(pages, findings)

    by_page: dict[int, list[dict[str, Any]]] = {}
    for f in findings:
        by_page.setdefault(f["page_id"], []).append(f)
    page_rows = [
        {
            "id": p["id"],
            "url": p["url"],
            "final_url": p.get("final_url"),
            "title": p.get("title"),
            "status_code": p.get("status_code"),
            "depth": p.get("depth"),
            "load_time_ms": p.get("load_time_ms"),
            "error": p.get("error"),
            "scanned_at": p.get("scanned_at"),
            "violation_rules": p.get("violation_count", 0),
            "review_rules": p.get("review_count", 0),
            "passes": p.get("passes_count", 0),
            "score": None if p.get("error") else page_score(by_page.get(p["id"], [])),
            "screenshot": p.get("screenshot"),
            "legend": p.get("legend") or [],
            "issues": _page_issues(by_page.get(p["id"], [])),
        }
        for p in pages
    ]

    return {
        "report_version": 1,
        "generator": {"name": "Vev Audit", "version": __version__, "brand": settings.brand_name},
        "generated_at": utcnow(),
        "scan": {
            "id": scan["id"],
            "url": scan["url"],
            "status": scan["status"],
            "created_at": scan["created_at"],
            "started_at": scan.get("started_at"),
            "finished_at": scan.get("finished_at"),
            "pages_total": scan.get("pages_total", 0),
            "pages_done": scan.get("pages_done", 0),
            "current_url": scan.get("current_url"),
            "note": scan.get("error"),
            "options": scan.get("options") or {},
            "engine": scan.get("engine"),
            "standard": "WCAG 2.2 Level A & AA (automated subset) + best practices",
        },
        "summary": summary,
        "pages": page_rows,
        "violations": group_findings(findings, pages, "violation"),
        "needs_review": group_findings(findings, pages, "needs_review"),
        "manual_checks": MANUAL_CHECKS,
        "disclaimer": DISCLAIMER,
    }
