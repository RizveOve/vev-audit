"""Aggregate statistics for a scan, shared by the API and every report format."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any

from .scanner.wcag import IMPACT_ORDER, IMPACTS, affected_users, remediation_for

IMPACT_WEIGHTS = {"critical": 10, "serious": 6, "moderate": 3, "minor": 1}

DISCLAIMER = (
    "This report was produced by automated testing with axe-core in a real browser. Automated tools can reliably "
    "detect only a portion of WCAG 2.2 issues (commonly estimated at 30–40% of success criteria). A clean automated "
    'result does not mean a site is accessible or conforms to WCAG 2.2. Items marked "Needs review" and the '
    "manual checklist require evaluation by a person, ideally including people with disabilities and assistive "
    "technology users. This report is not a certification or statement of WCAG conformance."
)


def page_score(findings: list[dict[str, Any]]) -> int:
    """Heuristic 0–100 score from automated violations only. Not a conformance measure."""
    penalty = 0.0
    for f in findings:
        if f["kind"] != "violation":
            continue
        count = max(1, f.get("node_count") or len(f.get("nodes") or []))
        penalty += IMPACT_WEIGHTS.get(f.get("impact") or "minor", 1) * (1 + math.log10(count))
    return max(0, round(100 - penalty))


def group_findings(findings: list[dict[str, Any]], pages: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    """Merge per-page findings of the same rule into one issue with page occurrences."""
    page_urls = {p["id"]: p.get("final_url") or p["url"] for p in pages}
    grouped: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f["kind"] != kind:
            continue
        issue = grouped.get(f["rule_id"])
        if issue is None:
            tags = f.get("tags") or []
            issue = grouped[f["rule_id"]] = {
                "rule_id": f["rule_id"],
                "kind": kind,
                "impact": f.get("impact") or "minor",
                "help": f["help"],
                "description": f["description"],
                "help_url": f.get("help_url"),
                "tags": tags,
                "wcag": f.get("wcag") or [],
                "best_practice": "best-practice" in tags and not f.get("wcag"),
                "remediation": remediation_for(f["rule_id"], f["help"]),
                "affects": affected_users(tags),
                "node_count": 0,
                "page_count": 0,
                "occurrences": [],
            }
        elif IMPACT_ORDER.get(f.get("impact") or "minor", 9) < IMPACT_ORDER.get(issue["impact"], 9):
            issue["impact"] = f["impact"]
        issue["node_count"] += f.get("node_count") or len(f.get("nodes") or [])
        issue["page_count"] += 1
        issue["occurrences"].append(
            {"page_id": f["page_id"], "page_url": page_urls.get(f["page_id"], ""), "nodes": f.get("nodes") or []}
        )
    return sorted(grouped.values(), key=lambda i: (IMPACT_ORDER.get(i["impact"], 9), -i["node_count"], i["rule_id"]))


def build_summary(pages: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    violations = [f for f in findings if f["kind"] == "violation"]
    reviews = [f for f in findings if f["kind"] == "needs_review"]

    issues_by_impact = Counter()
    elements_by_impact = Counter()
    for issue in group_findings(findings, pages, "violation"):
        issues_by_impact[issue["impact"]] += 1
    for f in violations:
        elements_by_impact[f.get("impact") or "minor"] += f.get("node_count") or len(f.get("nodes") or [])

    per_page: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        per_page[f["page_id"]].append(f)
    scanned = [p for p in pages if not p.get("error")]
    scores = [page_score(per_page[p["id"]]) for p in scanned]

    criteria: dict[str, dict[str, Any]] = {}
    for f in violations:
        for sc in f.get("wcag") or []:
            entry = criteria.setdefault(sc["id"], {**sc, "rules": set(), "elements": 0})
            entry["rules"].add(f["rule_id"])
            entry["elements"] += f.get("node_count") or 0
    criteria_list = sorted(
        ({**c, "rules": sorted(c["rules"])} for c in criteria.values()),
        key=lambda c: [int(x) for x in c["id"].split(".")],
    )

    return {
        "pages_scanned": len(scanned),
        "pages_failed": len(pages) - len(scanned),
        "violation_issues": sum(issues_by_impact.values()),
        "violation_elements": sum(elements_by_impact.values()),
        "issues_by_impact": {i: issues_by_impact.get(i, 0) for i in IMPACTS},
        "elements_by_impact": {i: elements_by_impact.get(i, 0) for i in IMPACTS},
        "needs_review_issues": len({f["rule_id"] for f in reviews}),
        "needs_review_elements": sum(f.get("node_count") or 0 for f in reviews),
        "passed_checks": sum(p.get("passes_count") or 0 for p in scanned),
        "automated_score": round(sum(scores) / len(scores)) if scores else None,
        "wcag_criteria_failed": criteria_list,
    }
