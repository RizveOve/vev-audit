"""Run axe-core inside a rendered Playwright page and normalise its results."""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Any

from playwright.async_api import Page

from ..config import PACKAGE_DIR
from .wcag import AXE_RUN_TAGS, affected_users, criteria_from_tags, remediation_for

log = logging.getLogger(__name__)

MAX_NODES_PER_RULE = 50
MAX_HTML_CHARS = 1500
_HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{3,8}$")

_RUN_AXE_JS = """
async (tags) => {
  const results = await window.axe.run(document, {
    runOnly: { type: 'tag', values: tags },
    resultTypes: ['violations', 'incomplete'],
    iframes: true,
    elementRef: false,
  });
  return {
    engine: results.testEngine,
    violations: results.violations,
    incomplete: results.incomplete,
    passes: results.passes.length,
    inapplicable: results.inapplicable.length,
  };
}
"""


@lru_cache(maxsize=1)
def axe_source() -> str:
    return (PACKAGE_DIR / "vendor" / "axe.min.js").read_text(encoding="utf-8")


async def inject_axe(page: Page) -> None:
    """Inject axe-core into the main frame and every child frame we can reach."""
    source = axe_source()
    for frame in page.frames:
        try:
            await frame.evaluate(source)
        except Exception as exc:  # detached / cross-origin frame that refused evaluation
            if frame is page.main_frame:
                raise
            log.debug("Could not inject axe into frame %s: %s", frame.url, exc)


async def run_axe(page: Page) -> dict[str, Any]:
    await inject_axe(page)
    raw = await page.evaluate(_RUN_AXE_JS, AXE_RUN_TAGS)
    findings = [normalize_rule(rule, "violation") for rule in raw["violations"]]
    findings += [normalize_rule(rule, "needs_review") for rule in raw["incomplete"]]
    return {
        "engine": raw.get("engine") or {},
        "findings": findings,
        "passes_count": raw.get("passes", 0),
        "inapplicable_count": raw.get("inapplicable", 0),
    }


def _flatten_target(target: Any) -> str:
    """axe targets are lists; nested lists denote iframe / shadow-DOM boundaries."""
    if isinstance(target, list):
        return " >>> ".join(_flatten_target(t) for t in target)
    return str(target)


def _check_messages(node: dict[str, Any]) -> list[str]:
    messages: list[str] = []
    for group in ("any", "all", "none"):
        for check in node.get(group) or []:
            msg = check.get("message")
            if msg and msg not in messages:
                messages.append(msg)
    return messages


def _split_checks(node: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Separate direct failures from unmet alternatives.

    axe reports ``all``/``none`` checks that failed (each one is a problem) and,
    for ``any``, every alternative that would have satisfied the rule — all of
    which were absent. Showing them apart tells developers *what is wrong*
    versus *which one fix is enough*.
    """
    problems, alternatives = [], []
    for group, bucket in (("all", problems), ("none", problems), ("any", alternatives)):
        for check in node.get(group) or []:
            msg = check.get("message")
            if msg and msg not in bucket:
                bucket.append(msg)
    return problems, alternatives


def _contrast_data(node: dict[str, Any]) -> dict[str, Any] | None:
    for check in node.get("any") or []:
        data = check.get("data")
        if isinstance(data, dict) and "contrastRatio" in data:
            fg, bg = data.get("fgColor"), data.get("bgColor")
            return {
                # Colours end up in style attributes of reports; accept hex values only.
                "foreground": fg if isinstance(fg, str) and _HEX_COLOR.match(fg) else None,
                "background": bg if isinstance(bg, str) and _HEX_COLOR.match(bg) else None,
                "ratio": data.get("contrastRatio"),
                "expected": data.get("expectedContrastRatio"),
                "font_size": data.get("fontSize"),
                "font_weight": data.get("fontWeight"),
            }
    return None


def normalize_rule(rule: dict[str, Any], kind: str) -> dict[str, Any]:
    tags = list(rule.get("tags") or [])
    raw_nodes = rule.get("nodes") or []
    nodes = []
    for node in raw_nodes[:MAX_NODES_PER_RULE]:
        html = node.get("html") or ""
        entry = {
            "html": html if len(html) <= MAX_HTML_CHARS else html[:MAX_HTML_CHARS] + "…",
            "target": _flatten_target(node.get("target") or []),
            "failure_summary": node.get("failureSummary") or "",
            "messages": _check_messages(node),
            "impact": node.get("impact"),
        }
        entry["problems"], entry["alternatives"] = _split_checks(node)
        contrast = _contrast_data(node)
        if contrast:
            entry["contrast"] = contrast
        nodes.append(entry)
    return {
        "kind": kind,
        "rule_id": rule.get("id", "unknown"),
        "impact": rule.get("impact") or ("moderate" if kind == "needs_review" else "minor"),
        "help": rule.get("help") or rule.get("id", ""),
        "description": rule.get("description") or "",
        "help_url": rule.get("helpUrl"),
        "tags": tags,
        "wcag": criteria_from_tags(tags),
        "best_practice": "best-practice" in tags and not criteria_from_tags(tags),
        "remediation": remediation_for(rule.get("id", ""), rule.get("help") or ""),
        "affects": affected_users(tags),
        "nodes": nodes,
        "node_count": len(raw_nodes),
    }
