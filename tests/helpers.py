"""Builders for realistic axe-core results used across tests."""

from __future__ import annotations

from vev_audit.scanner.axe import normalize_rule


def axe_rule(rule_id: str, impact: str, tags: list[str], nodes: list[dict], help_text: str | None = None) -> dict:
    return {
        "id": rule_id,
        "impact": impact,
        "tags": tags,
        "description": f"Ensures {rule_id} passes",
        "help": help_text or f"{rule_id} help",
        "helpUrl": f"https://dequeuniversity.com/rules/axe/4.10/{rule_id}",
        "nodes": nodes,
    }


def axe_node(html: str, target, summary: str = "Fix any of the following:\n  Something is wrong", **extra) -> dict:
    return {"html": html, "target": target, "failureSummary": summary, "impact": extra.pop("impact", None), **extra}


def sample_findings() -> list[dict]:
    """Normalised findings for one page: two violations and one needs-review item."""
    return [
        normalize_rule(
            axe_rule(
                "image-alt",
                "critical",
                ["cat.text-alternatives", "wcag2a", "wcag111"],
                [axe_node('<img src="a.png">', ["img"]), axe_node('<img src="b.png">', ["img:nth-child(2)"])],
                "Images must have alternative text",
            ),
            "violation",
        ),
        normalize_rule(
            axe_rule(
                "color-contrast",
                "serious",
                ["wcag2aa", "wcag143"],
                [
                    axe_node(
                        "<p>low</p>",
                        ["p"],
                        any=[
                            {
                                "message": "Low contrast",
                                "data": {
                                    "fgColor": "#aaaaaa",
                                    "bgColor": "#ffffff",
                                    "contrastRatio": 2.32,
                                    "expectedContrastRatio": "4.5:1",
                                },
                            }
                        ],
                    )
                ],
            ),
            "violation",
        ),
        normalize_rule(
            axe_rule("region", "moderate", ["best-practice"], [axe_node("<div>x</div>", ["div"])]),
            "violation",
        ),
        normalize_rule(
            axe_rule(
                "color-contrast",
                "serious",
                ["wcag2aa", "wcag143"],
                [axe_node("<span>over image</span>", ["span"], any=[{"message": "Background image"}])],
            ),
            "needs_review",
        ),
    ]
