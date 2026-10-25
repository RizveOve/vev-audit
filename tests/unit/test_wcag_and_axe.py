from tests.helpers import axe_node, axe_rule
from vev_audit.scanner.axe import MAX_HTML_CHARS, MAX_NODES_PER_RULE, axe_source, normalize_rule
from vev_audit.scanner.wcag import (
    CRITERIA,
    MANUAL_CHECKS,
    criteria_from_tags,
    remediation_for,
    understanding_url,
    wcag_level_from_tags,
)


def test_criteria_from_tags_maps_success_criteria():
    found = criteria_from_tags(["wcag2aa", "wcag143", "wcag1410", "wcag22aa", "wcag258", "cat.color", "wcag143"])
    assert [c["id"] for c in found] == ["1.4.3", "1.4.10", "2.5.8"]
    assert found[0]["name"] == "Contrast (Minimum)"
    assert found[0]["url"].endswith("/Understanding/contrast-minimum.html")


def test_wcag22_criteria_are_present_and_parsing_is_removed():
    for sc in ("2.4.11", "2.5.7", "2.5.8", "3.2.6", "3.3.7", "3.3.8"):
        assert sc in CRITERIA
    assert "4.1.1" not in CRITERIA


def test_level_and_understanding_url():
    assert wcag_level_from_tags(["wcag2a", "wcag111"]) == "A"
    assert wcag_level_from_tags(["best-practice"]) == "Best practice"
    assert understanding_url("4.1.2").endswith("name-role-value.html")


def test_remediation_falls_back_to_axe_help():
    assert "4.5:1" in remediation_for("color-contrast", "x")
    assert remediation_for("some-new-rule", "Use the fallback") == "Use the fallback"


def test_manual_checks_reference_real_criteria():
    for check in MANUAL_CHECKS:
        assert check["criteria_detail"], check["id"]


def test_normalize_rule_flattens_targets_and_extracts_contrast():
    rule = axe_rule(
        "color-contrast",
        "serious",
        ["wcag2aa", "wcag143"],
        [
            axe_node(
                "<p>x</p>",
                [["iframe#a", "p.low"]],
                any=[
                    {
                        "message": "Element has insufficient contrast",
                        "data": {
                            "fgColor": "#777777",
                            "bgColor": "url(evil)",
                            "contrastRatio": 3.1,
                            "expectedContrastRatio": "4.5:1",
                        },
                    }
                ],
            )
        ],
    )
    finding = normalize_rule(rule, "violation")
    node = finding["nodes"][0]
    assert node["target"] == "iframe#a >>> p.low"
    assert node["contrast"]["foreground"] == "#777777"
    assert node["contrast"]["background"] is None  # non-hex values never reach style attributes
    assert node["messages"] == ["Element has insufficient contrast"]
    assert finding["wcag"][0]["id"] == "1.4.3"
    assert not finding["best_practice"]


def test_normalize_rule_caps_nodes_and_html():
    nodes = [axe_node("<div>" + "x" * (MAX_HTML_CHARS + 50) + "</div>", [f"div:nth-child({i})"]) for i in range(80)]
    finding = normalize_rule(axe_rule("region", "moderate", ["best-practice"], nodes), "violation")
    assert len(finding["nodes"]) == MAX_NODES_PER_RULE
    assert finding["node_count"] == 80
    assert finding["nodes"][0]["html"].endswith("…")
    assert finding["best_practice"]


def test_vendored_axe_is_present():
    assert "axe v4" in axe_source()[:200]
