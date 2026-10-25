"""Annotated screenshots: outline each failing element and capture it in context.

Two kinds of image are produced per page:

* **element shots** — the element scrolled into view with a severity-coloured
  outline and rule label, cropped with surrounding context;
* **page overview** — a full-page capture (height-capped) with every located
  issue outlined and numbered, plus a legend mapping numbers to rules.

Only plain CSS selectors are annotated; elements inside iframes or shadow DOM
(axe targets containing ``>>>``) are described but not photographed.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from typing import Any

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Page

from .wcag import IMPACT_ORDER

log = logging.getLogger(__name__)

SEVERITY_COLORS = {"critical": "#d03b3b", "serious": "#e8703f", "moderate": "#e0a000", "minor": "#4f74b3"}
OVERVIEW_MAX_HEIGHT = 4000
SHOT_PADDING = 48
JPEG_QUALITY = 72

# Collects element facts for every node (cheap, no screenshots).
_DESCRIBE_JS = """
(selectors) => selectors.map((sel) => {
  let el = null;
  try { el = document.querySelector(sel); } catch (e) { return null; }
  if (!el) return null;
  const r = el.getBoundingClientRect();
  const cs = getComputedStyle(el);
  const text = (el.innerText || el.getAttribute('alt') || el.getAttribute('aria-label') ||
                el.getAttribute('title') || el.getAttribute('placeholder') || el.value || '')
                .toString().trim().replace(/\\s+/g, ' ').slice(0, 140);
  const tag = el.tagName.toLowerCase();
  return {
    tag,
    text,
    // Whole-document elements (html/body) or huge containers: a close-up would show nothing useful.
    page_level: tag === 'html' || tag === 'body' || r.width * r.height > 0.6 * innerWidth * innerHeight,
    x: Math.round(r.left + window.scrollX), y: Math.round(r.top + window.scrollY),
    width: Math.round(r.width), height: Math.round(r.height),
    visible: r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' &&
             parseFloat(cs.opacity || '1') > 0,
  };
})
"""

_MARK_STYLE = (
    "position:{pos};left:{x}px;top:{y}px;width:{w}px;height:{h}px;box-sizing:border-box;"
    "border:3px solid {c};box-shadow:0 0 0 2px #fff,0 0 0 5px {c}55;background:{c}1f;border-radius:3px;"
    "pointer-events:none;z-index:2147483647;"
)
_OUTLINE_STYLE = _MARK_STYLE.replace("background:{c}1f;", "")
_LABEL_STYLE = (
    "position:absolute;left:-3px;top:-24px;background:{c};color:#fff;font:700 12px/20px system-ui,Arial,sans-serif;"
    "padding:0 7px;border-radius:4px;white-space:nowrap;box-shadow:0 0 0 2px #fff;"
)

# Draws one outline around an element in the viewport (position:fixed) after scrolling it to the centre.
_MARK_ONE_JS = """
([sel, color, label, markStyle, labelStyle]) => {
  const el = document.querySelector(sel);
  if (!el) return null;
  el.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' });
  const r = el.getBoundingClientRect();
  const box = document.createElement('div');
  box.id = '__vev_mark';
  box.setAttribute('style', markStyle.replace('{pos}', 'fixed')
    .replace('{x}', r.left - 4).replace('{y}', r.top - 4)
    .replace('{w}', Math.max(r.width, 6) + 8).replace('{h}', Math.max(r.height, 6) + 8).replaceAll('{c}', color));
  const tag = document.createElement('div');
  tag.textContent = label;
  tag.setAttribute('style', labelStyle.replaceAll('{c}', color) + (r.top < 30 ? 'top:auto;bottom:-24px;' : ''));
  box.appendChild(tag);
  document.documentElement.appendChild(box);
  return { x: r.left, y: r.top, w: r.width, h: r.height, vw: window.innerWidth, vh: window.innerHeight };
}
"""

# Draws numbered outlines for many elements in document coordinates (for the full-page overview).
_MARK_ALL_JS = """
([items, markStyle, labelStyle]) => {
  window.scrollTo(0, 0);
  const layer = document.createElement('div');
  layer.id = '__vev_layer';
  layer.setAttribute('style',
    'position:absolute;left:0;top:0;width:0;height:0;z-index:2147483647;pointer-events:none;');
  let drawn = 0;
  for (const it of items) {
    let el = null;
    try { el = document.querySelector(it.selector); } catch (e) { continue; }
    if (!el) continue;
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) continue;
    const box = document.createElement('div');
    box.setAttribute('style', markStyle.replace('{pos}', 'absolute')
      .replace('{x}', r.left + window.scrollX - 3).replace('{y}', r.top + window.scrollY - 3)
      .replace('{w}', r.width + 6).replace('{h}', r.height + 6).replaceAll('{c}', it.color));
    const tag = document.createElement('div');
    tag.textContent = it.label;
    tag.setAttribute('style', labelStyle.replaceAll('{c}', it.color) + 'top:-22px;');
    box.appendChild(tag);
    layer.appendChild(box);
    drawn++;
  }
  document.documentElement.appendChild(layer);
  const d = document.documentElement, b = document.body || d;
  return { drawn, width: Math.max(d.scrollWidth, b.scrollWidth), height: Math.max(d.scrollHeight, b.scrollHeight) };
}
"""

_CLEAR_JS = "() => { for (const id of ['__vev_mark', '__vev_layer']) document.getElementById(id)?.remove(); }"


def _is_simple(target: str) -> bool:
    return bool(target) and ">>>" not in target


def _overview_worthy(info: dict[str, Any] | None) -> bool:
    """Outline only discrete elements; large containers would bury the rest of the page."""
    if not info or not info.get("visible") or info.get("page_level"):
        return False
    return info["width"] * info["height"] <= 0.3 * 1280 * 800


ShotBudget = Callable[[str], bool]
"""Called with a rule id before taking an element shot; returns False when the scan-wide budget is spent."""


async def annotate_page(
    page: Page,
    findings: list[dict[str, Any]],
    save: Callable[[str, bytes], str],
    page_key: str,
    max_element_shots: int = 25,
    shots_per_rule: int = 3,
    budget: ShotBudget | None = None,
) -> tuple[str | None, list[dict[str, Any]]]:
    """Add element facts and screenshots to ``findings`` in place.

    Returns ``(overview_name, legend)``; ``legend`` maps overview numbers to rules.
    """
    violations = sorted(
        (f for f in findings if f["kind"] == "violation"), key=lambda f: IMPACT_ORDER.get(f["impact"], 9)
    )

    # 1. Element facts for every node (text, size, position, visibility).
    all_nodes = [(f, n) for f in findings for n in f["nodes"] if _is_simple(n["target"])]
    try:
        facts = await page.evaluate(_DESCRIBE_JS, [n["target"] for _, n in all_nodes])
    except PlaywrightError as exc:
        log.debug("Could not describe elements on %s: %s", page.url, exc)
        facts = [None] * len(all_nodes)
    for (_, node), info in zip(all_nodes, facts, strict=False):
        if info:
            node["element"] = info

    # 2. Close-up shots, most severe rules first.
    taken = 0
    for finding in violations:
        color = SEVERITY_COLORS.get(finding["impact"], "#d03b3b")
        per_rule = 0
        for idx, node in enumerate(finding["nodes"]):
            if taken >= max_element_shots or per_rule >= shots_per_rule:
                break
            info = node.get("element")
            if not info or not info.get("visible") or info.get("page_level"):
                continue
            if budget is not None and not budget(finding["rule_id"]):
                break
            name = f"{page_key}-{finding['rule_id']}-{idx}.jpg"
            try:
                shot = await _element_shot(page, node["target"], color, finding["rule_id"])
            except PlaywrightError as exc:
                log.debug("Element screenshot failed for %s: %s", node["target"], exc)
                shot = None
            finally:
                with contextlib.suppress(PlaywrightError):
                    await page.evaluate(_CLEAR_JS)
            if shot:
                node["screenshot"] = save(name, shot)
                taken += 1
                per_rule += 1

    # 3. Full-page overview with numbered outlines (only worth taking when something failed).
    legend: list[dict[str, Any]] = []
    if not violations:
        return None, legend
    items: list[dict[str, str]] = []
    for number, finding in enumerate(violations, start=1):
        color = SEVERITY_COLORS.get(finding["impact"], "#d03b3b")
        # Best-practice-only rules (e.g. "region") flag whole content blocks; outlining them buries real defects.
        located = (
            [] if finding.get("best_practice") else [n for n in finding["nodes"] if _overview_worthy(n.get("element"))]
        )
        legend.append(
            {
                "number": number,
                "rule_id": finding["rule_id"],
                "impact": finding["impact"],
                "help": finding["help"],
                "marked": len(located),
                "total": finding.get("node_count", len(finding["nodes"])),
            }
        )
        items += [{"selector": n["target"], "color": color, "label": str(number)} for n in located]
    overview = None
    try:
        dims = await page.evaluate(_MARK_ALL_JS, [items, _OUTLINE_STYLE, _LABEL_STYLE])
        height = max(1, min(int(dims["height"]), OVERVIEW_MAX_HEIGHT))
        width = max(1, min(int(dims["width"]), 1280))
        image = await page.screenshot(
            full_page=True,
            clip={"x": 0, "y": 0, "width": width, "height": height},
            type="jpeg",
            quality=60,
            animations="disabled",
        )
        overview = save(f"{page_key}-overview.jpg", image)
    except PlaywrightError as exc:
        log.debug("Overview screenshot failed for %s: %s", page.url, exc)
    finally:
        with contextlib.suppress(PlaywrightError):
            await page.evaluate(_CLEAR_JS)
    return overview, legend


async def _element_shot(page: Page, selector: str, color: str, label: str) -> bytes | None:
    rect = await page.evaluate(_MARK_ONE_JS, [selector, color, label, _MARK_STYLE, _LABEL_STYLE])
    if not rect:
        return None
    vw, vh = rect["vw"], rect["vh"]
    x0 = max(0, rect["x"] - SHOT_PADDING * 2)
    y0 = max(0, rect["y"] - SHOT_PADDING - 28)
    x1 = min(vw, rect["x"] + rect["w"] + SHOT_PADDING * 2)
    y1 = min(vh, rect["y"] + rect["h"] + SHOT_PADDING + 28)
    # Give tiny elements enough surrounding context to be recognisable.
    if x1 - x0 < 360:
        grow = (360 - (x1 - x0)) / 2
        x0, x1 = max(0, x0 - grow), min(vw, x1 + grow)
    if x1 <= x0 or y1 <= y0:
        return None
    return await page.screenshot(
        clip={"x": x0, "y": y0, "width": x1 - x0, "height": y1 - y0},
        type="jpeg",
        quality=JPEG_QUALITY,
        animations="disabled",
    )
