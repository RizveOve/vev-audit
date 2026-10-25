"""Render a report document to JSON, standalone HTML or PDF."""

from __future__ import annotations

import html
import json
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from ..config import Settings
from ..scanner.wcag import IMPACTS
from ..storage import ScreenshotStore

TEMPLATE_DIR = Path(__file__).parent / "templates"

# Embedding caps keep exported files reasonable for large (all-pages) scans.
EMBED_LIMITS = {"html": {"elements": 200, "overviews": 30}, "pdf": {"elements": 80, "overviews": 12}}

IMPACT_LABELS = {"critical": "Critical", "serious": "Serious", "moderate": "Moderate", "minor": "Minor"}


def _fmt_date(value: str | None, with_time: bool = True) -> str:
    if not value:
        return "—"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    return dt.strftime("%d %b %Y, %H:%M UTC" if with_time else "%d %B %Y")


@lru_cache(maxsize=4)
def _logo_svg(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return ""


@lru_cache(maxsize=1)
def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["date"] = _fmt_date
    env.filters["host"] = lambda url: urlsplit(url).hostname or url
    return env


def report_filename(report: dict[str, Any], ext: str) -> str:
    host = (urlsplit(report["scan"]["url"]).hostname or "site").replace(".", "-")
    day = (report["scan"].get("finished_at") or report["generated_at"])[:10]
    return f"vev-audit_{host}_{day}.{ext}"


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def collect_images(
    report: dict[str, Any], store: ScreenshotStore | None, max_nodes: int, limits: dict[str, int]
) -> dict[str, str]:
    """Map screenshot names to data URIs for the images the report will actually show."""
    if store is None:
        return {}
    scan_id = report["scan"]["id"]
    images: dict[str, str] = {}
    budget = limits["elements"]
    for issue in report["violations"]:
        for occ in issue["occurrences"]:
            for node in occ["nodes"][:max_nodes]:
                name = node.get("screenshot")
                if name and budget > 0 and name not in images:
                    uri = store.data_uri(scan_id, name)
                    if uri:
                        images[name] = uri
                        budget -= 1
    for page in [p for p in report["pages"] if p.get("screenshot")][: limits["overviews"]]:
        uri = store.data_uri(scan_id, page["screenshot"])
        if uri:
            images[page["screenshot"]] = uri
    return images


def render_html(
    report: dict[str, Any], settings: Settings, store: ScreenshotStore | None = None, for_print: bool = False
) -> str:
    template = _env().get_template("report.html.j2")
    max_nodes = 5 if for_print else 25
    images = collect_images(report, store, max_nodes, EMBED_LIMITS["pdf" if for_print else "html"])
    return template.render(
        r=report,
        s=report["summary"],
        brand=settings.brand_name,
        brand_url=settings.brand_url,
        logo=Markup(_logo_svg(str(settings.brand_logo_path))),  # trusted, operator-supplied file
        impacts=IMPACTS,
        impact_labels=IMPACT_LABELS,
        for_print=for_print,
        max_nodes=max_nodes,
        images=images,
        overview_pages=EMBED_LIMITS["pdf" if for_print else "html"]["overviews"],
    )


async def render_pdf(report: dict[str, Any], settings: Settings, engine, store: ScreenshotStore | None = None) -> bytes:
    html_doc = render_html(report, settings, store, for_print=True)
    host = urlsplit(report["scan"]["url"]).hostname or ""
    label = f"{settings.brand_name} · Vev Audit · {host}"
    return await engine.render_pdf(html_doc, footer_label=html.escape(label))
