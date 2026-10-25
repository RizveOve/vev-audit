"""Headless Chromium lifecycle, single-page scanning and PDF rendering."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from playwright.async_api import Browser, BrowserContext, Page, Playwright, async_playwright
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeout

from ..config import Settings
from ..security.egress_proxy import EgressProxy
from ..security.url_policy import UrlPolicy
from .axe import run_axe
from .crawler import USER_AGENT

log = logging.getLogger(__name__)

CHROMIUM_ARGS = [
    "--dns-prefetch-disable",
    "--disable-quic",
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-background-networking",
    "--disable-component-update",
    "--no-first-run",
]


@dataclass
class PageResult:
    url: str
    depth: int
    final_url: str | None = None
    title: str | None = None
    status_code: int | None = None
    load_time_ms: int | None = None
    error: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    passes_count: int = 0
    links: list[str] = field(default_factory=list)
    engine: dict[str, Any] = field(default_factory=dict)
    screenshot: str | None = None
    legend: list[dict[str, Any]] | None = None
    retry_after: float | None = None  # seconds, from a 429/503 Retry-After header

    def as_page_row(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "title": self.title,
            "status_code": self.status_code,
            "depth": self.depth,
            "load_time_ms": self.load_time_ms,
            "error": self.error,
            "passes_count": self.passes_count,
            "screenshot": self.screenshot,
            "legend": self.legend,
        }


# Runs on the rendered page after axe (e.g. annotated screenshots); returns (overview_name, legend).
RenderedHook = Callable[[Page, list[dict[str, Any]]], Awaitable[tuple[str | None, list[dict[str, Any]]]]]


class ScanEngine:
    def __init__(self, settings: Settings, policy: UrlPolicy | None = None) -> None:
        self.settings = settings
        self.policy = policy or UrlPolicy(
            allowed_ports=settings.allowed_ports, allow_private_networks=settings.allow_private_networks
        )
        self.proxy = EgressProxy(self.policy)
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        await self.proxy.start()
        self._playwright = await async_playwright().start()
        await self._launch()

    async def _launch(self) -> None:
        assert self._playwright is not None
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            # "<-loopback>" removes Chromium's implicit proxy bypass for localhost.
            proxy={"server": self.proxy.url, "bypass": "<-loopback>"},
            args=CHROMIUM_ARGS,
        )

    async def stop(self) -> None:
        with contextlib.suppress(Exception):
            if self._browser:
                await self._browser.close()
        with contextlib.suppress(Exception):
            if self._playwright:
                await self._playwright.stop()
        await self.proxy.stop()

    async def browser(self) -> Browser:
        async with self._lock:
            if self._browser is None or not self._browser.is_connected():
                log.warning("Chromium is not connected; relaunching")
                await self._launch()
            assert self._browser is not None
            return self._browser

    async def new_scan_context(self) -> BrowserContext:
        browser = await self.browser()
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{browser.version} Safari/537.36 {USER_AGENT}",
            service_workers="block",
            bypass_csp=True,
            accept_downloads=False,
            java_script_enabled=True,
            locale="en-US",
        )
        context.set_default_navigation_timeout(self.settings.navigation_timeout_ms)
        context.set_default_timeout(self.settings.navigation_timeout_ms)
        return context

    async def fetch_text(self, context: BrowserContext, url: str, max_bytes: int = 512_000) -> str | None:
        """Fetch a small text resource (robots.txt) through the egress proxy."""
        try:
            response = await context.request.get(url, timeout=10_000, max_redirects=3)
        except PlaywrightError:
            return None
        if response.status != 200:
            return None
        body = await response.body()
        return body[:max_bytes].decode("utf-8", errors="replace")

    async def scan_page(
        self, context: BrowserContext, url: str, depth: int, on_rendered: RenderedHook | None = None
    ) -> PageResult:
        result = PageResult(url=url, depth=depth)
        page = await asyncio.wait_for(context.new_page(), timeout=30)
        started = time.perf_counter()
        try:
            try:
                response = await page.goto(url, wait_until="domcontentloaded")
            except PlaywrightTimeout:
                result.error = "The page took too long to load."
                return result
            except PlaywrightError as exc:
                result.error = _friendly_navigation_error(str(exc))
                return result

            with contextlib.suppress(PlaywrightTimeout, PlaywrightError):
                await page.wait_for_load_state("load", timeout=15_000)
            with contextlib.suppress(PlaywrightTimeout, PlaywrightError):
                await page.wait_for_load_state("networkidle", timeout=5_000)
            await page.wait_for_timeout(500)  # let client-side rendering settle

            result.load_time_ms = int((time.perf_counter() - started) * 1000)
            result.final_url = page.url
            result.status_code = response.status if response else None
            result.title = (await page.title())[:300] or None

            if response is not None and response.headers.get("x-vev-blocked") == "1":
                result.error = "Blocked by the scanner's network policy (private or disallowed destination)."
                return result
            if result.status_code and result.status_code >= 400:
                result.error = f"The server responded with HTTP {result.status_code}."
                if result.status_code in (429, 503) and response is not None:
                    result.retry_after = _parse_retry_after(response.headers.get("retry-after"))
                return result

            axe = await run_axe(page)
            result.findings = axe["findings"]
            result.passes_count = axe["passes_count"]
            result.engine = axe["engine"]
            result.links = await page.eval_on_selector_all(
                "a[href]", "els => els.slice(0, 2000).map(e => e.href).filter(Boolean)"
            )
            if on_rendered is not None:
                try:
                    result.screenshot, result.legend = await on_rendered(page, result.findings)
                except PlaywrightError as exc:  # screenshots are best-effort; findings still count
                    log.warning("Annotating %s failed: %s", url, exc)
        except PlaywrightError as exc:
            log.exception("Scan of %s failed", url)
            result.error = f"Accessibility analysis failed: {str(exc).splitlines()[0][:200]}"
        finally:
            # Bounded: a wedged tab must never block the scan (this also runs when the page is cancelled).
            with contextlib.suppress(Exception):
                await asyncio.wait_for(page.close(), timeout=10)
        return result

    async def render_pdf(self, html: str, footer_label: str) -> bytes:
        """Render trusted report HTML to PDF with JS disabled and all network access blocked."""
        browser = await self.browser()
        context = await browser.new_context(java_script_enabled=False, offline=True)
        try:
            await context.route("**/*", lambda route: route.abort())
            page = await context.new_page()
            await page.set_content(html, wait_until="load")
            return await page.pdf(
                format="A4",
                print_background=True,
                margin={"top": "18mm", "bottom": "20mm", "left": "14mm", "right": "14mm"},
                display_header_footer=True,
                header_template="<span></span>",
                footer_template=(
                    '<div style="width:100%;font-size:8px;color:#6b7280;padding:0 14mm;'
                    'font-family:Helvetica,Arial,sans-serif;display:flex;justify-content:space-between;">'
                    f"<span>{footer_label}</span>"
                    '<span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>'
                ),
            )
        finally:
            await context.close()


def _parse_retry_after(value: str | None) -> float | None:
    """Retry-After in seconds (HTTP-date form is ignored; callers fall back to their own back-off)."""
    try:
        return max(0.0, float(value)) if value else None
    except ValueError:
        return None


def _friendly_navigation_error(message: str) -> str:
    first = message.splitlines()[0]
    mapping = {
        "ERR_NAME_NOT_RESOLVED": "The domain name could not be resolved.",
        "ERR_CONNECTION_REFUSED": "The server refused the connection.",
        "ERR_CONNECTION_TIMED_OUT": "The connection timed out.",
        "ERR_TUNNEL_CONNECTION_FAILED": "Blocked by the scanner's network policy or the host is unreachable.",
        "ERR_CERT": "The site's TLS certificate is invalid.",
        "ERR_SSL": "A TLS/SSL error occurred while connecting.",
        "ERR_TOO_MANY_REDIRECTS": "The page redirected too many times.",
        "ERR_ABORTED": "Navigation was aborted (the URL may point to a file download).",
        "ERR_EMPTY_RESPONSE": "The server returned an empty response.",
    }
    for code, friendly in mapping.items():
        if code in first:
            return friendly
    return f"Could not load the page: {first[:200]}"
