"""Background scan orchestration: discover pages, scan them in parallel, persist results."""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from dataclasses import dataclass
from typing import Any

from ..config import Settings
from ..database import Database, utcnow
from ..storage import ScreenshotStore
from ..summary import build_summary
from .annotate import annotate_page
from .crawler import CrawlFrontier, origin_of, parse_robots, parse_sitemap, same_site, sitemaps_from_robots
from .engine import PageResult, ScanEngine

log = logging.getLogger(__name__)

MAX_SITEMAP_DOCUMENTS = 10
SITEMAP_MAX_BYTES = 5_000_000
THROTTLE_STATUSES = (429, 503)
MAX_RETRIES_PER_PAGE = 2
MAX_BACKOFF_S = 60.0
MAX_CRAWL_DELAY_S = 10.0
GIVE_UP_AFTER_THROTTLED_PAGES = 3
RAMP_UP_AFTER_OK_PAGES = 10  # after throttling, add a tab back once this many pages succeed in a row


@dataclass(frozen=True)
class ScanPlan:
    max_pages: int
    max_depth: int
    timeout_s: int
    scan_all: bool
    screenshots: bool
    respect_robots: bool


class ScanService:
    def __init__(
        self, db: Database, engine: ScanEngine, settings: Settings, store: ScreenshotStore | None = None
    ) -> None:
        self.db = db
        self.engine = engine
        self.settings = settings
        self.store = store or ScreenshotStore(settings.screenshot_dir)
        self._semaphore = asyncio.Semaphore(settings.max_concurrent_scans)
        self._tasks: set[asyncio.Task] = set()

    def submit(self, scan_id: str) -> asyncio.Task:
        task = asyncio.create_task(self._run(scan_id), name=f"scan-{scan_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def shutdown(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    def plan(self, options: dict[str, Any]) -> ScanPlan:
        s = self.settings
        respect = bool(options.get("respect_robots", s.respect_robots_txt))
        screenshots = bool(options.get("screenshots", True)) and s.screenshots_enabled
        if options.get("scan_all"):
            return ScanPlan(s.max_pages_all, s.max_crawl_depth_all, s.scan_timeout_all_s, True, screenshots, respect)
        max_pages = max(1, min(int(options.get("max_pages") or 1), s.max_pages_limit))
        depth = s.max_crawl_depth if max_pages > 1 else 0
        return ScanPlan(max_pages, depth, s.scan_timeout_s, False, screenshots, respect)

    async def _run(self, scan_id: str) -> None:
        async with self._semaphore:
            scan = self.db.get_scan(scan_id)
            if scan is None:
                return
            plan = self.plan(scan.get("options") or {})
            self.db.update_scan(scan_id, status="running", started_at=utcnow())
            try:
                note = await asyncio.wait_for(self._execute(scan, plan), timeout=plan.timeout_s)
                self._finish(scan_id, note=note)
            except TimeoutError:
                self._finish(scan_id, note="Scan time limit reached; results include the pages scanned so far.")
            except asyncio.CancelledError:
                self._finish(scan_id, failed=True, note="Scan cancelled because the server shut down.")
                raise
            except Exception as exc:  # noqa: BLE001 — record any unexpected failure on the scan
                log.exception("Scan %s crashed", scan_id)
                self._finish(scan_id, failed=True, note=f"Unexpected scanner error: {exc.__class__.__name__}")

    async def _execute(self, scan: dict[str, Any], plan: ScanPlan) -> str | None:
        scan_id = scan["id"]
        context = await self.engine.new_scan_context()
        inflight: dict[asyncio.Task, tuple[str, int]] = {}
        try:
            frontier = CrawlFrontier(start_url=scan["url"], max_pages=plan.max_pages, max_depth=plan.max_depth)
            if plan.max_pages > 1:
                await self._prepare_frontier(context, frontier, plan)
            self.db.update_scan(scan_id, pages_total=frontier.scheduled)

            shots_per_rule: Counter[str] = Counter()
            done = seq = 0
            engine_info: dict[str, Any] = {}
            loop = asyncio.get_running_loop()
            max_limit = max(1, self.settings.page_concurrency)
            limit = max_limit
            ok_streak = 0
            delay = min(max(self.settings.page_delay_s, frontier.crawl_delay() or 0.0), MAX_CRAWL_DELAY_S)
            next_start = 0.0  # loop time before which no new page may start (pacing / back-off)
            attempts: Counter[str] = Counter()
            throttled_in_a_row = 0
            note: str | None = None

            while True:
                while len(inflight) < limit and frontier.has_pending() and loop.time() >= next_start:
                    url, depth = frontier.next()
                    seq += 1
                    hook = self._screenshot_hook(scan_id, seq, shots_per_rule) if plan.screenshots else None
                    work = self.engine.scan_page(context, url, depth, hook)
                    task = asyncio.create_task(asyncio.wait_for(work, timeout=self.settings.page_timeout_s))
                    inflight[task] = (url, depth)
                    self.db.update_scan(scan_id, current_url=url)
                    next_start = loop.time() + delay
                if not inflight and not frontier.has_pending():
                    break
                wait = max(0.0, next_start - loop.time()) if frontier.has_pending() else None
                if not inflight:
                    await asyncio.sleep(wait or 0)
                    continue
                finished, _ = await asyncio.wait(
                    inflight, timeout=wait if wait else None, return_when=asyncio.FIRST_COMPLETED
                )
                for task in finished:
                    url, depth = inflight.pop(task)
                    result = self._result_of(task, url, depth)
                    if result.status_code in THROTTLE_STATUSES:
                        if attempts[url] < MAX_RETRIES_PER_PAGE:
                            # The site is rate-limiting us: slow down to one tab, back off, retry this page.
                            attempts[url] += 1
                            limit, ok_streak = 1, 0
                            backoff = (
                                result.retry_after
                                if result.retry_after is not None
                                else 10.0 * 2 ** (attempts[url] - 1)
                            )
                            next_start = max(next_start, loop.time() + min(backoff, MAX_BACKOFF_S))
                            frontier.retry(url, depth)
                            log.info(
                                "Scan %s: HTTP %s on %s, retrying in %.0fs", scan_id, result.status_code, url, backoff
                            )
                            continue
                        throttled_in_a_row += 1
                        ok_streak = 0
                    else:
                        throttled_in_a_row = 0
                        ok_streak += 1
                        if limit < max_limit and ok_streak >= RAMP_UP_AFTER_OK_PAGES:
                            limit, ok_streak = limit + 1, 0
                    self._absorb(result, frontier)
                    self.db.add_page(scan_id, result.as_page_row(), result.findings)
                    engine_info = engine_info or result.engine
                    done += 1
                self.db.update_scan(scan_id, pages_done=done, pages_total=max(frontier.scheduled, done))
                if throttled_in_a_row >= GIVE_UP_AFTER_THROTTLED_PAGES:
                    note = (
                        "The site kept rate-limiting the scanner (HTTP 429/503) even after slowing down, so the "
                        f"scan stopped early. Results cover the {done} pages checked so far; try again later or "
                        "scan fewer pages."
                    )
                    break

            if engine_info:
                engine = f"{engine_info.get('name', 'axe-core')} {engine_info.get('version', '')}".strip()
                self.db.update_scan(scan_id, engine=engine)
        finally:
            for task in inflight:
                task.cancel()
            await asyncio.gather(*inflight, return_exceptions=True)
            await context.close()
        return note

    async def _prepare_frontier(self, context, frontier: CrawlFrontier, plan: ScanPlan) -> None:
        scheme, host, port = origin_of(frontier.start_url)
        default = (scheme, port) in {("https", 443), ("http", 80)}
        origin = f"{scheme}://{host}{'' if default else f':{port}'}"
        robots_text = await self.engine.fetch_text(context, f"{origin}/robots.txt")
        if robots_text and plan.respect_robots:
            frontier.robots = parse_robots(robots_text, f"{origin}/robots.txt")
        if not plan.scan_all:
            return
        # Full-site mode: seed the queue from sitemaps (robots.txt "Sitemap:" lines, else /sitemap.xml).
        queue = [u for u in sitemaps_from_robots(robots_text or "") if same_site(u, frontier.start_url)]
        queue = queue or [f"{origin}/sitemap.xml"]
        fetched = 0
        while queue and fetched < MAX_SITEMAP_DOCUMENTS and frontier.scheduled < frontier.max_pages:
            url = queue.pop(0)
            if url.endswith(".gz"):
                continue
            fetched += 1
            text = await self.engine.fetch_text(context, url, max_bytes=SITEMAP_MAX_BYTES)
            if not text:
                continue
            pages, children = parse_sitemap(text)
            queue += [c for c in children if same_site(c, frontier.start_url)]
            frontier.add_links(pages, frontier.start_url, depth=0)

    def _screenshot_hook(self, scan_id: str, seq: int, shots_per_rule: Counter[str]):
        cap = self.settings.max_shots_per_rule_per_scan

        def budget(rule_id: str) -> bool:
            if shots_per_rule[rule_id] >= cap:
                return False
            shots_per_rule[rule_id] += 1
            return True

        async def hook(page, findings):
            return await annotate_page(
                page,
                findings,
                save=lambda name, data: self.store.save(scan_id, name, data),
                page_key=f"p{seq}",
                max_element_shots=self.settings.max_screenshots_per_page,
                budget=budget,
            )

        return hook

    def _result_of(self, task: asyncio.Task, url: str, depth: int) -> PageResult:
        exc = task.exception()
        if exc is None:
            return task.result()
        if isinstance(exc, TimeoutError):
            log.warning("Scanning %s exceeded %ss; skipped", url, self.settings.page_timeout_s)
            return PageResult(
                url=url,
                depth=depth,
                error=(
                    f"The page took longer than {self.settings.page_timeout_s} s to load and analyse, "
                    "so it was skipped."
                ),
            )
        log.error("Scanning %s raised %r", url, exc)
        return PageResult(url=url, depth=depth, error=f"Unexpected error while scanning: {exc.__class__.__name__}")

    @staticmethod
    def _absorb(result: PageResult, frontier: CrawlFrontier) -> None:
        if result.final_url:
            frontier.mark_seen(result.final_url)
            if result.depth == 0 and not same_site(result.final_url, frontier.start_url):
                # Start URL redirected (e.g. to www. or https) — crawl the destination site.
                frontier.start_url = result.final_url
        if result.links and result.final_url and same_site(result.final_url, frontier.start_url):
            frontier.add_links(result.links, result.final_url, result.depth)

    def _finish(self, scan_id: str, failed: bool = False, note: str | None = None) -> None:
        pages = self.db.get_pages(scan_id)
        findings = self.db.get_findings(scan_id)
        summary = build_summary(pages, findings)
        if not failed and pages and summary["pages_scanned"] == 0:
            failed = True
            note = note or pages[0].get("error") or "No pages could be scanned."
        self.db.update_scan(
            scan_id,
            status="failed" if failed else "completed",
            finished_at=utcnow(),
            current_url=None,
            error=note,
            summary=summary,
        )
