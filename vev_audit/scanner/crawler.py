"""Link discovery and URL normalisation for limited same-origin crawling."""

from __future__ import annotations

import html
import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

SKIP_EXTENSIONS = frozenset(
    ".pdf .zip .gz .tar .rar .7z .dmg .exe .msi .apk .iso .jpg .jpeg .png .gif .webp .svg .ico .bmp .tif .tiff "
    ".mp3 .mp4 .m4a .mov .avi .webm .ogg .wav .flac .css .js .json .xml .rss .atom .txt .csv .xls .xlsx .doc "
    ".docx .ppt .pptx .woff .woff2 .ttf .eot".split()
)
USER_AGENT = "VevAuditBot/1.0 (+https://vevkraft.com; accessibility scanner)"


def origin_of(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, (parts.hostname or "").lower(), port


def normalize_link(href: str, base: str) -> str | None:
    """Resolve ``href`` against ``base`` and canonicalise it, or return None if it is not crawlable."""
    if not href:
        return None
    href = href.strip()
    if href.startswith(("#", "mailto:", "tel:", "javascript:", "data:", "blob:", "sms:", "ftp:")):
        return None
    try:
        absolute = urljoin(base, href)
        parts = urlsplit(absolute)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not parts.hostname:
        return None
    path = parts.path or "/"
    last = path.rsplit("/", 1)[-1].lower()
    if "." in last and "." + last.rsplit(".", 1)[-1] in SKIP_EXTENSIONS:
        return None
    host = parts.hostname.lower()
    default = (scheme == "https" and port in (None, 443)) or (scheme == "http" and port in (None, 80))
    netloc = host if default else f"{host}:{port}"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def same_site(url: str, start_url: str) -> bool:
    """Same scheme+host+port, treating a leading ``www.`` as equivalent."""
    a, b = origin_of(url), origin_of(start_url)
    strip = lambda h: h[4:] if h.startswith("www.") else h  # noqa: E731
    return a[0] == b[0] and a[2] == b[2] and strip(a[1]) == strip(b[1])


@dataclass
class CrawlFrontier:
    """Breadth-first queue of pages to scan, bounded by page count and depth."""

    start_url: str
    max_pages: int
    max_depth: int
    robots: RobotFileParser | None = None
    _queue: deque[tuple[str, int]] = field(default_factory=deque)
    _seen: set[str] = field(default_factory=set)
    scheduled: int = 0

    def __post_init__(self) -> None:
        self._seen.add(self._key(self.start_url))
        self._queue.append((self.start_url, 0))
        self.scheduled = 1

    @staticmethod
    def _key(url: str) -> str:
        parts = urlsplit(url)
        path = parts.path.rstrip("/") or "/"
        return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))

    def allowed_by_robots(self, url: str) -> bool:
        return self.robots is None or self.robots.can_fetch(USER_AGENT, url)

    def next(self) -> tuple[str, int] | None:
        return self._queue.popleft() if self._queue else None

    def has_pending(self) -> bool:
        return bool(self._queue)

    def retry(self, url: str, depth: int) -> None:
        """Put a page back at the front of the queue (e.g. after the site rate-limited us)."""
        self._queue.appendleft((url, depth))

    def crawl_delay(self) -> float | None:
        if self.robots is None:
            return None
        delay = self.robots.crawl_delay(USER_AGENT)
        return float(delay) if delay is not None else None

    def mark_seen(self, url: str) -> None:
        """Record a URL (e.g. a redirect target) so it is not scanned twice."""
        self._seen.add(self._key(url))

    def add_links(self, links: list[str], base: str, depth: int) -> None:
        if depth >= self.max_depth:
            return
        for href in links:
            if self.scheduled >= self.max_pages:
                return
            url = normalize_link(href, base)
            if url is None or not same_site(url, self.start_url):
                continue
            key = self._key(url)
            if key in self._seen:
                continue
            self._seen.add(key)
            if not self.allowed_by_robots(url):
                continue
            self._queue.append((url, depth + 1))
            self.scheduled += 1


def parse_robots(text: str, url: str) -> RobotFileParser:
    parser = RobotFileParser(url)
    parser.parse(text.splitlines())
    return parser


_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_SITEMAP_INDEX = re.compile(r"<sitemapindex[\s>]", re.IGNORECASE)
_ROBOTS_SITEMAP = re.compile(r"^\s*sitemap\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


def parse_sitemap(text: str) -> tuple[list[str], list[str]]:
    """Return ``(page_urls, child_sitemap_urls)`` from a sitemap or sitemap index.

    A regex is used instead of an XML parser so hostile sitemaps cannot trigger
    entity-expansion attacks; ``<loc>`` is all we need.
    """
    locs = [html.unescape(m) for m in _LOC.findall(text)]
    if _SITEMAP_INDEX.search(text):
        return [], locs
    return locs, []


def sitemaps_from_robots(text: str) -> list[str]:
    return _ROBOTS_SITEMAP.findall(text)
