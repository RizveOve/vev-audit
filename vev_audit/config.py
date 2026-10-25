"""Runtime configuration, read from environment variables (prefix ``VEV_``)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return int(raw)


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if raw is None:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    database_path: Path = field(default_factory=lambda: PROJECT_DIR / "data" / "vev_audit.db")
    screenshot_dir: Path = field(default_factory=lambda: PROJECT_DIR / "data" / "screenshots")
    frontend_dir: Path | None = field(default_factory=lambda: PROJECT_DIR / "frontend")
    cors_origins: list[str] = field(default_factory=list)

    # Scan limits
    max_pages_limit: int = 10
    default_max_pages: int = 5
    max_crawl_depth: int = 2
    max_concurrent_scans: int = 2
    navigation_timeout_ms: int = 30_000
    scan_timeout_s: int = 300
    respect_robots_txt: bool = True
    # "All pages" mode: discover pages via sitemap.xml + links, up to this many
    max_pages_all: int = 200
    max_crawl_depth_all: int = 10
    scan_timeout_all_s: int = 3600
    # Pages scanned in parallel within one scan (browser tabs)
    page_concurrency: int = 3
    # Hard limit for loading + analysing + screenshotting one page; a stuck page is skipped, not waited on
    page_timeout_s: int = 120
    # Politeness: pause between page loads (robots.txt Crawl-delay is honoured up to 10 s)
    page_delay_s: float = 0.5

    # Annotated screenshots
    screenshots_enabled: bool = True
    max_screenshots_per_page: int = 25
    max_shots_per_rule_per_scan: int = 12

    # Network safety
    allowed_ports: frozenset[int] = frozenset({80, 443, 8080, 8443})
    # Only for local development/tests: lets the scanner reach private/loopback hosts.
    allow_private_networks: bool = False

    # Abuse protection: scans per client IP per window (0 disables)
    rate_limit_scans: int = 10
    rate_limit_window_s: int = 3600
    trust_proxy_headers: bool = False

    # Branding
    brand_name: str = "Vevkraft"
    brand_logo_path: Path = field(default_factory=lambda: PACKAGE_DIR / "reports" / "assets" / "vevkraft-logo.svg")
    brand_url: str = "https://vevkraft.com"

    @classmethod
    def from_env(cls) -> Settings:
        defaults = cls()
        frontend_raw = os.getenv("VEV_FRONTEND_DIR")
        if frontend_raw is None:
            frontend_dir = defaults.frontend_dir
        elif frontend_raw.strip() == "":
            frontend_dir = None  # API-only deployment
        else:
            frontend_dir = Path(frontend_raw)
        ports = _env_list("VEV_ALLOWED_PORTS", [str(p) for p in sorted(defaults.allowed_ports)])
        return cls(
            database_path=Path(os.getenv("VEV_DATABASE_PATH", str(defaults.database_path))),
            screenshot_dir=Path(os.getenv("VEV_SCREENSHOT_DIR", str(defaults.screenshot_dir))),
            frontend_dir=frontend_dir,
            cors_origins=_env_list("VEV_CORS_ORIGINS", []),
            max_pages_limit=_env_int("VEV_MAX_PAGES_LIMIT", defaults.max_pages_limit),
            default_max_pages=_env_int("VEV_DEFAULT_MAX_PAGES", defaults.default_max_pages),
            max_crawl_depth=_env_int("VEV_MAX_CRAWL_DEPTH", defaults.max_crawl_depth),
            max_concurrent_scans=_env_int("VEV_MAX_CONCURRENT_SCANS", defaults.max_concurrent_scans),
            navigation_timeout_ms=_env_int("VEV_NAVIGATION_TIMEOUT_MS", defaults.navigation_timeout_ms),
            scan_timeout_s=_env_int("VEV_SCAN_TIMEOUT_S", defaults.scan_timeout_s),
            respect_robots_txt=_env_bool("VEV_RESPECT_ROBOTS_TXT", defaults.respect_robots_txt),
            max_pages_all=_env_int("VEV_MAX_PAGES_ALL", defaults.max_pages_all),
            max_crawl_depth_all=_env_int("VEV_MAX_CRAWL_DEPTH_ALL", defaults.max_crawl_depth_all),
            scan_timeout_all_s=_env_int("VEV_SCAN_TIMEOUT_ALL_S", defaults.scan_timeout_all_s),
            page_concurrency=_env_int("VEV_PAGE_CONCURRENCY", defaults.page_concurrency),
            page_timeout_s=_env_int("VEV_PAGE_TIMEOUT_S", defaults.page_timeout_s),
            page_delay_s=float(os.getenv("VEV_PAGE_DELAY_S", str(defaults.page_delay_s))),
            screenshots_enabled=_env_bool("VEV_SCREENSHOTS_ENABLED", defaults.screenshots_enabled),
            max_screenshots_per_page=_env_int("VEV_MAX_SCREENSHOTS_PER_PAGE", defaults.max_screenshots_per_page),
            max_shots_per_rule_per_scan=_env_int("VEV_MAX_SHOTS_PER_RULE", defaults.max_shots_per_rule_per_scan),
            allowed_ports=frozenset(int(p) for p in ports),
            allow_private_networks=_env_bool("VEV_ALLOW_PRIVATE_NETWORKS", defaults.allow_private_networks),
            rate_limit_scans=_env_int("VEV_RATE_LIMIT_SCANS", defaults.rate_limit_scans),
            rate_limit_window_s=_env_int("VEV_RATE_LIMIT_WINDOW_S", defaults.rate_limit_window_s),
            trust_proxy_headers=_env_bool("VEV_TRUST_PROXY_HEADERS", defaults.trust_proxy_headers),
            brand_name=os.getenv("VEV_BRAND_NAME", defaults.brand_name),
            brand_logo_path=Path(os.getenv("VEV_BRAND_LOGO_PATH", str(defaults.brand_logo_path))),
            brand_url=os.getenv("VEV_BRAND_URL", defaults.brand_url),
        )
