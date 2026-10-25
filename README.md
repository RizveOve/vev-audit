# Vev Audit

**Automated WCAG 2.2 website accessibility auditing by Vevkraft.**

Vev Audit loads web pages in a real headless browser (Playwright + Chromium), runs the
[axe-core](https://github.com/dequelabs/axe-core) rule engine against WCAG 2.0/2.1/2.2 Level A and AA plus best
practices, and presents the results in a dashboard. Each issue shows its severity, the affected HTML elements, an
explanation, the WCAG success criteria it relates to, and a suggested fix. Every scan can be downloaded as a branded
**PDF**, a standalone **HTML** report, or **JSON**.

> **Important:** Vev Audit never claims WCAG compliance. Automated testing can detect only part of WCAG 2.2.
> Results are split into three groups:
> - **Automated issues:** confirmed rule failures.
> - **Needs review:** the engine found something it could not decide on.
> - **Manual checklist:** criteria that only a person can evaluate.
>
> Conformance always requires manual expert and user testing.

---

## Features

- **Rendered-page scanning:** pages are tested after JavaScript runs, as users see them.
- **Multi-page and full-site scanning:**
  - Choose 1–10 pages (follows same-site links breadth-first, depth 2), or **All pages**, which also reads `sitemap.xml` (including sitemap indexes and robots.txt `Sitemap:` lines) and follows links up to depth 10, capped at 200 pages by default.
  - Several pages are scanned in parallel browser tabs.
  - It crawls politely: a delay between page loads, robots.txt `Crawl-delay` honoured, and on HTTP 429/503 it backs off (respecting `Retry-After`), drops to one tab and retries. If a site keeps refusing, the scan stops early with an explanation.
  - It respects robots.txt and skips files, off-site links, `mailto:` links and similar.
- **Annotated screenshots:**
  - A close-up of every failing element (up to 3 per rule per page), outlined in its severity colour and labelled with the rule.
  - A full-page overview of each page with every located problem outlined and numbered, plus a legend.
  - Whole-page issues (such as a missing `lang`) and best-practice container issues are listed as "page-level" rather than outlined.
- **Exact problem per element:**
  - the specific failed checks, with the main problem first and the other accepted fixes listed separately
  - the element's tag, text, size and position on the page
  - measured contrast with the required ratio
  - who is affected (for example screen-reader users, or people with low vision)
- **Findings:**
  - severity: critical, serious, moderate or minor
  - affected elements, with HTML snippet and CSS selector
  - per-element failure reasons
  - colour-contrast measurements
  - WCAG 2.2 criteria with links to the W3C Understanding pages
  - curated fixes for about 80 common rules
- **Clear separation of automated and manual results:** automated issues, needs-review items and a manual WCAG 2.2 checklist each have their own section, both in the dashboard and in the reports.
- **Scan history** stored in SQLite, with delete.
- **Reports:**
  - **PDF:** branded with the Vevkraft logo. Contains a cover page, scan date, audited URLs, an executive summary, severity breakdown, WCAG criteria table, detailed findings with element screenshots, page-by-page results with annotated overviews, needs-review items, the manual checklist, a phased remediation plan and the methodology/limitations.
  - **HTML:** standalone and self-contained, with screenshots embedded and no external requests.
  - To keep files a sensible size on big scans, the HTML embeds up to 200 element shots and 30 page overviews, and the PDF up to 80 and 12. The dashboard always shows every screenshot.
  - **JSON:** the complete structured data.
- **Security:** SSRF-hardened URL validation plus a validating egress proxy for every browser connection, rate limiting, CSP and other security headers, and output escaping everywhere (see [Security](#security)).
- **Accessible dashboard:** it passes its own axe audit. It has landmarks, a skip link, keyboard-operable tabs, live progress announcements, visible focus, dark mode, reduced-motion support and support for forced-colours mode.

## Tech stack

| Layer | Technology |
|---|---|
| API | FastAPI, Uvicorn |
| Scanning | Playwright (Chromium), axe-core 4.14 (vendored in `vev_audit/vendor/`) |
| Storage | SQLite (WAL mode) |
| Reports | Jinja2 templates; PDF printed by the same headless Chromium |
| Frontend | Plain HTML, CSS and JavaScript with no build step, deployable on any static host |
| Tooling | pytest, ruff, Docker, GitHub Actions |

---

## Quick start (local)

**Requirements:** Python 3.11+ and about 500 MB of disk space for Chromium.

```bash
git clone <your-repo-url> vev_audit && cd vev_audit

python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate

pip install -r requirements-dev.txt  # or requirements.txt for runtime only
python -m playwright install chromium
# On Linux, also install system libraries:  python -m playwright install-deps chromium

uvicorn vev_audit.main:app --reload --port 8000
```

Open **http://127.0.0.1:8000**, enter a public URL (for example `https://www.w3.org/WAI/demos/bad/before/home.html`,
W3C's deliberately inaccessible demo site) and click **Scan site**.

- Interactive API docs are at http://127.0.0.1:8000/api/docs
- Scan history is stored in `./data/vev_audit.db`

### Configuration

All settings are optional environment variables with the `VEV_` prefix. See [`.env.example`](.env.example) for the
full list. To use a file:

```bash
cp .env.example .env
uvicorn vev_audit.main:app --env-file .env
```

| Variable | Default | Purpose |
|---|---|---|
| `VEV_DATABASE_PATH` | `./data/vev_audit.db` | SQLite file location |
| `VEV_MAX_PAGES_LIMIT` | `10` | Maximum pages a single scan may crawl |
| `VEV_MAX_CONCURRENT_SCANS` | `2` | Scans that run in parallel; the rest are queued |
| `VEV_MAX_PAGES_ALL` | `200` | Page cap for **All pages** scans |
| `VEV_MAX_CRAWL_DEPTH_ALL` | `10` | Link depth for **All pages** scans |
| `VEV_SCAN_TIMEOUT_ALL_S` | `3600` | Time limit for **All pages** scans |
| `VEV_PAGE_CONCURRENCY` | `3` | Pages scanned in parallel within one scan |
| `VEV_PAGE_TIMEOUT_S` | `120` | Hard limit per page (load + analysis + screenshots); a stuck page is skipped, not waited on |
| `VEV_PAGE_DELAY_S` | `0.5` | Minimum pause between page loads; robots.txt `Crawl-delay` is honoured up to 10 s |
| `VEV_SCREENSHOTS_ENABLED` | `true` | Turn annotated screenshots off server-wide |
| `VEV_SCREENSHOT_DIR` | `./data/screenshots` | Where screenshots are stored |
| `VEV_MAX_SCREENSHOTS_PER_PAGE` / `VEV_MAX_SHOTS_PER_RULE` | `25` / `12` | Close-up limits per page, and per rule across a scan |
| `VEV_SCAN_TIMEOUT_S` | `300` | Hard time limit per scan; partial results are kept |
| `VEV_ALLOWED_PORTS` | `80,443,8080,8443` | Ports the scanner may connect to |
| `VEV_RATE_LIMIT_SCANS` / `_WINDOW_S` | `10` / `3600` | New scans allowed per client IP per window |
| `VEV_CORS_ORIGINS` | *(empty)* | Cross-origin frontends allowed to call the API |
| `VEV_TRUST_PROXY_HEADERS` | `false` | Use `X-Forwarded-For` for client IPs; enable only behind a trusted proxy |
| `VEV_FRONTEND_DIR` | `./frontend` | Set to an empty value for an API-only deployment |
| `VEV_BRAND_NAME`, `VEV_BRAND_URL`, `VEV_BRAND_LOGO_PATH` | Vevkraft | Report branding |
| `VEV_ALLOW_PRIVATE_NETWORKS` | `false` | **Local development only.** Lets the scanner reach localhost and private networks |

### Using your real logo

`vev_audit/reports/assets/vevkraft-logo.svg` is a placeholder wordmark. To use your real logo, either:

- replace that file (and `frontend/assets/img/vevkraft-logo.svg` / `favicon.svg`) with the official Vevkraft SVG, or
- point `VEV_BRAND_LOGO_PATH` at your own SVG.

The logo is embedded inline in the PDF and HTML reports, so no network access is needed.

---

## Running tests

```bash
pytest                       # everything (≈110 tests, ~20 s)
pytest tests/unit            # fast, no browser needed
pytest -m "not browser"      # skip tests that launch Chromium
ruff check . && ruff format --check .
```

The test suite covers:

- **Unit:** URL/SSRF policy (about 50 attack vectors), egress proxy, crawler and robots.txt handling, WCAG mapping, axe result normalisation, scoring and summaries, the database, the rate limiter, and report rendering, including XSS escaping of scanned HTML.
- **Integration, API:** the full scan → poll → report → delete flow against a fake engine, plus validation, rate limits, CORS and security headers.
- **Integration, browser:** real Chromium scans of a local fixture site with known defects, crawl limits, robots.txt, JavaScript-rendered content and PDF output. They also prove that redirects and iframes pointing at an internal service are blocked before that service receives any request.

---

## Docker

```bash
docker compose up --build
# → http://localhost:8000   (scan history persists in the "vev-data" volume)
```

Or without Compose:

```bash
docker build -t vev-audit .
docker run -p 8000:8000 --shm-size=1g -v vev-data:/app/data vev-audit
```

The image runs as a non-root user and listens on `$PORT` (default 8000). It has a built-in health check at
`/api/health`. Run it with a **single worker**: scans, the browser and SQLite all live in one process.

---

## Deploying (Netlify + a backend host)

**Netlify can host the dashboard, but not the scanner.** The scanner needs a long-running server with a real Chromium
browser, which Netlify Functions can't provide (size and time limits). The recommended setup:

```
Browser ──► Netlify (static frontend/)  ──/api/* proxy──►  Render / Fly.io / Railway (Docker: FastAPI + Chromium + SQLite)
```

### 1. Deploy the backend (Docker)

**Render** (blueprint included):

1. Push this repo to GitHub.
2. In Render, go to **New → Blueprint** and select the repo. It reads [`render.yaml`](render.yaml), which defines a Docker web service, a health check and a 1 GB persistent disk for SQLite.
3. Note the service URL, e.g. `https://vev-audit-api.onrender.com`.

Use at least the *Starter* plan: Chromium needs about 1 GB of RAM, and a persistent disk keeps scan history and screenshots. Screenshots take roughly 0.1–0.5 MB per scanned page with issues; deleting a scan deletes its screenshots.

**Fly.io:** run `fly launch` (it detects the Dockerfile), then `fly volumes create vev_data --size 1` and mount it at
`/app/data`.

**Railway:** create a new service from the repo (Dockerfile detected) and add a volume mounted at `/app/data`.

On any of these hosts, set `VEV_TRUST_PROXY_HEADERS=true` so rate limiting sees real client IPs.

### 2. Deploy the frontend on Netlify

1. In Netlify, go to **Add new site → Import from Git** and choose this repo. [`netlify.toml`](netlify.toml) already sets the publish directory (`frontend`) and the build command.
2. In **Site configuration → Environment variables**, add `VEV_API_URL` with your backend URL (it must use `https://`).
3. Deploy.

By default (`VEV_API_MODE=proxy`) the build script writes a Netlify `_redirects` rule that proxies `/api/*` to your
backend. The browser only ever talks to your Netlify domain, so **no CORS setup is needed**.

If you prefer the browser to call the API directly instead, set `VEV_API_MODE=direct` in Netlify, and set
`VEV_CORS_ORIGINS=https://your-site.netlify.app` on the backend.

> Tip: the backend also serves the dashboard itself, so a single Docker deployment works on its own without
> Netlify.

---

## API overview

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/scans` | Start a scan: `{"url": "https://example.com", "max_pages": 5, "scan_all": false, "screenshots": true, "respect_robots": true}`. Returns `202` |
| `GET` | `/api/scans/{id}/screenshots/{name}` | An annotated screenshot (JPEG); names appear in the scan results |
| `GET` | `/api/scans/{id}/status` | Lightweight progress for polling |
| `GET` | `/api/scans/{id}` | Full results: summary, pages, grouped violations, needs-review items, manual checks |
| `GET` | `/api/scans?limit=&offset=` | Scan history |
| `DELETE` | `/api/scans/{id}` | Delete a finished scan |
| `GET` | `/api/scans/{id}/report.pdf` · `.html` · `.json` | Download a report (`?inline=true` to view in the browser) |
| `GET` | `/api/health`, `/api/config` | Health check and public limits |

---

## Security

Scanning arbitrary URLs with a headless browser is a classic SSRF risk. Vev Audit defends against it in layers:

1. **Input validation** ([`url_policy.py`](vev_audit/security/url_policy.py)). Only `http` and `https` URLs are accepted, without embedded credentials, and only on allowed ports. Local and internal hostnames are rejected (`localhost`, `*.local`, `*.internal`, `metadata.google.internal`, and so on). The hostname is resolved, and the URL is rejected if **any** of its addresses is non-public. That covers:
   - private, loopback and link-local ranges, including 169.254.169.254 (cloud metadata)
   - carrier-grade NAT (CGNAT), reserved and multicast ranges
   - IPv6 unique-local addresses
   - IPv4 addresses embedded in IPv6 (IPv4-mapped, 6to4, NAT64)
   - decimal, octal and hex IPv4 tricks
2. **Egress proxy** ([`egress_proxy.py`](vev_audit/security/egress_proxy.py)). Chromium can reach the network *only* through an in-process HTTP/CONNECT proxy. For **every** connection (navigations, redirects, iframes, sub-resources, fetch/XHR, WebSockets, robots.txt) the proxy re-resolves DNS, re-applies the policy and connects to the exact IP it vetted. This defeats open-redirect pivots and DNS rebinding. Loopback is explicitly *not* bypassed, and WebRTC non-proxied UDP, QUIC and DNS prefetching are disabled.
3. **Browser isolation.** Each scan uses a fresh browser context: no cookies, service workers blocked, downloads disabled. PDF rendering runs with JavaScript disabled and all network access aborted.
4. **Output safety.** Everything taken from scanned pages is escaped, in both the Jinja2 templates and the dashboard's escaping template helper. Link URLs are restricted to `http(s)`, and colour values to hex. HTML reports are served with a `default-src 'none'` Content Security Policy.
5. **Abuse limits.** Per-IP rate limiting, a cap on pages per scan, a concurrency limit and per-scan timeouts.

For public deployments, also consider running the container in a network with egress firewalling and putting
authentication in front of the API.

## Limitations

- Results reflect the default, logged-out state of each page at a single 1280×800 viewport. Content behind logins or interactions isn't tested, and neither are other breakpoints.
- Automated checks cover only part of WCAG 2.2. Always complete the manual checklist and test with assistive technology.
- The "automated score" is a heuristic summary of automated violations, **not** a conformance or compliance rating.
- Rate limits and the scan queue are in-memory, which fits the intended single-instance deployment.

## Project structure

```
vev_audit/
  main.py              FastAPI app factory, security headers, static frontend
  config.py            Environment-based settings
  database.py          SQLite persistence (scans, pages, findings)
  summary.py           Aggregation, scoring, disclaimer
  api/routes.py        REST endpoints and report downloads
  scanner/             engine (Chromium lifecycle), axe runner, crawler, scan service, WCAG reference data
  security/            URL policy, egress proxy, rate limiter
  reports/             report builder, renderers, Jinja2 template, logo
  vendor/axe.min.js    axe-core (MPL-2.0, see AXE_LICENSE.txt)
frontend/              Static dashboard (Netlify-ready)
tests/                 unit/, integration/, fixtures/site/
scripts/netlify-build.sh, netlify.toml, render.yaml, Dockerfile, docker-compose.yml, .github/workflows/ci.yml
```

## Licences

axe-core is © Deque Systems and licensed under MPL-2.0 (`vev_audit/vendor/AXE_LICENSE.txt`).
