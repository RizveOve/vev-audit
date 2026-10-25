/* Vev Audit dashboard — dependency-free single-page app. */
(() => {
  "use strict";

  const API = String((window.VEV_CONFIG && window.VEV_CONFIG.apiBase) || "").replace(/\/+$/, "");
  const view = document.getElementById("view");
  const main = document.getElementById("main");
  const IMPACTS = ["critical", "serious", "moderate", "minor"];
  const LABEL = { critical: "Critical", serious: "Serious", moderate: "Moderate", minor: "Minor" };
  const STATUS_LABEL = { queued: "Queued", running: "Scanning", completed: "Completed", failed: "Failed" };
  const NODES_SHOWN = 5;

  let pollTimer = null;
  let firstRender = true;
  let appConfig = { max_pages_limit: 10, default_max_pages: 5, respect_robots_txt: true, max_pages_all: 200, screenshots_enabled: true };
  let currentScanId = null;

  // ---------------------------------------------------------------------------
  // Safe templating: every interpolated value is HTML-escaped unless wrapped in raw().
  class Raw { constructor(s) { this.s = s; } }
  const raw = (s) => new Raw(s);
  const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
  const renderVal = (v) => {
    if (v instanceof Raw) return v.s;
    if (Array.isArray(v)) return v.map(renderVal).join("");
    if (v === false || v === null || v === undefined) return "";
    return esc(v);
  };
  const html = (strings, ...vals) => raw(strings.reduce((out, s, i) => out + renderVal(vals[i - 1]) + s));
  const mount = (el, tpl) => { el.innerHTML = renderVal(tpl); };

  const icon = {
    check: raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>'),
    shield: raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>'),
    layers: raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 2 10 5-10 5L2 7l10-5z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/></svg>'),
    file: raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M12 18v-6"/><path d="m9 15 3 3 3-3"/></svg>'),
    eye: raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>'),
    chev: raw('<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>'),
    person: raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="7" r="4"/><path d="M5.5 21a6.5 6.5 0 0 1 13 0"/></svg>'),
    arrow: raw('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>'),
  };

  // ---------------------------------------------------------------------------
  class ApiError extends Error {
    constructor(message, status) { super(message); this.status = status; }
  }

  async function api(path, options = {}) {
    let res;
    try {
      res = await fetch(API + path, {
        ...options,
        headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}) },
      });
    } catch {
      throw new ApiError("Could not reach the Vev Audit API. Check that the backend is running.", 0);
    }
    if (!res.ok) {
      let message = `Request failed (HTTP ${res.status}).`;
      try {
        const body = await res.json();
        if (typeof body.detail === "string") message = body.detail;
        else if (Array.isArray(body.detail)) message = body.detail.map((d) => d.msg).join(" ");
      } catch { /* non-JSON error */ }
      throw new ApiError(message, res.status);
    }
    return res.status === 204 ? null : res.json();
  }

  const fmtDate = (iso) => {
    if (!iso) return "—";
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(d);
  };
  // Only http(s) URLs may become links; anything else (javascript:, data:, chrome-error:) is neutralised.
  const safeUrl = (url) => { try { const u = new URL(url); return /^https?:$/.test(u.protocol) ? u.href : "#"; } catch { return "#"; } };
  const hostOf = (url) => { try { return new URL(url).host; } catch { return url; } };
  const plural = (n, word, pluralWord) => `${n} ${n === 1 ? word : pluralWord || word + "s"}`;

  function toast(message) {
    const el = document.getElementById("toast");
    el.textContent = message;
    el.hidden = false;
    clearTimeout(toast.t);
    toast.t = setTimeout(() => { el.hidden = true; }, 3200);
  }

  function setTitle(t) { document.title = `${t} — Vev Audit`; }

  function focusHeading() {
    if (firstRender) { firstRender = false; return; }
    const h = view.querySelector("h1");
    if (h) { h.setAttribute("tabindex", "-1"); h.focus({ preventScroll: false }); }
    else main.focus();
  }

  // ---------------------------------------------------------------------------
  // Router
  function route() {
    clearInterval(pollTimer);
    pollTimer = null;
    const hash = location.hash.replace(/^#/, "") || "/";
    const scanMatch = hash.match(/^\/scan\/([a-f0-9]{8,64})$/);
    let navKey = "home";
    if (scanMatch) { navKey = "history"; renderScan(scanMatch[1]); }
    else if (hash === "/history") { navKey = "history"; renderHistory(); }
    else if (hash === "/about") { navKey = "about"; renderAbout(); }
    else { renderHome(); }
    document.querySelectorAll("[data-nav]").forEach((a) => {
      if (a.dataset.nav === navKey && !scanMatch) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    window.scrollTo(0, 0);
  }

  // ---------------------------------------------------------------------------
  // Home
  function renderHome() {
    setTitle("New accessibility scan");
    const limit = appConfig.max_pages_limit;
    const options = [1, 3, 5, 10, 25].filter((n) => n <= limit);
    if (!options.includes(limit)) options.push(limit);
    const def = options.includes(appConfig.default_max_pages) ? appConfig.default_max_pages : options[0];

    mount(view, html`
      <section class="hero" aria-labelledby="hero-title">
        <div>
          <span class="eyebrow">WCAG 2.2 · Automated audit</span>
          <h1 id="hero-title">Find accessibility barriers <span class="gradient-text">before your users do</span></h1>
          <p class="hero-lead">Vev Audit loads your pages in a real browser, runs the axe-core rule engine against
            WCAG 2.2 A/AA, and turns the results into prioritised, developer-ready fixes and branded reports.</p>
          <ul class="feature-list">
            <li>${icon.layers}<span><strong>Rendered-page scanning</strong> — JavaScript-heavy sites are tested as users see them, with limited same-site crawling.</span></li>
            <li>${icon.check}<span><strong>Actionable findings</strong> — severity, affected HTML, WCAG criteria and suggested fixes for every issue.</span></li>
            <li>${icon.file}<span><strong>Shareable reports</strong> — download branded PDF, standalone HTML or JSON.</span></li>
            <li>${icon.person}<span><strong>Honest results</strong> — automated findings are kept separate from issues that need a human to review.</span></li>
          </ul>
        </div>
        <div class="card scan-card">
          <h2>Start a new scan</h2>
          <form id="scan-form" novalidate>
            <div id="form-error" role="alert"></div>
            <div class="field">
              <label for="url">Website URL</label>
              <div class="url-row">
                <input id="url" name="url" type="url" inputmode="url" autocomplete="url" spellcheck="false"
                  placeholder="https://example.com" required aria-describedby="url-hint">
                <button class="btn btn-primary" type="submit" id="scan-submit">${icon.shield}<span>Scan site</span></button>
              </div>
              <p class="hint" id="url-hint">Public websites only. Private, internal and local network addresses are blocked.</p>
            </div>
            <fieldset class="field segmented">
              <legend>Pages to scan</legend>
              ${options.map((n) => html`<label><input type="radio" name="max_pages" value="${n}" ${n === def ? raw("checked") : ""}><span>${n === 1 ? "1 page" : n}</span></label>`)}
              <label><input type="radio" name="max_pages" value="all"><span>All pages</span></label>
            </fieldset>
            <p class="hint pages-hint" id="pages-hint">More than one page follows same-site links from your URL. <strong>All pages</strong> also reads the sitemap and scans the whole site (up to ${appConfig.max_pages_all} pages, several at a time).</p>
            <div class="field">
              <label class="checkbox"><input type="checkbox" name="respect_robots" ${appConfig.respect_robots_txt ? raw("checked") : ""}> Respect robots.txt when crawling</label>
            </div>
            ${appConfig.screenshots_enabled ? html`<div class="field">
              <label class="checkbox"><input type="checkbox" name="screenshots" checked> Capture annotated screenshots of each problem</label>
            </div>` : ""}
          </form>
        </div>
      </section>
      <section aria-labelledby="recent-title" class="section-gap">
        <div class="card-head">
          <h2 id="recent-title">Recent scans</h2>
          <a href="#/history" class="btn btn-ghost btn-sm">View all history ${icon.arrow}</a>
        </div>
        <div id="recent"><div class="skeleton"></div><div class="skeleton"></div></div>
      </section>
    `);
    document.getElementById("scan-form").addEventListener("submit", onSubmitScan);
    loadScanTable(document.getElementById("recent"), 5, true);
    focusHeading();
  }

  async function onSubmitScan(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const input = form.url;
    const errorBox = document.getElementById("form-error");
    const button = document.getElementById("scan-submit");
    const showError = (msg) => {
      mount(errorBox, html`<p class="alert alert-error" id="url-error">${msg}</p>`);
      input.setAttribute("aria-invalid", "true");
      input.setAttribute("aria-describedby", "url-error url-hint");
      input.focus();
    };
    mount(errorBox, "");
    input.removeAttribute("aria-invalid");
    input.setAttribute("aria-describedby", "url-hint");
    const url = input.value.trim();
    if (!url) return showError("Enter the address of the website you want to scan.");

    button.disabled = true;
    mount(button, html`<span class="spin" aria-hidden="true"></span><span>Starting…</span>`);
    try {
      const scan = await api("/api/scans", {
        method: "POST",
        body: JSON.stringify({
          url,
          scan_all: form.max_pages.value === "all",
          max_pages: form.max_pages.value === "all" ? null : Number(form.max_pages.value),
          respect_robots: form.respect_robots.checked,
          screenshots: form.screenshots ? form.screenshots.checked : false,
        }),
      });
      location.hash = `#/scan/${scan.id}`;
    } catch (err) {
      showError(err.message);
      button.disabled = false;
      mount(button, html`${icon.shield}<span>Scan site</span>`);
    }
  }

  // ---------------------------------------------------------------------------
  // History
  function renderHistory() {
    setTitle("Scan history");
    mount(view, html`
      <div class="card-head">
        <div>
          <h1>Scan history</h1>
          <p class="muted" style="margin:0">All scans stored on this Vev Audit server, newest first.</p>
        </div>
        <a class="btn btn-primary" href="#/">${icon.shield} New scan</a>
      </div>
      <div id="history-table"><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div></div>
    `);
    loadScanTable(document.getElementById("history-table"), 100, false);
    focusHeading();
  }

  function miniSeverity(summary) {
    if (!summary) return html`<span class="muted">—</span>`;
    const parts = IMPACTS.filter((i) => summary.issues_by_impact[i] > 0)
      .map((i) => html`<span class="badge ${i}" title="${LABEL[i]} issues">${summary.issues_by_impact[i]} ${LABEL[i].toLowerCase()}</span>`);
    return parts.length ? html`<span class="mini-sev">${parts}</span>` : html`<span class="badge status-completed">No automated issues</span>`;
  }

  async function loadScanTable(container, limit, compact) {
    try {
      const data = await api(`/api/scans?limit=${limit}`);
      if (!data.items.length) {
        mount(container, html`<div class="empty"><h3>No scans yet</h3><p>Run your first scan to see results here.</p>${compact ? "" : html`<a class="btn btn-primary" href="#/">Start a scan</a>`}</div>`);
        return;
      }
      mount(container, html`
        <div class="table-wrap">
          <table>
            <caption class="visually-hidden">${compact ? "Most recent scans" : `All scans (${data.total})`}</caption>
            <thead><tr>
              <th scope="col">Website</th><th scope="col">Scanned</th><th scope="col">Status</th>
              <th scope="col" class="num">Pages</th><th scope="col">Automated issues</th><th scope="col" class="num">Score</th>
              <th scope="col"><span class="visually-hidden">Actions</span></th>
            </tr></thead>
            <tbody>
              ${data.items.map((s) => html`
                <tr>
                  <td class="url-cell"><a href="#/scan/${s.id}"><strong>${hostOf(s.url)}</strong></a><div class="small muted">${s.url}</div></td>
                  <td>${fmtDate(s.finished_at || s.created_at)}</td>
                  <td><span class="badge status-${s.status}">${STATUS_LABEL[s.status] || s.status}</span></td>
                  <td class="num">${s.summary ? s.summary.pages_scanned : s.pages_done}</td>
                  <td>${s.status === "completed" ? miniSeverity(s.summary) : html`<span class="muted small">${s.note || "—"}</span>`}</td>
                  <td class="num">${s.summary && s.summary.automated_score != null ? s.summary.automated_score : "—"}</td>
                  <td><div class="row-actions">
                    <a class="btn btn-secondary btn-sm" href="#/scan/${s.id}">View<span class="visually-hidden"> scan of ${hostOf(s.url)}</span></a>
                    ${compact || s.status === "running" || s.status === "queued" ? "" : html`<button class="btn btn-danger btn-sm" type="button" data-delete="${s.id}" data-host="${hostOf(s.url)}">Delete<span class="visually-hidden"> scan of ${hostOf(s.url)}</span></button>`}
                  </div></td>
                </tr>`)}
            </tbody>
          </table>
        </div>`);
      container.querySelectorAll("[data-delete]").forEach((btn) => btn.addEventListener("click", async () => {
        if (!window.confirm(`Delete the scan of ${btn.dataset.host}? This cannot be undone.`)) return;
        try {
          await api(`/api/scans/${btn.dataset.delete}`, { method: "DELETE" });
          toast("Scan deleted");
          loadScanTable(container, limit, compact);
          main.focus();
        } catch (err) { toast(err.message); }
      }));
    } catch (err) {
      mount(container, html`<p class="alert alert-error">${err.message}</p>`);
    }
  }

  // ---------------------------------------------------------------------------
  // Scan detail
  async function renderScan(id) {
    setTitle("Scan results");
    mount(view, html`<h1 class="visually-hidden">Loading scan</h1><div class="card"><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div></div>`);
    let report;
    try {
      report = await api(`/api/scans/${id}`);
    } catch (err) {
      mount(view, html`<h1>Scan not available</h1><p class="alert alert-error">${err.message}</p><a class="btn btn-secondary" href="#/history">Back to history</a>`);
      focusHeading();
      return;
    }
    if (report.scan.status === "queued" || report.scan.status === "running") {
      renderProgress(report.scan);
      focusHeading();
      startPolling(id);
    } else {
      renderReport(report);
      focusHeading();
    }
  }

  function progressText(scan) {
    const total = scan.pages_total || 0;
    if (!total) return "Launching browser and discovering pages…";
    return `Scanned ${scan.pages_done} of ${total} ${total === 1 ? "page" : "pages"}${total > 10 ? " found so far" : ""}`;
  }

  function renderProgress(scan) {
    setTitle(`Scanning ${hostOf(scan.url)}`);
    const total = scan.pages_total || 0;
    const pct = total ? Math.round((scan.pages_done / total) * 100) : 0;
    const existing = document.getElementById("progress-status");
    if (existing) {
      // Update in place so screen readers hear concise changes, not a full re-render.
      const bar = view.querySelector(".progress");
      bar.classList.toggle("indeterminate", !total);
      bar.setAttribute("aria-valuenow", String(pct));
      bar.firstElementChild.style.width = `${pct}%`;
      existing.textContent = progressText(scan);
      document.getElementById("progress-url").textContent = scan.current_url || "";
      return;
    }
    mount(view, html`
      <nav class="breadcrumb" aria-label="Breadcrumb"><a href="#/history">Scan history</a> / Scan in progress</nav>
      <section class="card progress-card" aria-labelledby="progress-title">
        <div class="spinner" aria-hidden="true"></div>
        <h1 id="progress-title">Scanning ${hostOf(scan.url)}</h1>
        <p class="muted">Rendering pages in headless Chromium, running axe-core WCAG 2.2 checks and capturing annotated screenshots. Small scans take under a minute; full-site scans can take several minutes.</p>
        <div class="progress ${total ? "" : "indeterminate"}" role="progressbar" aria-label="Scan progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><span></span></div>
        <p id="progress-status" role="status" aria-live="polite"><strong>${progressText(scan)}</strong></p>
        <p class="current-url" id="progress-url">${scan.current_url || ""}</p>
      </section>`);
    view.querySelector(".progress > span").style.width = `${pct}%`;
  }

  function startPolling(id) {
    let failures = 0;
    pollTimer = setInterval(async () => {
      try {
        const status = await api(`/api/scans/${id}/status`);
        failures = 0;
        if (status.status === "queued" || status.status === "running") {
          renderProgress(status);
        } else {
          clearInterval(pollTimer);
          pollTimer = null;
          const report = await api(`/api/scans/${id}`);
          renderReport(report);
          toast(status.status === "completed" ? "Scan complete" : "Scan finished with errors");
          focusHeading();
        }
      } catch (err) {
        failures += 1;
        if (failures >= 5) {
          clearInterval(pollTimer);
          mount(view, html`<h1>Lost connection</h1><p class="alert alert-error">${err.message}</p><a class="btn btn-secondary" href="#/scan/${id}">Retry</a>`);
        }
      }
    }, 1500);
  }

  function scoreRing(score) {
    if (score == null) return html`<div class="stat-value">—</div>`;
    const r = 20, c = 2 * Math.PI * r, off = c * (1 - score / 100);
    return html`<div class="score-ring">
      <svg viewBox="0 0 48 48" aria-hidden="true"><circle cx="24" cy="24" r="${r}" fill="none" stroke="var(--surface-2)" stroke-width="6"/>
      <circle cx="24" cy="24" r="${r}" fill="none" stroke="var(--brand)" stroke-width="6" stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}" transform="rotate(-90 24 24)"/></svg>
      <div class="stat-value">${score}<span class="small muted">/100</span></div></div>`;
  }

  const shotUrl = (name) => `${API}/api/scans/${currentScanId}/screenshots/${encodeURIComponent(name)}`;

  function renderReport(report) {
    const { scan, summary: s } = report;
    currentScanId = scan.id;
    const host = hostOf(scan.url);
    setTitle(`${host} accessibility results`);
    const failed = scan.status === "failed";
    const maxEl = Math.max(1, ...IMPACTS.map((i) => s.elements_by_impact[i]));
    const totalEl = IMPACTS.reduce((a, i) => a + s.elements_by_impact[i], 0);

    mount(view, html`
      <nav class="breadcrumb" aria-label="Breadcrumb"><a href="#/history">Scan history</a> / ${host}</nav>
      <header class="scan-header">
        <div>
          <h1>${host}</h1>
          <div class="scan-meta">
            <span class="badge status-${scan.status}">${STATUS_LABEL[scan.status]}</span>
            <span>${fmtDate(scan.finished_at || scan.created_at)}</span>
            <span>${plural(s.pages_scanned, "page")} scanned</span>
            ${scan.engine ? html`<span>${scan.engine}</span>` : ""}
          </div>
          <p class="small muted" style="margin:6px 0 0; word-break:break-all">${scan.url}</p>
        </div>
        ${failed && !s.pages_scanned ? "" : html`
        <div class="downloads" role="group" aria-label="Download report">
          <button class="btn btn-primary" type="button" data-download="pdf">${icon.file}<span>PDF report</span></button>
          <button class="btn btn-secondary" type="button" data-download="html"><span>HTML</span></button>
          <button class="btn btn-secondary" type="button" data-download="json"><span>JSON</span></button>
        </div>`}
      </header>

      ${scan.note ? html`<p class="alert ${failed ? "alert-error" : "alert-info"}">${scan.note}</p>` : ""}
      <p class="alert alert-info"><strong>Automated results only.</strong> These findings come from automated testing, which detects only part of WCAG 2.2.
        Passing these checks does not mean the site is accessible or WCAG-conformant. Review the “Needs review” items and the manual checklist with real users and assistive technology.</p>

      ${failed && !s.pages_scanned ? html`
        <div class="empty"><h3>No pages could be scanned</h3><p>Check that the URL is publicly reachable and try again.</p><a class="btn btn-primary" href="#/">Try another scan</a></div>
      ` : html`
      <section aria-label="Summary statistics" class="stats">
        <div class="stat"><div class="stat-label">Automated issues</div><div class="stat-value">${s.violation_issues}</div><div class="stat-hint">${plural(s.violation_elements, "affected element")}</div></div>
        <div class="stat"><div class="stat-label">Critical + serious</div><div class="stat-value">${s.issues_by_impact.critical + s.issues_by_impact.serious}</div><div class="stat-hint">fix these first</div></div>
        <div class="stat"><div class="stat-label">Needs review</div><div class="stat-value">${s.needs_review_issues}</div><div class="stat-hint">manual verification</div></div>
        <div class="stat"><div class="stat-label">Checks passed</div><div class="stat-value">${s.passed_checks}</div><div class="stat-hint">automated rules</div></div>
        <div class="stat"><div class="stat-label">Automated score</div>${scoreRing(s.automated_score)}<div class="stat-hint">Not a compliance rating</div></div>
      </section>

      <div class="grid-2">
        <section class="card" aria-labelledby="sev-title">
          <h2 id="sev-title">Severity breakdown</h2>
          <p class="small muted">Affected elements by axe-core impact level.</p>
          <div class="stacked" aria-hidden="true">
            ${IMPACTS.filter((i) => s.elements_by_impact[i] > 0).map((i) => html`<span class="fill-${i}" data-grow="${s.elements_by_impact[i] / Math.max(totalEl, 1)}" title="${LABEL[i]}: ${s.elements_by_impact[i]}"></span>`)}
          </div>
          <ul class="sev-rows" style="list-style:none;padding:0;margin:0">
            ${IMPACTS.map((i) => html`
              <li class="sev-row" title="${LABEL[i]}: ${plural(s.issues_by_impact[i], "issue")}, ${plural(s.elements_by_impact[i], "element")}">
                <span class="badge ${i}">${LABEL[i]}</span>
                <span class="sev-track" aria-hidden="true"><span class="sev-fill fill-${i}" data-width="${(s.elements_by_impact[i] / maxEl) * 100}" style="display:block"></span></span>
                <span class="sev-val">${plural(s.elements_by_impact[i], "element")} · ${plural(s.issues_by_impact[i], "issue")}</span>
              </li>`)}
          </ul>
        </section>
        <section class="card" aria-labelledby="crit-title">
          <h2 id="crit-title">WCAG criteria affected</h2>
          ${s.wcag_criteria_failed.length ? html`
            <p class="small muted">${plural(s.wcag_criteria_failed.length, "success criterion", "success criteria")} with automated failures.</p>
            <ul class="criteria-list">
              ${s.wcag_criteria_failed.map((c) => html`<li><a href="${safeUrl(c.url)}" target="_blank" rel="noopener noreferrer">${c.id} ${c.name}<span class="visually-hidden"> (opens in new tab)</span></a><span class="lvl">Level ${c.level} · ${plural(c.elements, "el.", "el.")}</span></li>`)}
            </ul>` : html`<p class="muted">No WCAG success criteria failed automated checks. Manual review is still required.</p>`}
        </section>
      </div>

      <div class="tabs" role="tablist" aria-label="Scan results">
        ${[
          ["violations", "Automated issues", report.violations.length],
          ["review", "Needs review", report.needs_review.length],
          ["manual", "Manual checklist", report.manual_checks.length],
          ["pages", "Pages", report.pages.length],
        ].map(([key, label, count], idx) => html`
          <button class="tab" role="tab" type="button" id="tab-${key}" aria-controls="panel-${key}" aria-selected="${idx === 0}" tabindex="${idx === 0 ? 0 : -1}">${label}<span class="count">${count}</span></button>`)}
      </div>
      <div class="tabpanel" role="tabpanel" id="panel-violations" aria-labelledby="tab-violations" tabindex="0"></div>
      <div class="tabpanel" role="tabpanel" id="panel-review" aria-labelledby="tab-review" tabindex="0" hidden></div>
      <div class="tabpanel" role="tabpanel" id="panel-manual" aria-labelledby="tab-manual" tabindex="0" hidden></div>
      <div class="tabpanel" role="tabpanel" id="panel-pages" aria-labelledby="tab-pages" tabindex="0" hidden></div>
      `}
    `);

    // CSP-friendly sizing (no inline style attributes from data).
    view.querySelectorAll("[data-width]").forEach((el) => { el.style.width = `${Number(el.dataset.width)}%`; });
    view.querySelectorAll("[data-grow]").forEach((el) => { el.style.flex = `${Number(el.dataset.grow)} 1 0`; });
    view.querySelectorAll("[data-download]").forEach((btn) => btn.addEventListener("click", () => download(scan.id, btn.dataset.download, btn)));

    if (failed && !s.pages_scanned) return;
    setupTabs();
    renderViolationsPanel(report);
    renderReviewPanel(report);
    renderManualPanel(report);
    renderPagesPanel(report);
  }

  function setupTabs() {
    const tabs = [...view.querySelectorAll('[role="tab"]')];
    const select = (tab, focus) => {
      tabs.forEach((t) => {
        const on = t === tab;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
      });
      if (focus) tab.focus();
    };
    tabs.forEach((tab, i) => {
      tab.addEventListener("click", () => select(tab, false));
      tab.addEventListener("keydown", (e) => {
        let next = null;
        if (e.key === "ArrowRight") next = tabs[(i + 1) % tabs.length];
        else if (e.key === "ArrowLeft") next = tabs[(i - 1 + tabs.length) % tabs.length];
        else if (e.key === "Home") next = tabs[0];
        else if (e.key === "End") next = tabs[tabs.length - 1];
        if (next) { e.preventDefault(); select(next, true); }
      });
    });
  }

  function problemView(n, isReview) {
    const parts = [];
    if (n.problems && n.problems.length) parts.push(html`<ul class="problems">${n.problems.map((m) => html`<li><strong>${m}</strong></li>`)}</ul>`);
    if (n.alternatives && n.alternatives.length) {
      // Lead with the most common cause; list the other accepted ways to satisfy the rule below it.
      const lead = !n.problems || !n.problems.length;
      const rest = lead ? n.alternatives.slice(1) : n.alternatives;
      if (lead) parts.push(html`<p class="problem-headline">${n.alternatives[0]}</p>`);
      if (rest.length) parts.push(html`<p class="alt-lbl">${isReview ? "Also checked:" : lead ? "Also missing (any one of these would fix it):" : "None of these accepted alternatives is present:"}</p>
        <ul class="problems alt">${rest.map((m) => html`<li>${m}</li>`)}</ul>`);
    }
    if (!parts.length && n.failure_summary) parts.push(html`<p class="why">${n.failure_summary}</p>`);
    return parts;
  }

  function nodeView(n, isReview) {
    const el = n.element;
    return html`<div class="node${n.screenshot ? " has-shot" : ""}">
      ${n.screenshot ? html`<button type="button" class="shot-btn" data-shot="${n.screenshot}" data-caption="${n.target}">
        <img src="${shotUrl(n.screenshot)}" alt="Screenshot of the ${el ? `<${el.tag}>` : "affected"} element outlined on the page" loading="lazy">
        <span class="shot-hint">Enlarge screenshot</span></button>` : ""}
      <div class="node-info">
        <p class="node-lbl">${isReview ? "Why it needs review" : "Exact problem"}</p>
        ${problemView(n, isReview)}
        ${n.contrast && n.contrast.foreground && n.contrast.background ? html`<div class="contrast-info">
          <span class="swatch" data-bg="${n.contrast.foreground}"></span>${n.contrast.foreground} text on
          <span class="swatch" data-bg="${n.contrast.background}"></span>${n.contrast.background} —
          measured <strong>${n.contrast.ratio}:1</strong>, needs ${n.contrast.expected}${n.contrast.font_size ? ` (${n.contrast.font_size})` : ""}</div>` : ""}
        <dl class="facts">
          ${el ? html`<div><dt>Element</dt><dd><code>&lt;${el.tag}&gt;</code>${el.text ? html` “${el.text}”` : ""}</dd></div>
            ${el.page_level ? html`<div><dt>Scope</dt><dd>Applies to the whole page</dd></div>`
              : el.visible ? html`<div><dt>Size / position</dt><dd>${el.width}×${el.height} px at x ${el.x}, y ${el.y}</dd></div>`
              : html`<div><dt>Visibility</dt><dd>Not visible on screen (hidden or zero-size)</dd></div>`}` : ""}
          <div><dt>Selector</dt><dd class="node-sel"><code>${n.target}</code><button type="button" class="btn btn-ghost btn-sm" data-copy="${n.target}">Copy</button></dd></div>
        </dl>
        <pre><code>${n.html}</code></pre>
      </div>
    </div>`;
  }

  function occurrencesView(issue) {
    return issue.occurrences.map((occ) => html`
      <p class="occ-page">On page: <a href="${safeUrl(occ.page_url)}" target="_blank" rel="noopener noreferrer">${occ.page_url}<span class="visually-hidden"> (opens in new tab)</span></a></p>
      ${occ.nodes.slice(0, NODES_SHOWN).map((n) => nodeView(n, issue.kind === "needs_review"))}
      ${occ.nodes.length > NODES_SHOWN ? html`<details class="more-nodes"><summary class="btn btn-ghost btn-sm">Show ${occ.nodes.length - NODES_SHOWN} more elements</summary>${occ.nodes.slice(NODES_SHOWN).map((n) => nodeView(n, issue.kind === "needs_review"))}</details>` : ""}
    `);
  }

  function issueView(issue, isReview) {
    const cls = isReview ? "review" : issue.impact;
    return html`<details class="issue ${cls}">
      <summary>
        <div class="issue-top">
          ${isReview ? html`<span class="badge review">Needs review</span>` : html`<span class="badge ${issue.impact}">${LABEL[issue.impact]}</span>`}
          <span class="issue-title">${issue.help}</span>
          <span class="issue-rule">${issue.rule_id}</span>
          ${icon.chev}
        </div>
        <div>
          ${issue.wcag.map((c) => html`<span class="chip">WCAG ${c.id} · ${c.level}</span>`)}
          ${issue.best_practice ? html`<span class="chip">Best practice</span>` : ""}
          <span class="issue-counts">${plural(issue.node_count, "element")} on ${plural(issue.page_count, "page")}</span>
        </div>
      </summary>
      <div class="issue-body">
        <p>${issue.description}</p>
        ${issue.affects ? html`<p class="affects"><strong>Who is affected:</strong> ${issue.affects}</p>` : ""}
        ${isReview
          ? html`<div class="fix"><p class="fix-title">What to check</p><p>The automated engine could not determine whether this passes. Inspect each element below and verify it manually against the related WCAG criteria.</p></div>`
          : html`<div class="fix"><p class="fix-title">How to fix</p><p>${issue.remediation}</p></div>`}
        ${issue.wcag.length ? html`<p class="small">${issue.wcag.map((c) => html`<a class="chip" href="${safeUrl(c.url)}" target="_blank" rel="noopener noreferrer">${c.id} ${c.name}<span class="visually-hidden"> (opens in new tab)</span></a>`)}</p>` : ""}
        ${occurrencesView(issue)}
        ${issue.help_url ? html`<p class="small" style="margin-top:12px"><a href="${safeUrl(issue.help_url)}" target="_blank" rel="noopener noreferrer">Learn more about ${issue.rule_id}<span class="visually-hidden"> (opens in new tab)</span></a></p>` : ""}
      </div>
    </details>`;
  }

  function wireNodes(container) {
    container.querySelectorAll("[data-shot]").forEach((btn) => btn.addEventListener("click", () => openShot(shotUrl(btn.dataset.shot), btn.dataset.caption, btn)));
    container.querySelectorAll("[data-bg]").forEach((el) => { el.style.background = el.dataset.bg; });
    container.querySelectorAll("[data-copy]").forEach((btn) => btn.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(btn.dataset.copy); toast("Selector copied"); }
      catch { toast("Could not copy to clipboard"); }
    }));
  }

  function renderViolationsPanel(report) {
    const panel = document.getElementById("panel-violations");
    if (!report.violations.length) {
      mount(panel, html`<div class="empty"><h3>No automated violations detected</h3><p>That's a great start, but automated tools can't test everything. Work through the <strong>Needs review</strong> items and the <strong>Manual checklist</strong>.</p></div>`);
      return;
    }
    const state = { impacts: new Set(IMPACTS), page: "all", q: "" };
    mount(panel, html`
      <div class="filters">
        <div role="group" aria-label="Filter by severity">
          <span class="small" style="display:block;font-weight:600;margin-bottom:6px">Severity</span>
          <div class="sev-toggle">${IMPACTS.map((i) => html`<button type="button" class="${i}" data-impact="${i}" aria-pressed="true"><span class="dot ${i}" aria-hidden="true"></span>${LABEL[i]} (${report.summary.issues_by_impact[i]})</button>`)}</div>
        </div>
        <div class="field"><label for="f-page">Page</label>
          <select id="f-page"><option value="all">All pages</option>${report.pages.filter((p) => !p.error).map((p) => html`<option value="${p.id}">${p.title ? `${p.title} — ` : ""}${p.final_url || p.url}</option>`)}</select></div>
        <div class="field"><label for="f-q">Search issues</label><input id="f-q" type="search" placeholder="e.g. contrast, label, 1.4.3"></div>
      </div>
      <p class="small muted" id="v-count" role="status" aria-live="polite"></p>
      <div class="issue-list" id="v-list"></div>
    `);
    const list = document.getElementById("v-list");
    const count = document.getElementById("v-count");
    const update = () => {
      const q = state.q.toLowerCase();
      const items = report.violations
        .filter((v) => state.impacts.has(v.impact))
        .map((v) => (state.page === "all" ? v : { ...v, occurrences: v.occurrences.filter((o) => String(o.page_id) === state.page) }))
        .filter((v) => v.occurrences.length)
        .filter((v) => !q || [v.help, v.description, v.rule_id, ...v.wcag.map((c) => `${c.id} ${c.name}`)].join(" ").toLowerCase().includes(q))
        .map((v) => state.page === "all" ? v : { ...v, node_count: v.occurrences.reduce((a, o) => a + o.nodes.length, 0), page_count: 1 });
      count.textContent = `Showing ${plural(items.length, "issue")} of ${report.violations.length}.`;
      mount(list, items.length ? items.map((v) => issueView(v, false)) : html`<div class="empty">No issues match these filters.</div>`);
      wireNodes(list);
    };
    panel.querySelectorAll("[data-impact]").forEach((btn) => btn.addEventListener("click", () => {
      const on = btn.getAttribute("aria-pressed") !== "true";
      btn.setAttribute("aria-pressed", String(on));
      if (on) state.impacts.add(btn.dataset.impact); else state.impacts.delete(btn.dataset.impact);
      update();
    }));
    document.getElementById("f-page").addEventListener("change", (e) => { state.page = e.target.value; update(); });
    document.getElementById("f-q").addEventListener("input", (e) => { state.q = e.target.value.trim(); update(); });
    update();
  }

  function renderReviewPanel(report) {
    const panel = document.getElementById("panel-review");
    mount(panel, html`
      <p class="alert alert-info"><strong>Not counted as violations.</strong> axe-core found these potential problems but could not decide whether they pass — for example text over images or gradients. A person must check each one.</p>
      ${report.needs_review.length ? html`<div class="issue-list">${report.needs_review.map((i) => issueView(i, true))}</div>` : html`<div class="empty">No items need review from the automated engine. Use the manual checklist next.</div>`}
    `);
    wireNodes(panel);
  }

  function renderManualPanel(report) {
    mount(document.getElementById("panel-manual"), html`
      <p class="alert alert-info"><strong>Not tested by this scan.</strong> These WCAG 2.2 requirements need human judgement and can't be verified automatically. Use them to plan expert and user testing.</p>
      <div class="checklist">
        ${report.manual_checks.map((c) => html`<article class="check-item">
          <h3>${icon.eye}${c.title}</h3>
          <p>${c.how}</p>
          <div>${c.criteria_detail.map((sc) => html`<a class="chip" href="${safeUrl(sc.url)}" target="_blank" rel="noopener noreferrer">${sc.id} ${sc.name}<span class="visually-hidden"> (opens in new tab)</span></a>`)}</div>
        </article>`)}
      </div>`);
  }

  function renderPagesPanel(report) {
    const panel = document.getElementById("panel-pages");
    mount(panel, html`
      <div class="table-wrap"><table>
        <caption class="visually-hidden">Pages included in this scan</caption>
        <thead><tr><th scope="col">Page</th><th scope="col" class="num">HTTP</th><th scope="col" class="num">Issues</th><th scope="col" class="num">Review</th><th scope="col" class="num">Passed</th><th scope="col" class="num">Score</th><th scope="col" class="num">Load</th></tr></thead>
        <tbody>${report.pages.map((p) => html`<tr>
          <td class="url-cell">${p.title ? html`<strong>${p.title}</strong><br>` : ""}<a href="${safeUrl(p.final_url || p.url)}" target="_blank" rel="noopener noreferrer">${p.final_url || p.url}<span class="visually-hidden"> (opens in new tab)</span></a>
            ${p.error ? html`<div class="small" style="color:var(--danger-ink)">Not scanned: ${p.error}</div>` : ""}</td>
          <td class="num">${p.status_code ?? "—"}</td>
          <td class="num">${p.error ? "—" : p.violation_rules}</td>
          <td class="num">${p.error ? "—" : p.review_rules}</td>
          <td class="num">${p.error ? "—" : p.passes}</td>
          <td class="num">${p.score ?? "—"}</td>
          <td class="num">${p.load_time_ms ? `${(p.load_time_ms / 1000).toFixed(1)}s` : "—"}</td>
        </tr>`)}</tbody>
      </table></div>
      ${report.pages.some((p) => p.screenshot) ? html`<h2 class="section-gap">Annotated pages</h2>
        <p class="muted small">Numbered outlines mark each located problem. Page-level and best-practice container issues are listed but not outlined.</p>
        <div class="page-cards">
          ${report.pages.filter((p) => p.screenshot).map((p) => html`<article class="card page-card">
            <h3>${p.title || hostOf(p.final_url || p.url)}</h3>
            <p class="small muted url-cell">${p.final_url || p.url}</p>
            <button type="button" class="shot-btn overview-btn" data-shot="${p.screenshot}" data-caption="${p.title || p.url}">
              <img src="${shotUrl(p.screenshot)}" alt="Annotated screenshot of ${p.title || "the page"} with numbered outlines around each problem" loading="lazy">
              <span class="shot-hint">Enlarge screenshot</span></button>
            <ol class="legend">${p.legend.map((l) => html`<li><span class="legend-num ${l.impact}">${l.number}</span><span class="badge ${l.impact}">${LABEL[l.impact]}</span> ${l.help} <span class="small muted">(${l.marked ? `${l.marked} outlined` : "page-level"}${l.total > l.marked && l.marked ? ` of ${l.total}` : ""})</span></li>`)}</ol>
          </article>`)}
        </div>` : ""}`);
    wireNodes(panel);
  }

  // Accessible screenshot viewer (native <dialog>: focus trap, Esc to close).
  function openShot(src, caption, opener) {
    let dlg = document.getElementById("shot-dialog");
    if (!dlg) {
      dlg = document.createElement("dialog");
      dlg.id = "shot-dialog";
      dlg.className = "shot-dialog";
      dlg.setAttribute("aria-labelledby", "shot-dialog-title");
      document.body.appendChild(dlg);
      dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });
      dlg.addEventListener("close", () => { if (dlg._opener) dlg._opener.focus(); });
    }
    mount(dlg, html`<div class="shot-dialog-head"><h2 id="shot-dialog-title">Screenshot</h2><p class="small muted mono">${caption}</p>
      <button type="button" class="btn btn-secondary btn-sm" data-close>Close</button></div>
      <div class="shot-dialog-body"><img src="${src}" alt="Full-size annotated screenshot: ${caption}"></div>`);
    dlg.querySelector("[data-close]").addEventListener("click", () => dlg.close());
    dlg._opener = opener;
    dlg.showModal();
    dlg.querySelector("[data-close]").focus();
  }

  async function download(id, fmt, btn) {
    const original = btn.innerHTML;
    btn.disabled = true;
    mount(btn, html`<span class="spin" aria-hidden="true"></span><span>${fmt === "pdf" ? "Generating PDF…" : "Preparing…"}</span>`);
    try {
      const res = await fetch(`${API}/api/scans/${id}/report.${fmt}`);
      if (!res.ok) {
        let msg = `Download failed (HTTP ${res.status}).`;
        try { msg = (await res.json()).detail || msg; } catch { /* ignore */ }
        throw new Error(msg);
      }
      const blob = await res.blob();
      const cd = res.headers.get("Content-Disposition") || "";
      const name = (cd.match(/filename="([^"]+)"/) || [])[1] || `vev-audit-report.${fmt}`;
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
      toast(`${fmt.toUpperCase()} report downloaded`);
    } catch (err) {
      toast(err.message);
    } finally {
      btn.disabled = false;
      btn.innerHTML = original;
    }
  }

  // ---------------------------------------------------------------------------
  // About
  function renderAbout() {
    setTitle("How it works");
    mount(view, html`
      <div class="prose">
        <span class="eyebrow">Methodology</span>
        <h1>How Vev Audit works</h1>
        <p class="hero-lead">Vev Audit combines a real browser with the industry-standard axe-core engine, and is explicit about what automation can and can't tell you.</p>
      </div>
      <div class="how-grid section-gap">
        <div class="card"><div class="step-num">1</div><h2>Render</h2><p>Each page loads in headless Chromium (via Playwright) so scripts, frameworks and dynamic content are tested as users see them. Optional crawling follows same-site links.</p></div>
        <div class="card"><div class="step-num">2</div><h2>Test</h2><p>axe-core runs WCAG 2.0, 2.1 and 2.2 Level A and AA rules plus best-practice checks, and maps each result to the relevant success criteria.</p></div>
        <div class="card"><div class="step-num">3</div><h2>Prioritise</h2><p>Results are grouped by rule, ranked by severity and paired with the affected HTML, CSS selectors and suggested fixes, then exported as PDF, HTML or JSON.</p></div>
      </div>
      <div class="grid-2 section-gap">
        <section class="card" aria-labelledby="ah-1">
          <h2 id="ah-1">Automated vs. manual</h2>
          <ul>
            <li><span class="badge critical">Automated issues</span> are confirmed failures of a rule — fix these.</li>
            <li><span class="badge review">Needs review</span> means the engine found something it couldn't decide on; a person must check it.</li>
            <li>The <strong>manual checklist</strong> covers criteria automation cannot evaluate, such as keyboard operation, focus order, caption accuracy and meaningful alt text.</li>
          </ul>
          <p><strong>Vev Audit never claims WCAG compliance.</strong> Automated tools typically detect a minority of accessibility barriers; conformance requires expert and user testing.</p>
        </section>
        <section class="card" aria-labelledby="ah-2">
          <h2 id="ah-2">Security &amp; privacy</h2>
          <ul>
            <li>Only public <code>http</code>/<code>https</code> sites can be scanned.</li>
            <li>Every connection the browser makes — including redirects, iframes and sub-resources — passes through a validating proxy that blocks private, loopback, link-local and cloud-metadata addresses.</li>
            <li>Scans run without cookies or logins, with service workers and downloads disabled.</li>
            <li>Results are stored in this server's SQLite database and can be deleted from Scan history.</li>
          </ul>
        </section>
      </div>`);
    focusHeading();
  }

  // ---------------------------------------------------------------------------
  document.getElementById("year").textContent = String(new Date().getFullYear());
  window.addEventListener("hashchange", route);
  api("/api/config").then((cfg) => { appConfig = { ...appConfig, ...cfg }; }).catch(() => {}).finally(route);
})();
