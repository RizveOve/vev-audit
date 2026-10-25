"""HTTP API: scans, scan history and report downloads."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse

from .. import __version__
from ..reports import build_report, render_html, render_json, render_pdf, report_filename
from ..schemas import ErrorResponse, ScanCreate, ScanList, ScanListItem, ScanStatus
from ..security import UrlValidationError

router = APIRouter(prefix="/api")

REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"


def _client_key(request: Request) -> str:
    if request.app.state.settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _get_scan_or_404(request: Request, scan_id: str) -> dict:
    scan = request.app.state.db.get_scan(scan_id) if len(scan_id) <= 64 else None
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
    return scan


@router.get("/health")
async def health(request: Request) -> dict:
    engine = request.app.state.engine
    return {"status": "ok", "version": __version__, "scanner": "ready" if engine is not None else "unavailable"}


@router.get("/config")
async def public_config(request: Request) -> dict:
    s = request.app.state.settings
    return {
        "max_pages_limit": s.max_pages_limit,
        "default_max_pages": min(s.default_max_pages, s.max_pages_limit),
        "respect_robots_txt": s.respect_robots_txt,
        "max_pages_all": s.max_pages_all,
        "screenshots_enabled": s.screenshots_enabled,
        "brand_name": s.brand_name,
        "version": __version__,
    }


@router.post(
    "/scans",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanStatus,
    responses={422: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
async def create_scan(payload: ScanCreate, request: Request) -> ScanStatus | JSONResponse:
    state = request.app.state
    try:
        url = await state.policy.validate_url(payload.url)
    except UrlValidationError as exc:
        raise HTTPException(422, str(exc)) from exc

    allowed, retry_after = state.rate_limiter.check(_client_key(request))
    if not allowed:
        return JSONResponse(
            {"detail": "Scan limit reached. Please try again later."},
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
        )

    settings = state.settings
    if payload.scan_all:
        max_pages = settings.max_pages_all
    else:
        max_pages = min(payload.max_pages or settings.default_max_pages, settings.max_pages_limit)
    options = {
        "max_pages": max_pages,
        "scan_all": payload.scan_all,
        "respect_robots": payload.respect_robots,
        "screenshots": payload.screenshots and settings.screenshots_enabled,
    }
    scan = state.db.create_scan(url, options)
    state.scan_service.submit(scan["id"])
    return ScanStatus(id=scan["id"], url=url, status=scan["status"], pages_done=0, pages_total=0)


@router.get("/scans", response_model=ScanList)
async def list_scans(request: Request, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0)) -> ScanList:
    db = request.app.state.db
    items = [
        ScanListItem(
            id=s["id"],
            url=s["url"],
            status=s["status"],
            created_at=s["created_at"],
            finished_at=s.get("finished_at"),
            pages_done=s.get("pages_done", 0),
            pages_total=s.get("pages_total", 0),
            note=s.get("error"),
            summary=s.get("summary"),
        )
        for s in db.list_scans(limit, offset)
    ]
    return ScanList(items=items, total=db.count_scans())


@router.get("/scans/{scan_id}/status", response_model=ScanStatus)
async def scan_status(scan_id: str, request: Request) -> ScanStatus:
    s = _get_scan_or_404(request, scan_id)
    return ScanStatus(
        id=s["id"],
        url=s["url"],
        status=s["status"],
        pages_done=s.get("pages_done", 0),
        pages_total=s.get("pages_total", 0),
        current_url=s.get("current_url"),
        note=s.get("error"),
    )


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, request: Request) -> dict:
    _get_scan_or_404(request, scan_id)
    return build_report(request.app.state.db, scan_id, request.app.state.settings)


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: str, request: Request) -> Response:
    scan = _get_scan_or_404(request, scan_id)
    if scan["status"] in {"queued", "running"}:
        raise HTTPException(status.HTTP_409_CONFLICT, "A running scan cannot be deleted.")
    request.app.state.db.delete_scan(scan_id)
    request.app.state.store.delete_scan(scan_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/scans/{scan_id}/screenshots/{name}")
async def get_screenshot(scan_id: str, name: str, request: Request) -> FileResponse:
    path = request.app.state.store.path(scan_id, name)
    if path is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Screenshot not found.")
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=86400"})


@router.get("/scans/{scan_id}/report.{fmt}")
async def download_report(
    scan_id: str, fmt: Literal["json", "html", "pdf"], request: Request, inline: bool = False
) -> Response:
    scan = _get_scan_or_404(request, scan_id)
    if scan["status"] in {"queued", "running"}:
        raise HTTPException(status.HTTP_409_CONFLICT, "The report is available once the scan has finished.")
    state = request.app.state
    report = build_report(state.db, scan_id, state.settings)
    filename = report_filename(report, fmt)
    disposition = f'{"inline" if inline else "attachment"}; filename="{filename}"'

    if fmt == "json":
        return Response(
            render_json(report), media_type="application/json", headers={"Content-Disposition": disposition}
        )
    if fmt == "html":
        return Response(
            render_html(report, state.settings, state.store),
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": disposition, "Content-Security-Policy": REPORT_CSP},
        )
    if state.engine is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "PDF rendering is unavailable.")
    pdf = await render_pdf(report, state.settings, state.engine, state.store)
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": disposition})
