"""FastAPI application factory and ASGI entry point (``uvicorn vev_audit.main:app``)."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api.routes import router
from .config import Settings
from .database import Database
from .scanner.engine import ScanEngine
from .scanner.service import ScanService
from .security import RateLimiter, UrlPolicy
from .storage import ScreenshotStore

log = logging.getLogger("vev_audit")

APP_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def create_app(
    settings: Settings | None = None, engine: ScanEngine | None = None, start_engine: bool = True
) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db = Database(settings.database_path)
        interrupted = db.mark_interrupted_scans()
        if interrupted:
            log.warning("Marked %d interrupted scan(s) as failed", interrupted)
        scan_engine = engine
        if scan_engine is None and start_engine:
            scan_engine = ScanEngine(settings, app.state.policy)
            await scan_engine.start()
        app.state.db = db
        app.state.engine = scan_engine
        app.state.scan_service = ScanService(db, scan_engine, settings, app.state.store)
        try:
            yield
        finally:
            await app.state.scan_service.shutdown()
            if scan_engine is not None and engine is None:
                await scan_engine.stop()
            db.close()

    app = FastAPI(
        title="Vev Audit API",
        version=__version__,
        description="Automated WCAG 2.2 accessibility scanning by Vevkraft.",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )
    app.state.settings = settings
    app.state.policy = (
        engine.policy
        if engine is not None
        else UrlPolicy(allowed_ports=settings.allowed_ports, allow_private_networks=settings.allow_private_networks)
    )
    app.state.store = ScreenshotStore(settings.screenshot_dir)
    app.state.rate_limiter = RateLimiter(settings.rate_limit_scans, settings.rate_limit_window_s)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Content-Type"],
            expose_headers=["Content-Disposition", "Retry-After"],
        )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if not request.url.path.startswith("/api/docs"):
            response.headers.setdefault("Content-Security-Policy", APP_CSP)
        return response

    app.include_router(router)

    if settings.frontend_dir is not None and settings.frontend_dir.is_dir():
        app.mount("/", StaticFiles(directory=settings.frontend_dir, html=True), name="frontend")

    return app


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
app = create_app()
