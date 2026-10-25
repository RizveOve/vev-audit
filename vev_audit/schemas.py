"""Request/response models for the public API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, examples=["https://example.com"])
    max_pages: int | None = Field(None, ge=1, le=100, description="Pages to crawl (capped by server limit).")
    scan_all: bool = Field(False, description="Discover and scan every page (sitemap + links), up to the server cap.")
    respect_robots: bool = True
    screenshots: bool = Field(True, description="Capture annotated screenshots of failing elements.")


class ScanListItem(BaseModel):
    id: str
    url: str
    status: str
    created_at: str
    finished_at: str | None = None
    pages_done: int = 0
    pages_total: int = 0
    note: str | None = None
    summary: dict[str, Any] | None = None


class ScanList(BaseModel):
    items: list[ScanListItem]
    total: int


class ScanStatus(BaseModel):
    id: str
    url: str
    status: str
    pages_done: int
    pages_total: int
    current_url: str | None = None
    note: str | None = None


class ErrorResponse(BaseModel):
    detail: str
