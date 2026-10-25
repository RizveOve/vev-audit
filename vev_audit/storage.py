"""On-disk storage for scan screenshots: ``<screenshot_dir>/<scan_id>/<name>.jpg``."""

from __future__ import annotations

import base64
import re
import shutil
from pathlib import Path

_SCAN_ID = re.compile(r"^[a-f0-9]{8,64}$")
_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,120}\.jpg$")


class ScreenshotStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def path(self, scan_id: str, name: str) -> Path | None:
        """Resolve a stored file, or None for anything that is not a well-formed name (no traversal)."""
        if not _SCAN_ID.match(scan_id) or not _NAME.match(name):
            return None
        path = self.root / scan_id / name
        return path if path.is_file() else None

    def save(self, scan_id: str, name: str, data: bytes) -> str:
        if not _SCAN_ID.match(scan_id) or not _NAME.match(name):
            raise ValueError(f"Invalid screenshot name: {name!r}")
        folder = self.root / scan_id
        folder.mkdir(parents=True, exist_ok=True)
        (folder / name).write_bytes(data)
        return name

    def data_uri(self, scan_id: str, name: str | None) -> str | None:
        path = self.path(scan_id, name) if name else None
        if path is None:
            return None
        return "data:image/jpeg;base64," + base64.b64encode(path.read_bytes()).decode("ascii")

    def delete_scan(self, scan_id: str) -> None:
        if _SCAN_ID.match(scan_id):
            shutil.rmtree(self.root / scan_id, ignore_errors=True)
