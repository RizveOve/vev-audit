from __future__ import annotations

import functools
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

FIXTURE_SITE = Path(__file__).parent / "fixtures" / "site"


@dataclass
class LocalServer:
    port: int
    hits: list[str] = field(default_factory=list)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"


class _Handler(SimpleHTTPRequestHandler):
    server_state: LocalServer

    def do_GET(self) -> None:  # noqa: N802
        self.server_state.hits.append(self.path)
        parts = urlsplit(self.path)
        if parts.path == "/redirect-out":
            target = parse_qs(parts.query)["to"][0]
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return
        if parts.path == "/sitemap.xml":
            base = f"http://127.0.0.1:{self.server_state.port}"
            body = (
                '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                f"<url><loc>{base}/sitemap-only.html</loc></url><url><loc>{base}/about.html</loc></url>"
                "<url><loc>https://other.example/x</loc></url></urlset>"
            )
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if parts.path == "/iframe-out":
            target = parse_qs(parts.query)["to"][0]
            body = (
                '<!doctype html><html lang="en"><title>Frame</title>'
                f'<main><iframe src="{target}" title="x"></iframe></main></html>'
            )
            self._send_html(body)
            return
        super().do_GET()

    def _send_html(self, body: str) -> None:
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        pass


def _start_server(directory: Path) -> tuple[ThreadingHTTPServer, LocalServer]:
    state = LocalServer(port=0)
    handler = type("Handler", (_Handler,), {"server_state": state})
    server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(handler, directory=str(directory)))
    state.port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, state


@pytest.fixture(scope="session")
def fixture_site() -> Iterator[LocalServer]:
    server, state = _start_server(FIXTURE_SITE)
    yield state
    server.shutdown()


@pytest.fixture
def trap_server(tmp_path: Path) -> Iterator[LocalServer]:
    """A server that should never be reached by the scanner."""
    (tmp_path / "index.html").write_text("<title>internal secret</title>")
    server, state = _start_server(tmp_path)
    yield state
    server.shutdown()


def fake_resolver(mapping: dict[str, list[str]]):
    async def resolve(host: str, port: int) -> list[str]:
        if host not in mapping:
            raise OSError("NXDOMAIN")
        return mapping[host]

    return resolve
