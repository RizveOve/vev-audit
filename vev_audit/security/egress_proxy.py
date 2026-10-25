"""A tiny validating HTTP/CONNECT forward proxy for the headless browser.

Chromium is launched with this proxy as its only route to the network. For each
connection the proxy resolves the destination itself, rejects anything that is
not a public address via :class:`UrlPolicy`, and connects to the *vetted* IP.
This covers redirects, sub-resources, iframes and WebSockets, and closes the
DNS-rebinding window that pre-validation alone would leave open.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .url_policy import UrlPolicy, UrlValidationError

log = logging.getLogger(__name__)

MAX_HEADER_BYTES = 64 * 1024
CONNECT_TIMEOUT_S = 10
IDLE_TIMEOUT_S = 60
HOP_BY_HOP = {"proxy-connection", "proxy-authorization", "connection", "keep-alive"}


@dataclass
class EgressStats:
    allowed: int = 0
    blocked: int = 0
    blocked_hosts: dict[str, str] = field(default_factory=dict)


class EgressProxy:
    def __init__(self, policy: UrlPolicy, host: str = "127.0.0.1") -> None:
        self.policy = policy
        self.host = host
        self.port: int | None = None
        self.stats = EgressStats()
        self._server: asyncio.base_events.Server | None = None

    @property
    def url(self) -> str:
        if self.port is None:
            raise RuntimeError("Proxy not started")
        return f"http://{self.host}:{self.port}"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, 0)
        self.port = self._server.sockets[0].getsockname()[1]
        log.info("Egress proxy listening on %s", self.url)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None

    # ------------------------------------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=IDLE_TIMEOUT_S)
            if len(head) > MAX_HEADER_BYTES:
                await _respond(writer, 431, "Request Header Fields Too Large")
                return
            request_line, *header_lines = head.decode("latin-1").split("\r\n")
            method, target, version = request_line.split(" ", 2)

            if method.upper() == "CONNECT":
                host, port = _split_host_port(target, 443)
                ips = await self._authorize(host, port)
                if ips is None:
                    await _respond(writer, 403, "Blocked by Vev Audit network policy")
                    return
                up_reader, upstream_writer = await self._open(ips, port)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            else:
                parts = urlsplit(target)
                if parts.scheme.lower() != "http" or not parts.hostname:
                    await _respond(writer, 400, "Bad Request")
                    return
                port = parts.port or 80
                ips = await self._authorize(parts.hostname, port)
                if ips is None:
                    await _respond(writer, 403, "Blocked by Vev Audit network policy")
                    return
                up_reader, upstream_writer = await self._open(ips, port)
                path = parts.path or "/"
                if parts.query:
                    path += "?" + parts.query
                headers = [h for h in header_lines if h and h.split(":", 1)[0].strip().lower() not in HOP_BY_HOP]
                headers.append("Connection: close")
                upstream_writer.write(f"{method} {path} {version}\r\n".encode("latin-1"))
                upstream_writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("latin-1"))
                await upstream_writer.drain()

            # One request per upstream connection: when either side finishes, tear down both.
            tasks = [
                asyncio.create_task(_pipe(reader, upstream_writer)),
                asyncio.create_task(_pipe(up_reader, writer)),
            ]
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            with contextlib.suppress(Exception):
                await _respond(writer, 400, "Bad Request")
        except OSError as exc:
            log.debug("Upstream connection failed: %s", exc)
            with contextlib.suppress(Exception):
                await _respond(writer, 502, "Bad Gateway")
        finally:
            for w in (upstream_writer, writer):
                if w is not None:
                    with contextlib.suppress(Exception):
                        w.close()

    async def _authorize(self, host: str, port: int) -> list[str] | None:
        try:
            ips = await self.policy.resolve_allowed(host, port)
        except UrlValidationError as exc:
            self.stats.blocked += 1
            self.stats.blocked_hosts[f"{host}:{port}"] = str(exc)
            log.warning("Blocked egress to %s:%s — %s", host, port, exc)
            return None
        self.stats.allowed += 1
        return ips

    async def _open(self, ips: list[str], port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        last_error: OSError | None = None
        for ip in ips:
            try:
                return await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT_S)
            except (TimeoutError, OSError) as exc:
                last_error = exc if isinstance(exc, OSError) else OSError(str(exc))
        raise last_error or OSError("No addresses to connect to")


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, _, port = target.rpartition(":") if ":" in target else (target, "", "")
    return host, int(port) if port else default_port


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT_S)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (TimeoutError, OSError):
        pass
    finally:
        with contextlib.suppress(Exception):
            if writer.can_write_eof():
                writer.write_eof()


async def _respond(writer: asyncio.StreamWriter, status: int, reason: str) -> None:
    body = f"{status} {reason}\n".encode()
    writer.write(
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
        f"X-Vev-Blocked: {'1' if status == 403 else '0'}\r\nConnection: close\r\n\r\n".encode()
        + body
    )
    with contextlib.suppress(Exception):
        await writer.drain()
