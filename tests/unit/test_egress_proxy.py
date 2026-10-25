import asyncio

import pytest

from vev_audit.security.egress_proxy import EgressProxy
from vev_audit.security.url_policy import UrlPolicy


async def _raw(proxy: EgressProxy, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    writer.write(request)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(65536), timeout=5)
    writer.close()
    return data


@pytest.fixture
async def dev_proxy(fixture_site):
    """Proxy that permits loopback but only the fixture site's port."""
    proxy = EgressProxy(UrlPolicy(allow_private_networks=True, allowed_ports=frozenset({fixture_site.port})))
    await proxy.start()
    yield proxy
    await proxy.stop()


async def test_forwards_allowed_http(dev_proxy, fixture_site):
    resp = await _raw(dev_proxy, f"GET {fixture_site.base}/about.html HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    assert resp.startswith(b"HTTP/1.0 200") or resp.startswith(b"HTTP/1.1 200")
    assert dev_proxy.stats.allowed == 1


async def test_blocks_disallowed_destination_without_contacting_it(dev_proxy, trap_server):
    resp = await _raw(dev_proxy, f"GET {trap_server.base}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    assert resp.startswith(b"HTTP/1.1 403")
    assert trap_server.hits == []
    assert dev_proxy.stats.blocked == 1


async def test_blocks_connect_tunnels(dev_proxy, trap_server):
    resp = await _raw(dev_proxy, f"CONNECT 127.0.0.1:{trap_server.port} HTTP/1.1\r\n\r\n".encode())
    assert resp.startswith(b"HTTP/1.1 403")
    resp = await _raw(dev_proxy, b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n")
    assert resp.startswith(b"HTTP/1.1 403")


async def test_allows_connect_to_permitted_destination(dev_proxy, fixture_site):
    resp = await _raw(dev_proxy, f"CONNECT 127.0.0.1:{fixture_site.port} HTTP/1.1\r\n\r\n".encode())
    assert resp.startswith(b"HTTP/1.1 200 Connection Established")


async def test_default_policy_blocks_loopback(fixture_site):
    proxy = EgressProxy(UrlPolicy(allowed_ports=frozenset({fixture_site.port})))
    await proxy.start()
    try:
        resp = await _raw(proxy, f"GET {fixture_site.base}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        assert resp.startswith(b"HTTP/1.1 403")
    finally:
        await proxy.stop()


async def test_rejects_malformed_requests(dev_proxy):
    assert (await _raw(dev_proxy, b"GET /relative HTTP/1.1\r\n\r\n")).startswith(b"HTTP/1.1 400")
    assert (await _raw(dev_proxy, b"garbage\r\n\r\n")).startswith(b"HTTP/1.1 400")
