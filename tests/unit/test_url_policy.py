import ipaddress

import pytest

from tests.conftest import fake_resolver
from vev_audit.security.url_policy import UrlPolicy, UrlValidationError, is_public_ip

PUBLIC = {"example.com": ["93.184.215.14"], "www.example.com": ["93.184.215.14", "2606:2800:21f:cb07::1"]}


@pytest.fixture
def policy() -> UrlPolicy:
    return UrlPolicy(
        resolver=fake_resolver(
            {
                **PUBLIC,
                "rebind.example.net": ["93.184.215.14", "10.0.0.5"],
                "internal.example.net": ["192.168.1.10"],
                "v6local.example.net": ["fd00::1"],
                "metadata.example.net": ["169.254.169.254"],
            }
        )
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://example.com", "https://example.com/"),
        ("example.com", "https://example.com/"),
        ("example.com:8080", "https://example.com:8080/"),
        ("  HTTPS://Example.COM/path?q=1#frag ", "https://example.com/path?q=1"),
        ("http://example.com:8080/a", "http://example.com:8080/a"),
        ("https://example.com:443/", "https://example.com/"),
        ("https://www.example.com./x", "https://www.example.com/x"),
    ],
)
async def test_valid_urls_are_normalised(policy, raw, expected):
    assert await policy.validate_url(raw) == expected


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ("", "enter a URL"),
        ("ftp://example.com", "Only http"),
        ("javascript:alert(1)", "Only http"),
        ("mailto:someone@example.com", "Only http"),
        ("data:text/html,hi", "Only http"),
        ("file:///etc/passwd", "Only http"),
        ("http://user:pass@example.com", "credentials"),
        ("http://example.com:22", "Port 22"),
        ("http://example.com:99999", "invalid port"),
        ("http://localhost", "local or internal"),
        ("http://app.localhost", "local or internal"),
        ("http://printer.local", "local or internal"),
        ("http://metadata.google.internal", "local or internal"),
        ("http://intranet", "fully-qualified"),
        ("http://127.0.0.1", "private"),
        ("http://10.1.2.3", "private"),
        ("http://172.16.0.1", "private"),
        ("http://192.168.0.1", "private"),
        ("http://169.254.169.254/latest/meta-data", "private"),
        ("http://100.64.0.1", "private"),
        ("http://0.0.0.0", "private"),
        ("http://[::1]", "private"),
        ("http://[fe80::1]", "private"),
        ("http://[fd12:3456::1]", "private"),
        ("http://[::ffff:10.0.0.1]", "private"),
        ("http://[64:ff9b::7f00:1]", "private"),
        ("http://2130706433", "private"),  # decimal 127.0.0.1
        ("http://0x7f.1", "private"),  # hex shorthand
        ("http://017700000001", "private"),  # octal
        ("http://internal.example.net", "private"),
        ("http://rebind.example.net", "private"),
        ("http://v6local.example.net", "private"),
        ("http://metadata.example.net", "private"),
        ("http://does-not-exist.example.net", "resolve"),
        ("http://exa mple.com", "whitespace"),
        ("http://example.com/" + "a" * 3000, "too long"),
    ],
)
async def test_unsafe_urls_are_rejected(policy, raw, message):
    with pytest.raises(UrlValidationError, match=f"(?i){message}"):
        await policy.validate_url(raw)


@pytest.mark.parametrize(
    ("ip", "public"),
    [
        ("8.8.8.8", True),
        ("2606:4700:4700::1111", True),
        ("127.0.0.1", False),
        ("10.0.0.1", False),
        ("198.18.0.1", False),
        ("224.0.0.1", False),
        ("::", False),
        ("2002:0a00:0001::1", False),  # 6to4 wrapping 10.0.0.1
        ("2002:0808:0808::1", False),  # 6to4 relay space is blocked wholesale
    ],
)
def test_is_public_ip(ip, public):
    assert is_public_ip(ipaddress.ip_address(ip)) is public


async def test_resolve_allowed_returns_vetted_addresses(policy):
    assert await policy.resolve_allowed("www.example.com", 443) == PUBLIC["www.example.com"]


async def test_private_networks_can_be_enabled_for_development():
    dev = UrlPolicy(allow_private_networks=True, allowed_ports=frozenset({8000}))
    assert await dev.validate_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000/"
    with pytest.raises(UrlValidationError, match="Port"):
        await dev.validate_url("http://127.0.0.1:9000/")
