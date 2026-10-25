import pytest

from vev_audit.scanner.crawler import CrawlFrontier, normalize_link, parse_robots, same_site

BASE = "https://example.com/blog/post"


@pytest.mark.parametrize(
    ("href", "expected"),
    [
        ("/about", "https://example.com/about"),
        ("next", "https://example.com/blog/next"),
        ("https://EXAMPLE.com:443/x#section", "https://example.com/x"),
        ("?page=2", "https://example.com/blog/post?page=2"),
        ("http://example.com:8080/", "http://example.com:8080/"),
        ("#top", None),
        ("mailto:a@b.c", None),
        ("tel:+123", None),
        ("javascript:void(0)", None),
        ("/files/report.PDF", None),
        ("/img/logo.png", None),
        ("ftp://example.com/x", None),
        ("", None),
        ("http://[bad", None),
    ],
)
def test_normalize_link(href, expected):
    assert normalize_link(href, BASE) == expected


def test_same_site_treats_www_as_equivalent():
    assert same_site("https://www.example.com/a", "https://example.com/")
    assert not same_site("http://example.com/a", "https://example.com/")
    assert not same_site("https://sub.example.com/a", "https://example.com/")
    assert not same_site("https://example.com:8443/a", "https://example.com/")


def test_frontier_respects_page_budget_and_dedupes():
    f = CrawlFrontier("https://example.com/", max_pages=3, max_depth=2)
    assert f.next() == ("https://example.com/", 0)
    f.add_links(
        ["/a", "/a/", "/a#x", "https://other.org/", "/b", "/c", "/d"],
        base="https://example.com/",
        depth=0,
    )
    assert [f.next(), f.next(), f.next()] == [("https://example.com/a", 1), ("https://example.com/b", 1), None]
    assert f.scheduled == 3


def test_frontier_respects_depth():
    f = CrawlFrontier("https://example.com/", max_pages=10, max_depth=1)
    f.next()
    f.add_links(["/level1"], "https://example.com/", depth=0)
    url, depth = f.next()
    f.add_links(["/level2"], url, depth=depth)
    assert f.next() is None


def test_frontier_respects_robots():
    robots = parse_robots("User-agent: *\nDisallow: /private/\n", "https://example.com/robots.txt")
    f = CrawlFrontier("https://example.com/", max_pages=10, max_depth=2, robots=robots)
    f.next()
    f.add_links(["/private/x", "/public"], "https://example.com/", depth=0)
    assert f.next() == ("https://example.com/public", 1)
    assert f.next() is None
