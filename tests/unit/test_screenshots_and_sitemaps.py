import sqlite3

import pytest

from tests.helpers import axe_node, axe_rule
from vev_audit.database import Database
from vev_audit.scanner.axe import normalize_rule
from vev_audit.scanner.crawler import parse_sitemap, sitemaps_from_robots
from vev_audit.scanner.wcag import affected_users
from vev_audit.storage import ScreenshotStore

SCAN = "0123456789abcdef0123456789abcdef"


def test_store_round_trip_and_rejects_traversal(tmp_path):
    store = ScreenshotStore(tmp_path)
    assert store.save(SCAN, "p1-overview.jpg", b"jpeg") == "p1-overview.jpg"
    assert store.path(SCAN, "p1-overview.jpg").read_bytes() == b"jpeg"
    assert store.data_uri(SCAN, "p1-overview.jpg") == "data:image/jpeg;base64,anBlZw=="
    for bad in ["../x.jpg", "a/b.jpg", "x.png", ".hidden.jpg", ""]:
        assert store.path(SCAN, bad) is None
        with pytest.raises(ValueError):
            store.save(SCAN, bad or "x", b"")
    assert store.path("../etc", "p1-overview.jpg") is None
    assert store.data_uri(SCAN, None) is None
    store.delete_scan(SCAN)
    assert store.path(SCAN, "p1-overview.jpg") is None


def test_parse_sitemap_and_index():
    pages, children = parse_sitemap(
        "<urlset><url><loc> https://a.example/x?y=1&amp;z=2 </loc></url><url><loc>https://a.example/b</loc></url></urlset>"
    )
    assert pages == ["https://a.example/x?y=1&z=2", "https://a.example/b"] and children == []
    pages, children = parse_sitemap(
        "<sitemapindex><sitemap><loc>https://a.example/s1.xml</loc></sitemap></sitemapindex>"
    )
    assert pages == [] and children == ["https://a.example/s1.xml"]
    entity_bomb = '<!DOCTYPE x [<!ENTITY a "aaaa">]><urlset><url><loc>&a;</loc></url></urlset>'
    assert parse_sitemap(entity_bomb)[0] == ["&a;"]  # entities are never expanded


def test_sitemaps_from_robots():
    text = "User-agent: *\nDisallow:\nSitemap: https://a.example/sitemap.xml\nsitemap:https://a.example/news.xml\n"
    assert sitemaps_from_robots(text) == ["https://a.example/sitemap.xml", "https://a.example/news.xml"]


def test_node_separates_problems_from_alternatives():
    node = axe_node(
        "<img src=x>",
        ["img"],
        any=[{"message": "Element does not have an alt attribute"}, {"message": "aria-label is empty"}],
        none=[{"message": "Element has a presentational role conflict"}],
    )
    finding = normalize_rule(
        axe_rule("image-alt", "critical", ["cat.text-alternatives", "wcag111"], [node]), "violation"
    )
    n = finding["nodes"][0]
    assert n["problems"] == ["Element has a presentational role conflict"]
    assert n["alternatives"] == ["Element does not have an alt attribute", "aria-label is empty"]
    assert "screen readers" in finding["affects"]


def test_affected_users_unknown_category():
    assert affected_users(["wcag2a"]) is None


def test_database_migrates_old_schema(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE pages (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, url TEXT, final_url TEXT, title TEXT,"
        " status_code INTEGER, depth INTEGER DEFAULT 0, load_time_ms INTEGER, error TEXT, scanned_at TEXT,"
        " violation_count INTEGER DEFAULT 0, review_count INTEGER DEFAULT 0, passes_count INTEGER DEFAULT 0)"
    )
    conn.commit()
    conn.close()
    db = Database(path)
    scan = db.create_scan("https://example.com/", {})
    db.add_page(scan["id"], {"url": "https://example.com/", "screenshot": "p1-overview.jpg", "legend": [{"n": 1}]}, [])
    page = db.get_pages(scan["id"])[0]
    assert page["screenshot"] == "p1-overview.jpg" and page["legend"] == [{"n": 1}]
    db.close()
