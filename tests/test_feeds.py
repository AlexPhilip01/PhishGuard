"""
Tests for live threat-feed handling. No test touches the network: downloads are
replaced by a fake `http_get`, and all caches live in pytest's tmp_path.
"""
import json
import sys
import time
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishguard import threat_feed as tf  # noqa: E402
from phishguard.core import analyze_single  # noqa: E402


def make_index(domains=(), urls=()):
    idx = tf.FeedIndex()
    if domains:
        idx.add_domains("phishing-database", domains)
    if urls:
        idx.add_urls("openphish", urls)
    return idx


# --- matching rules -------------------------------------------------------

def test_listed_dedicated_domain_matches_host_and_parent():
    idx = make_index(domains=["paypa1-security.com"])
    assert idx.match("http://paypa1-security.com/login")["kind"] == "host"
    m = idx.match("https://secure.login.paypa1-security.com/x")
    assert m["kind"] == "parent-domain" and m["matched"] == "paypa1-security.com"


def test_unlisted_domain_does_not_match():
    idx = make_index(domains=["paypa1-security.com"])
    assert idx.match("https://www.paypal.com/signin") is None
    assert idx.match("https://paypa1-security.com.evil-but-unlisted.org/") is None


def test_www_variants_match_both_ways():
    assert make_index(domains=["www.evil.com"]).match("http://evil.com/a")
    assert make_index(domains=["evil.com"]).match("http://www.evil.com/a")


def test_bare_platform_entries_are_dropped_not_matched():
    # sites.google.com really appears as a bare entry in the Phishing.Database list
    idx = make_index(domains=["sites.google.com", "dweb.link", "s3.us-east-2.amazonaws.com", "github.io"])
    assert idx.match("https://sites.google.com/view/my-portfolio") is None
    assert idx.match("https://bafy123.ipfs.dweb.link/") is None
    assert idx.match("https://s3.us-east-2.amazonaws.com/my-bucket/file.pdf") is None
    assert idx.match("https://someone.github.io/site") is None


def test_listed_platform_tenant_matches_only_that_tenant():
    idx = make_index(domains=["scam123.github.io"])
    assert idx.match("https://scam123.github.io/login")
    assert idx.match("https://scam123.github.io/other/path")
    assert idx.match("https://honest.github.io/") is None
    assert idx.match("https://github.io/") is None
    # a deeper subdomain of a listed tenant is NOT assumed bad on platforms
    assert idx.match("https://x.scam123.github.io/") is None


def test_hub_entries_with_many_children_are_dropped(monkeypatch):
    monkeypatch.setattr(tf, "HUB_CHILD_THRESHOLD", 3)
    children = [f"c{i}.hubzone.net" for i in range(5)]
    idx = make_index(domains=["hubzone.net"] + children)
    assert idx.match("https://hubzone.net/legit") is None          # hub itself dropped
    assert idx.match("https://c1.hubzone.net/x")                    # listed child still matches
    assert idx.match("https://other.hubzone.net/x") is None


def test_second_level_tld_is_never_a_parent_match():
    idx = make_index(domains=["co.uk", "com.au"])
    assert idx.match("https://example.co.uk/") is None
    assert idx.match("https://example.com.au/") is None
    assert make_index(domains=["evil.co.uk"]).match("https://login.evil.co.uk/")


def test_ip_hosts_match_exactly():
    idx = make_index(domains=["203.0.113.9"])
    assert idx.match("http://203.0.113.9/payload")
    assert idx.match("http://203.0.113.10/payload") is None


def test_malformed_entries_are_skipped():
    idx = make_index(domains=["", "# comment", "has space.com", "user:pw@evil.com", "ok-domain.com/path", "fine.org"])
    assert list(idx.hosts) == ["fine.org"]


# --- URL feeds ------------------------------------------------------------

def test_url_feed_exact_url_and_case_insensitive_host():
    idx = make_index(urls=["http://Bad-Site.example/Login.php?id=7"])
    assert idx.match("http://bad-site.example/Login.php?id=7")["kind"] == "url"


def test_url_feed_on_dedicated_host_also_flags_other_paths():
    idx = make_index(urls=["http://bad-site.example/a/b.html"])
    m = idx.match("http://bad-site.example/completely/different")
    assert m and m["kind"] == "host"


def test_url_feed_on_shared_platform_only_matches_exact_url():
    idx = make_index(urls=["https://sites.google.com/view/scam-page"])
    assert idx.match("https://sites.google.com/view/scam-page")["kind"] == "url"
    assert idx.match("https://sites.google.com/view/my-real-portfolio") is None


def test_check_urls_against_feed_wrapper():
    got = tf.check_urls_against_feed(
        ["http://paypa1-security.com/login", "https://www.google.com/"],
        ["http://paypa1-security.com/verify"],
    )
    assert got == ["http://paypa1-security.com/login"]
    assert tf.check_urls_against_feed([], ["http://x.com"]) == []


# --- caching / offline behaviour -----------------------------------------

class FakeHttp:
    def __init__(self, text="evil-one.com\nevil-two.net\n", etag='"v1"', fail=False, not_modified=False):
        self.text, self.etag, self.fail, self.not_modified = text, etag, fail, not_modified
        self.calls = []

    def __call__(self, url, etag=None, timeout=30.0):
        self.calls.append({"url": url, "etag": etag})
        if self.fail:
            raise urllib.error.URLError("simulated outage")
        if self.not_modified and etag:
            return 304, None, etag
        return 200, self.text, self.etag


def test_first_load_downloads_then_cache_is_reused(tmp_path):
    http = FakeHttp()
    lines, status = tf.load_source("phishing-database", tmp_path, http_get=http)
    assert status == "fresh" and lines == ["evil-one.com", "evil-two.net"]
    lines, status = tf.load_source("phishing-database", tmp_path, http_get=http)
    assert status == "cached" and len(http.calls) == 1


def test_stale_cache_revalidates_with_etag_and_304_keeps_cache(tmp_path):
    http = FakeHttp()
    tf.load_source("phishing-database", tmp_path, http_get=http)
    meta_path = tmp_path / "phishing-database.meta.json"
    meta = json.loads(meta_path.read_text())
    meta["fetched_at"] = time.time() - 48 * 3600          # make it old
    meta_path.write_text(json.dumps(meta))

    http2 = FakeHttp(not_modified=True)
    lines, status = tf.load_source("phishing-database", tmp_path, http_get=http2)
    assert status == "cached" and lines == ["evil-one.com", "evil-two.net"]
    assert http2.calls[0]["etag"] == '"v1"'                # conditional request was sent
    assert time.time() - json.loads(meta_path.read_text())["fetched_at"] < 60  # age was reset


def test_download_failure_uses_stale_cache(tmp_path):
    tf.load_source("phishing-database", tmp_path, http_get=FakeHttp())
    meta_path = tmp_path / "phishing-database.meta.json"
    meta = json.loads(meta_path.read_text())
    meta["fetched_at"] = time.time() - 48 * 3600
    meta_path.write_text(json.dumps(meta))

    lines, status = tf.load_source("phishing-database", tmp_path, http_get=FakeHttp(fail=True))
    assert status == "stale" and lines == ["evil-one.com", "evil-two.net"]


def test_offline_with_no_cache_returns_empty_and_never_raises(tmp_path):
    lines, status = tf.load_source("phishing-database", tmp_path, http_get=FakeHttp(fail=True))
    assert status == "offline" and lines == []


def test_force_redownloads_even_when_cache_is_fresh(tmp_path):
    http = FakeHttp()
    tf.load_source("phishing-database", tmp_path, http_get=http)
    tf.load_source("phishing-database", tmp_path, force=True, http_get=http)
    assert len(http.calls) == 2


def test_build_index_reports_status_and_rejects_unknown_feed(tmp_path):
    idx, statuses = tf.build_index(["phishing-database"], cache_dir=tmp_path, http_get=FakeHttp())
    assert statuses["phishing-database"]["status"] == "fresh"
    assert statuses["phishing-database"]["count"] == 2
    assert idx.match("http://evil-one.com/x")
    try:
        tf.build_index(["no-such-feed"], cache_dir=tmp_path, http_get=FakeHttp())
        assert False, "expected ValueError"
    except ValueError as e:
        assert "no-such-feed" in str(e)


# --- end to end through the analyzer --------------------------------------

EML = """From: "Account Team" <team@example.com>
To: victim@example.com
Subject: Please review
Received: from mail.example.com (198.51.100.7) by mx.example.com
Date: Tue, 25 Aug 2026 09:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain

Please continue here: http://login.paypa1-security.com/session
and also see https://www.google.com/ for help.
"""


def test_analyze_single_flags_feed_match_and_explains_it(tmp_path):
    eml = tmp_path / "t.eml"
    eml.write_text(EML)
    idx = make_index(domains=["paypa1-security.com"])

    with_feed = analyze_single(str(eml), feed=idx, check_dmarc=False)
    without = analyze_single(str(eml), feed=None, check_dmarc=False)

    assert with_feed["feed_matches"] == ["http://login.paypa1-security.com/session"]
    detail = with_feed["feed_match_details"][0]
    assert detail["source"] == "phishing-database" and detail["kind"] == "parent-domain"
    assert with_feed["score"] == without["score"] + 40
    assert without["feed_matches"] is None


def test_analyze_single_still_accepts_a_plain_url_list(tmp_path):
    eml = tmp_path / "t.eml"
    eml.write_text(EML)
    r = analyze_single(str(eml), feed=["http://login.paypa1-security.com/session"], check_dmarc=False)
    assert r["feed_matches"] == ["http://login.paypa1-security.com/session"]
