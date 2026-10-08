"""Tests for look-alike (impersonation) domain detection."""
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishguard import core, lookalike, scorer  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("host,brand,kind", [
    ("paypa1-secure.com", "paypal", "homoglyph"),
    ("micr0soft-login.net", "microsoft", "homoglyph"),
    ("rnicrosoft.com", "microsoft", "homoglyph"),
    ("g00gle.com", "google", "homoglyph"),
    ("xn--pypal-4ve.com", "paypal", "homoglyph"),          # Cyrillic "а" in place of "a"
    ("paypall.com", "paypal", "typosquat"),
    ("amazom.com", "amazon", "typosquat"),
    ("paypal.com.evil.xyz", "paypal", "brand-in-subdomain"),
    ("www.paypal.evil.xyz", "paypal", "brand-in-subdomain"),
    ("paypal.github.io", "paypal", "brand-in-subdomain"),
    ("secure-paypal-login.com", "paypal", "brand-keyword"),
    ("ups-delivery.top", "ups", "brand-keyword"),
    ("paypal.xyz", "paypal", "unofficial-domain"),
])
def test_impersonating_hosts_are_flagged(host, brand, kind):
    hit = lookalike.check_host(host)
    assert hit and hit["brand"] == brand and hit["kind"] == kind


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.com", "amazon.in", "amazon.co.uk", "google.co.in",
    "mail.google.com", "login.microsoftonline.com", "raw.githubusercontent.com", "githubstatus.com",
    "s3.amazonaws.com", "googleusercontent.com", "fbcdn.net", "tracking.ups.com",
    "finance.com", "pineapple.com", "ample.com", "strive.com", "purchase.com", "chasing.com",
    "slackware.com", "example.com", "bbc.co.uk", "wikipedia.org", "paypay.ne.jp",
    "1.2.3.4", "localhost", "",
])
def test_legitimate_hosts_are_left_alone(host):
    assert lookalike.check_host(host) is None


def test_strength_levels():
    assert lookalike.check_host("paypa1.com")["strength"] == "strong"
    assert lookalike.check_host("paypal-help.com")["strength"] == "moderate"


def test_host_of_handles_urls_and_addresses():
    assert lookalike.host_of("https://User:pw@Evil.COM:8080/a?b#c") == "evil.com"
    assert lookalike.host_of("evil.com/path") == "evil.com"
    assert lookalike.host_of("name@evil.com") == "evil.com"


def test_scoring_strong_moderate_and_once_only():
    strong = lookalike.check_hosts(["paypa1.com"])
    moderate = lookalike.check_hosts(["paypal-help.com"])
    assert scorer.calculate_score([], {}, False, [], lookalikes=strong)[0] == 25
    assert scorer.calculate_score([], {}, False, [], lookalikes=moderate)[0] == 15
    both = strong + moderate + lookalike.check_hosts(["amazom.com"])
    score, reasons = scorer.calculate_score([], {}, False, [], lookalikes=both)
    assert score == 25 and len(reasons) == 1 and "more" in reasons[0]


def test_end_to_end_sender_and_link(tmp_path):
    eml = tmp_path / "a.eml"
    eml.write_text(
        "From: PayPal <service@paypa1-secure.com>\nTo: me@example.org\nSubject: Hello\n"
        "Date: Mon, 1 Jan 2024 10:00:00 +0000\nMessage-ID: <1@x>\n\n"
        "See https://www.paypal.evil.xyz/page for details.\n"
    )
    r = core.analyze_single(str(eml), check_dmarc=False)
    hosts = {l["host"] for l in r["lookalikes"]}
    assert hosts == {"paypa1-secure.com", "www.paypal.evil.xyz"}
    assert r["score"] == 25 and any("Look-alike" in x for x in r["reasons"])


def test_website_copy_of_brand_data_matches_python():
    """index.html carries a copy of the rules; fail loudly if the two drift apart."""
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    m = re.search(r"/\*LOOKALIKE_DATA_START\*/(.*?)/\*LOOKALIKE_DATA_END\*/", html, re.S)
    assert m, "look-alike data block missing from index.html"
    js = json.loads(m.group(1))
    assert js["brands"] == lookalike.BRANDS
    assert js["aliases"] == lookalike.ALIASES
    assert set(js["known_legit_nearby"]) == lookalike.KNOWN_LEGIT_NEARBY
    assert js["confusables"] == lookalike.CONFUSABLES
    assert js["platform_suffixes"] == list(lookalike._PLATFORM_SUFFIXES)
    assert set(js["second_level"]) == lookalike._SECOND_LEVEL
    assert set(js["no_typo_check"]) == lookalike.NO_TYPO_CHECK
    assert (js["min_substring_len"], js["min_subdomain_len"], js["min_typo_len"]) == (
        lookalike.MIN_SUBSTRING_LEN, lookalike.MIN_SUBDOMAIN_LEN, lookalike.MIN_TYPO_LEN)
