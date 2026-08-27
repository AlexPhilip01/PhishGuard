"""
Live threat-feed integration — new in the restructured version.

Checks URLs found in an email body against OpenPhish's free community feed
(https://openphish.com/feed.txt), which lists currently active phishing URLs
and is refreshed by OpenPhish every few hours.

Design notes:
- This is entirely optional and fails *safely*: if the feed can't be reached
  (no internet, firewall, rate limit) the analyzer still runs on headers +
  keywords as before, it just skips the feed signal and says so.
- The feed is cached to disk so you're not re-downloading it for every email.
- OpenPhish's free feed is for personal/research use — check their terms
  (openphish.com/phishing_feeds.html) before relying on it in a commercial
  product; their paid tiers exist specifically for that.
"""
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
DEFAULT_CACHE_PATH = Path.home() / ".phishguard" / "openphish_cache.json"
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")


def extract_urls(text: str) -> list:
    """Pulls http(s) URLs out of an email body."""
    if not text:
        return []
    found = []
    for url in URL_PATTERN.findall(text):
        cleaned = url.rstrip(").,;\"'")
        if cleaned not in found:
            found.append(cleaned)
    return found


def _domain_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except ValueError:
        return ""


def _load_cache(cache_path: Path) -> dict:
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(cache_path: Path, urls: list) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps({"fetched_at": time.time(), "urls": urls}))


def fetch_openphish_feed(
    cache_path: Path = DEFAULT_CACHE_PATH,
    max_age_hours: float = 6.0,
    timeout: float = 10.0,
) -> tuple:
    """
    Returns (urls, status) where status is one of:
      "fresh"   - just downloaded
      "cached"  - served from a still-valid local cache
      "stale"   - download failed, fell back to an old cache
      "offline" - download failed and no cache was available
    Never raises — a feed problem should never crash an email analysis.
    """
    cache = _load_cache(cache_path)
    age_seconds = time.time() - cache.get("fetched_at", 0)

    if cache.get("urls") and age_seconds < max_age_hours * 3600:
        return cache["urls"], "cached"

    try:
        req = urllib.request.Request(
            OPENPHISH_FEED_URL,
            headers={"User-Agent": "PhishGuard/1.0 (+https://github.com/AlexPhilip01/PhishGuard)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        urls = [line.strip() for line in text.splitlines() if line.strip()]
        _save_cache(cache_path, urls)
        return urls, "fresh"
    except (urllib.error.URLError, TimeoutError, OSError):
        if cache.get("urls"):
            return cache["urls"], "stale"
        return [], "offline"


def check_urls_against_feed(urls: list, feed_urls: list) -> list:
    """
    Returns the subset of `urls` that match the feed — either an exact URL
    match or a match on domain (attackers often reuse a domain across many
    paths).
    """
    if not urls or not feed_urls:
        return []

    feed_url_set = set(feed_urls)
    feed_domains = {_domain_of(u) for u in feed_urls if _domain_of(u)}

    matches = []
    for url in urls:
        if url in feed_url_set or _domain_of(url) in feed_domains:
            matches.append(url)
    return matches
