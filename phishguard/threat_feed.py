"""
Live threat-feed integration (multi-source).

Two feeds are supported out of the box:

  phishing-database  Phishing.Database "ACTIVE domains" list (community, regularly
                     refreshed upstream). A plain list of hostnames, ~400k entries.
  openphish          OpenPhish community feed (a list of full phishing URLs).
                     Non-commercial use only — see https://openphish.com/terms.html

How "live" works: every run checks each feed's local cache. If it is older than the
feed's max age, the feed is re-downloaded (using an ETag so an unchanged 11 MB list
costs one tiny request). If a download fails, the last cached copy is used; if there
is none, that feed is skipped and the analysis still runs. A feed problem never
crashes an analysis.

Matching is deliberately conservative, because a false "known phishing" verdict on a
legitimate link is worse than a miss:

  * Dedicated domains (evil-bank-login.com): a link matches if its host, or any parent
    domain of its host, is listed — so login.evil-bank-login.com is caught.
  * Shared platforms (sites.google.com, *.github.io, IPFS gateways, S3 endpoints...):
    these host both legitimate and malicious content, so only an exact listed host
    (abc123.github.io) or, for URL feeds, an exact listed URL, ever matches. The bare
    platform entries that some lists contain are dropped. Listing one tenant never
    flags the whole platform.
"""
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_CACHE_DIR = Path.home() / ".phishguard" / "feeds"
USER_AGENT = "PhishGuard/2.0 (+https://github.com/AlexPhilip01/PhishGuard)"
MAX_FEED_BYTES = 120 * 1024 * 1024  # refuse absurdly large responses

FEED_SOURCES = {
    "phishing-database": {
        "label": "Phishing.Database (active domains)",
        "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "kind": "domains",
        "max_age_hours": 6.0,
    },
    "openphish": {
        "label": "OpenPhish community feed",
        "url": "https://openphish.com/feed.txt",
        "kind": "urls",
        "max_age_hours": 12.0,
    },
}

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")

# Hosting platforms where one hostname serves many unrelated tenants. A bare entry for
# one of these in a feed must never flag the whole platform.
SHARED_PLATFORM_SUFFIXES = (
    "sites.google.com", "storage.googleapis.com", "docs.google.com", "drive.google.com",
    "forms.gle", "github.io", "githubusercontent.com", "gitlab.io", "pages.dev", "workers.dev",
    "r2.dev", "netlify.app", "vercel.app", "web.app", "firebaseapp.com", "herokuapp.com",
    "onrender.com", "glitch.me", "repl.co", "replit.app", "000webhostapp.com", "weebly.com",
    "wixsite.com", "blogspot.com", "wordpress.com", "typedream.app", "carrd.co", "webflow.io",
    "dweb.link", "ipfs.io", "cf-ipfs.com", "cloudflare-ipfs.com", "nftstorage.link", "w3s.link",
    "infura-ipfs.io", "filesusr.com", "plesk.page", "edgeone.app", "amazonaws.com",
    "digitaloceanspaces.com", "appdomain.cloud", "azurewebsites.net", "windows.net",
    "cloudfront.net", "bit.ly", "t.co", "tinyurl.com",
)

# Region/service endpoints of object storage — hosts that thousands of legitimate
# buckets sit behind, even though the endpoint name itself can show up in a feed.
_PLATFORM_ENDPOINT_PATTERNS = (
    re.compile(r"^s3[.-][a-z0-9-]+\.amazonaws\.com$"),
    re.compile(r"^s3\.amazonaws\.com$"),
    re.compile(r"^[a-z0-9-]+\.digitaloceanspaces\.com$"),
    re.compile(r"^s3\.[a-z0-9-]+\.cloud-object-storage\.appdomain\.cloud$"),
)

# A listed entry that is the parent of this many other listed entries is almost
# certainly a multi-tenant platform or a wildcard-spam zone, not a single bad domain.
HUB_CHILD_THRESHOLD = 500

_SECOND_LEVEL_LABELS = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"}
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# --------------------------------------------------------------------------- URLs

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


def _host_of(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def normalize_url(url: str) -> str:
    """Canonical form for exact-URL comparison (case-insensitive scheme/host, no fragment)."""
    try:
        p = urlparse(url.strip())
    except ValueError:
        return url.strip()
    path = p.path if p.path not in ("", "/") else ""
    query = f"?{p.query}" if p.query else ""
    return f"{p.scheme.lower()}://{p.netloc.lower()}{path}{query}".rstrip("/")


def is_platform_host(host: str) -> bool:
    """True if `host` is, or sits under, a shared hosting platform."""
    if any(p.match(host) for p in _PLATFORM_ENDPOINT_PATTERNS):
        return True
    return any(host == s or host.endswith("." + s) for s in SHARED_PLATFORM_SUFFIXES)


def _is_platform_root(host: str) -> bool:
    """True for a bare platform entry (sites.google.com, dweb.link, an S3 endpoint)."""
    if host in SHARED_PLATFORM_SUFFIXES:
        return True
    return any(p.match(host) for p in _PLATFORM_ENDPOINT_PATTERNS)


def _candidate_hosts(host: str) -> list:
    """Host plus parent domains to look up — never walking above the registrable domain."""
    if not host:
        return []
    if _IPV4.match(host) or is_platform_host(host):
        return [host]
    labels = host.split(".")
    min_labels = 3 if (len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL_LABELS) else 2
    return [".".join(labels[i:]) for i in range(0, max(len(labels) - min_labels, 0) + 1)]


# ------------------------------------------------------------------------- index

class FeedIndex:
    """In-memory lookup built from one or more feeds."""

    def __init__(self):
        self.hosts = {}   # dedicated host -> source name
        self.urls = {}    # normalized exact URL -> source name
        self.info = {}    # source name -> {"status", "count", "dropped", ...}

    def add_domains(self, source: str, entries) -> dict:
        cleaned = []
        for line in entries:
            d = line.strip().lower().rstrip(".")
            # skip blanks, comments, and malformed entries (paths, ports, credentials)
            if not d or d.startswith("#") or any(c in d for c in "/ :@"):
                continue
            cleaned.append(d)
        listed = set(cleaned)

        children = {}
        for d in listed:
            labels = d.split(".")
            for i in range(1, len(labels) - 1):
                parent = ".".join(labels[i:])
                if parent in listed:
                    children[parent] = children.get(parent, 0) + 1

        dropped = 0
        for d in listed:
            if _is_platform_root(d) or children.get(d, 0) >= HUB_CHILD_THRESHOLD:
                dropped += 1
                continue
            self.hosts.setdefault(d, source)
        return {"count": len(listed) - dropped, "dropped": dropped}

    def add_urls(self, source: str, entries) -> dict:
        count = 0
        for line in entries:
            u = line.strip()
            if not u or u.startswith("#") or "://" not in u:
                continue
            self.urls.setdefault(normalize_url(u), source)
            host = _host_of(u)
            if host and not is_platform_host(host):
                self.hosts.setdefault(host, source)  # dedicated host: also catch other paths
            count += 1
        return {"count": count, "dropped": 0}

    def match(self, url: str):
        """Returns a match dict, or None. See module docstring for the matching rules."""
        exact = self.urls.get(normalize_url(url))
        if exact:
            return {"url": url, "source": exact, "kind": "url", "matched": normalize_url(url)}
        host = _host_of(url)
        if not host:
            return None
        candidates = _candidate_hosts(host)
        if host.startswith("www."):
            candidates = candidates + _candidate_hosts(host[4:])
        else:
            candidates = candidates + ["www." + host]
        for cand in candidates:
            src = self.hosts.get(cand)
            if src:
                return {"url": url, "source": src, "kind": "host" if cand == host else "parent-domain", "matched": cand}
        return None

    def match_all(self, urls) -> list:
        return [m for m in (self.match(u) for u in urls) if m]

    @property
    def total(self) -> int:
        return len(self.hosts) + len(self.urls)


# ----------------------------------------------------------------------- download

def _http_get(url: str, etag=None, timeout: float = 30.0):
    """Returns (status, text_or_None, etag). status 304 means 'unchanged'. Raises on failure."""
    headers = {"User-Agent": USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_FEED_BYTES + 1)
            if len(raw) > MAX_FEED_BYTES:
                raise OSError("feed larger than the allowed maximum")
            return 200, raw.decode("utf-8", errors="ignore"), resp.headers.get("ETag")
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return 304, None, etag
        raise


def _paths(cache_dir: Path, name: str):
    return cache_dir / f"{name}.txt", cache_dir / f"{name}.meta.json"


def _read_meta(meta_path: Path) -> dict:
    try:
        return json.loads(meta_path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def load_source(name: str, cache_dir: Path = DEFAULT_CACHE_DIR, force: bool = False,
                timeout: float = 30.0, http_get=None):
    """
    Returns (lines, status) for one feed. status is one of:
      "fresh"    - just downloaded
      "cached"   - cache still within max age, or the server confirmed it is unchanged
      "stale"    - download failed; an older cached copy was used
      "offline"  - download failed and no cache exists (lines is empty)
    Never raises.
    """
    http_get = http_get or _http_get
    spec = FEED_SOURCES[name]
    cache_dir = Path(cache_dir)
    data_path, meta_path = _paths(cache_dir, name)
    meta = _read_meta(meta_path)
    have_cache = data_path.exists() and meta.get("fetched_at")
    age = time.time() - meta.get("fetched_at", 0) if have_cache else None

    def _cached_lines():
        return data_path.read_text(encoding="utf-8", errors="ignore").splitlines()

    if have_cache and not force and age < spec["max_age_hours"] * 3600:
        try:
            return _cached_lines(), "cached"
        except OSError:
            have_cache = False

    try:
        status, text, etag = http_get(spec["url"], etag=meta.get("etag") if have_cache else None, timeout=timeout)
        cache_dir.mkdir(parents=True, exist_ok=True)
        if status == 304 and have_cache:
            meta["fetched_at"] = time.time()
            _write_atomic(meta_path, json.dumps(meta))
            return _cached_lines(), "cached"
        _write_atomic(data_path, text)
        _write_atomic(meta_path, json.dumps({"fetched_at": time.time(), "etag": etag}))
        return text.splitlines(), "fresh"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        if have_cache:
            try:
                return _cached_lines(), "stale"
            except OSError:
                pass
        return [], "offline"


def build_index(sources=None, cache_dir: Path = DEFAULT_CACHE_DIR, force: bool = False,
                timeout: float = 30.0, http_get=None):
    """
    Loads the chosen feeds (default: all) into a FeedIndex.
    Returns (index, statuses) where statuses maps source name -> {"status", "count", "dropped", "label"}.
    """
    index = FeedIndex()
    statuses = {}
    for name in (sources or list(FEED_SOURCES)):
        if name not in FEED_SOURCES:
            raise ValueError(f"unknown feed '{name}' (choose from: {', '.join(FEED_SOURCES)})")
        lines, status = load_source(name, cache_dir, force=force, timeout=timeout, http_get=http_get)
        stats = (index.add_domains if FEED_SOURCES[name]["kind"] == "domains" else index.add_urls)(name, lines)
        statuses[name] = {"status": status, "label": FEED_SOURCES[name]["label"], **stats}
        index.info[name] = statuses[name]
    return index, statuses


# ------------------------------------------------------------ simple URL-list helper

def check_urls_against_feed(urls: list, feed_urls: list) -> list:
    """
    Convenience wrapper: match `urls` against a plain list of known-bad URLs and return
    the matching URLs. Uses the same conservative rules as FeedIndex.
    """
    if not urls or not feed_urls:
        return []
    index = FeedIndex()
    index.add_urls("list", feed_urls)
    return [m["url"] for m in index.match_all(urls)]
