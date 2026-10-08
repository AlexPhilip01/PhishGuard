"""
Compact browser snapshot of the live threat feeds.

The website can't download an 11 MB domain list on every visit, so a scheduled job
(see .github/workflows/update-feeds.yml) runs `phishguard build-snapshot` and publishes:

  phishguard-feed.bin   sorted 5-byte truncated SHA-256 fingerprints, one per listed
                        host ("h:<host>") or exact URL ("u:<normalized url>").
                        ~2 MB for ~400k entries. Only fingerprints are shipped, never the
                        list itself.
  feed-meta.json        build time, per-source counts/status, and the matching rules
                        (shared-platform suffixes etc.) so the browser applies exactly
                        the same conservative rules as the Python tool.

A 40-bit fingerprint gives roughly a 1-in-a-million chance of a random false match per
lookup at this list size — acceptable for a hint that is clearly labelled as such.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from . import threat_feed

HASH_BYTES = 5
BIN_NAME = "phishguard-feed.bin"
META_NAME = "feed-meta.json"
SNAPSHOT_DEFAULT_FEEDS = ["phishing-database"]  # OpenPhish is non-commercial: opt-in only
MIN_ENTRIES = 50_000  # refuse to publish a suspiciously small snapshot over a good one


def fingerprint(kind: str, value: str) -> bytes:
    """kind is 'h' (host) or 'u' (normalized URL). Mirrored exactly in index.html."""
    return hashlib.sha256(f"{kind}:{value}".encode("utf-8")).digest()[:HASH_BYTES]


def build_snapshot(out_dir, sources=None, cache_dir=threat_feed.DEFAULT_CACHE_DIR,
                   force=True, http_get=None, min_entries=MIN_ENTRIES) -> dict:
    """Builds the snapshot files in out_dir and returns the metadata dict."""
    sources = sources or SNAPSHOT_DEFAULT_FEEDS
    index, statuses = threat_feed.build_index(sources, cache_dir=cache_dir, force=force, http_get=http_get)

    bad = [n for n, s in statuses.items() if s["status"] in ("stale", "offline")]
    if bad:
        raise RuntimeError(f"feed(s) not fresh, refusing to publish: {', '.join(bad)}")
    if index.total < min_entries:
        raise RuntimeError(f"only {index.total} entries (minimum {min_entries}); refusing to publish")

    prints = {fingerprint("h", h) for h in index.hosts}
    prints |= {fingerprint("u", u) for u in index.urls}
    blob = b"".join(sorted(prints))

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / BIN_NAME).write_bytes(blob)

    meta = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hash_bytes": HASH_BYTES,
        "entries": len(prints),
        "sources": {n: {"label": s["label"], "status": s["status"], "count": s["count"],
                        "dropped": s.get("dropped", 0)} for n, s in statuses.items()},
        "rules": {
            "platform_suffixes": list(threat_feed.SHARED_PLATFORM_SUFFIXES),
            "platform_endpoint_patterns": [p.pattern for p in threat_feed._PLATFORM_ENDPOINT_PATTERNS],
            "second_level_labels": sorted(threat_feed._SECOND_LEVEL_LABELS),
        },
    }
    (out / META_NAME).write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
    return meta
