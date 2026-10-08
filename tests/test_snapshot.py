"""Tests for the compact browser snapshot (phishguard.snapshot)."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishguard import snapshot  # noqa: E402

DOMAINS = ["evil-bank-login.com", "paypa1-secure.top", "sites.google.com", "abc123.github.io"]


def fake_get(url, etag=None, timeout=30.0):
    return 200, "# comment\n" + "\n".join(DOMAINS) + "\n", "etag1"


def build(tmp_path, **kw):
    return snapshot.build_snapshot(tmp_path / "out", cache_dir=tmp_path / "cache",
                                   http_get=fake_get, min_entries=1, **kw)


def test_snapshot_files_are_sorted_fingerprints(tmp_path):
    meta = build(tmp_path)
    blob = (tmp_path / "out" / snapshot.BIN_NAME).read_bytes()
    records = [blob[i:i + 5] for i in range(0, len(blob), 5)]
    assert len(blob) % 5 == 0 and records == sorted(records)
    assert len(records) == meta["entries"] == 3          # bare platform root sites.google.com dropped
    assert snapshot.fingerprint("h", "evil-bank-login.com") in records
    assert snapshot.fingerprint("h", "abc123.github.io") in records
    assert snapshot.fingerprint("h", "sites.google.com") not in records


def test_meta_carries_matching_rules_and_status(tmp_path):
    build(tmp_path)
    meta = json.loads((tmp_path / "out" / snapshot.META_NAME).read_text())
    assert meta["hash_bytes"] == 5 and meta["sources"]["phishing-database"]["status"] == "fresh"
    assert "github.io" in meta["rules"]["platform_suffixes"]
    assert meta["rules"]["platform_endpoint_patterns"] and "co" in meta["rules"]["second_level_labels"]


def test_refuses_to_publish_a_tiny_snapshot(tmp_path):
    with pytest.raises(RuntimeError, match="refusing to publish"):
        snapshot.build_snapshot(tmp_path / "out", cache_dir=tmp_path / "cache", http_get=fake_get)


def test_refuses_to_publish_when_feed_is_offline(tmp_path):
    def down(url, etag=None, timeout=30.0):
        raise OSError("network down")
    with pytest.raises(RuntimeError, match="not fresh"):
        snapshot.build_snapshot(tmp_path / "out", cache_dir=tmp_path / "cache",
                                http_get=down, min_entries=1)
    assert not (tmp_path / "out" / snapshot.BIN_NAME).exists()
