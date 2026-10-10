"""測試 scope 白名單刷新（fail-closed）"""
import json
import time

from agent.scope_refresh import ScopeRefresher


def test_missing_file_returns_none(tmp_path):
    r = ScopeRefresher(tmp_path / "nope.json")
    assert r.load() is None


def test_valid_snapshot(tmp_path):
    p = tmp_path / "scope.json"
    ScopeRefresher.write_snapshot(["microsoft.com", "google.com"], p)
    r = ScopeRefresher(p)
    assert r.load() == ["microsoft.com", "google.com"]


def test_stale_snapshot_returns_none(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"fetched_at": time.time() - 25 * 3600,
                             "domains": ["microsoft.com"]}))
    r = ScopeRefresher(p, max_age_hours=24)
    assert r.load() is None   # 過期 = fail-closed


def test_corrupt_file_returns_none(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text("not json{{{")
    assert ScopeRefresher(p).load() is None


def test_empty_domains_returns_none(tmp_path):
    p = tmp_path / "scope.json"
    ScopeRefresher.write_snapshot([], p)
    assert ScopeRefresher(p).load() is None
