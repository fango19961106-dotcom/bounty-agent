"""測試深化引擎"""
import random

from agent.deepen import (builder_derivation, find_contradiction_candidates,
                          lifecycle_audit, pick_lifecycle_item)
from agent.labels import Evidence, ModelStore

EV = Evidence(source="x", excerpt="y")


def _store_with_descriptions():
    s = ModelStore()
    s.add_obs("插件只能讀取當前文件 doc token", EV, "D1_doc")
    s.add_obs("fetchDocument 只檢查 token 無檢查 doc 歸屬", EV, "D2_code")
    s.add_obs("健康檢查 endpoint 返回 pong", EV, "D3_traffic")
    return s


def test_contradiction_candidates_cross_description():
    s = _store_with_descriptions()
    cands = find_contradiction_candidates(s, min_shared=2)
    assert any("D1_doc" in c.reason and "D2_code" in c.reason for c in cands)


def test_no_candidates_when_disjoint_topics():
    s = ModelStore()
    s.add_obs("文檔講 OAuth 流程", EV, "D1_doc")
    s.add_obs("流量見到 PNG 圖片", EV, "D3_traffic")
    assert find_contradiction_candidates(s, min_shared=2) == []


def test_builder_derivation_without_actual():
    r = builder_derivation("login", "預測有 CSRF token", None, judge=None)
    assert not r.matched
    assert "recon" in r.note


def test_lifecycle_audit_finds_gaps():
    gaps = lifecycle_audit("session token", covered_stages=["簽發", "驗證"])
    assert "撤銷" in gaps and "刪除後" in gaps
    assert "簽發" not in gaps


def test_pick_lifecycle_item():
    s = _store_with_descriptions()
    item = pick_lifecycle_item(s, rng=random.Random(42))
    assert item is not None
    empty = ModelStore()
    assert pick_lifecycle_item(empty) is None
