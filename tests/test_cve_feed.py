"""測試 CVE 變種分析模組"""
import pytest

from agent.cve_feed import (CveFeed, CveQuality, CveRecord, VARIANT_ANGLES,
                            derive_variant_hypotheses, ingest_cve)
from agent.labels import Label, ModelStore


def _gold_cve():
    return CveRecord(
        cve_id="CVE-2026-12345",
        product="azure",
        root_cause="Missing length check in packet parser leads to OOB read",
        commit_ref="abc123def",
        error_pattern="missing length check",
        in_scope_products=("azure",),
    )


def test_gold_cve_quality():
    assert _gold_cve().quality() is CveQuality.GOLD


def test_silver_when_no_commit():
    c = _gold_cve()
    c.commit_ref = ""
    assert c.quality() is CveQuality.SILVER


def test_skip_out_of_scope():
    c = _gold_cve()
    c.in_scope_products = ("chrome",)
    assert c.quality() is CveQuality.SKIP


def test_skip_hot_cve():
    c = _gold_cve()
    c.hot = True
    assert c.quality() is CveQuality.SKIP   # 明星 CVE 紅海


def test_skip_no_root_cause():
    c = _gold_cve()
    c.root_cause = ""
    assert c.quality() is CveQuality.SKIP


def test_ingest_writes_d2_obs_with_cve_pointer():
    s = ModelStore()
    stmts = ingest_cve(s, _gold_cve())
    assert len(stmts) == 2   # root cause + error pattern
    assert all(st.label is Label.OBS for st in stmts)
    assert all(st.evidence.source.startswith("cve:CVE-2026-12345") for st in stmts)
    assert len(s.descriptions["D2_code"]) == 2


def test_variant_hypotheses_have_three_angles():
    s = ModelStore()
    hyps = derive_variant_hypotheses(s, _gold_cve())
    assert len(hyps) == len(VARIANT_ANGLES)
    assert all(h.label is Label.HYP for h in hyps)
    assert all("預測訊號" in h.text for h in hyps)


def test_feed_process_and_stats():
    feed = CveFeed()
    s = ModelStore()
    hyps = feed.process(s, _gold_cve())
    assert len(hyps) == 3
    feed.process(s, CveRecord(cve_id="CVE-2026-99999", product="x",
                              root_cause="", in_scope_products=("x",)))
    assert feed.stats.ingested == 1
    assert feed.stats.skipped == 1
    assert feed.stats.gold == 1


def test_invalid_cve_id_rejected():
    feed = CveFeed()
    with pytest.raises(ValueError):
        feed.process(ModelStore(), CveRecord(cve_id="NOT-A-CVE",
                                             product="azure", root_cause="x"))
