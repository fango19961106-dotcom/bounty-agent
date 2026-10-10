"""測試標籤制度同幻覺防火牆"""
import pytest

from agent.labels import Evidence, Label, ModelStore


EV = Evidence(source="burp:req#1", excerpt="HTTP/1.1 200 OK")


def test_obs_without_evidence_auto_downgrades_to_hyp():
    s = ModelStore()
    st = s.add_obs("個 endpoint 會反射輸入", evidence=None)
    assert st.label is Label.HYP   # 無證據 → 自動降級


def test_obs_with_evidence_stays_obs():
    s = ModelStore()
    st = s.add_obs("個 endpoint 會反射輸入", evidence=EV, description="D3_traffic")
    assert st.label is Label.OBS


def test_inf_must_depend_on_existing_obs():
    s = ModelStore()
    with pytest.raises(ValueError):
        s.add_inf("所以呢度有 XSS", depends_on=[999])
    obs = s.add_obs("反射", evidence=EV)
    with pytest.raises(ValueError):
        s.add_inf("推斷依賴 HYP", depends_on=[s.add_obs("無證據", None).id])
    inf = s.add_inf("所以呢度有 XSS", depends_on=[obs.id])
    assert inf.label is Label.INF


def test_hyp_cannot_enter_description_files():
    s = ModelStore()
    hyp = s.add_hyp("或者可以越權", predicted_signal="200 而非 403")
    with pytest.raises(ValueError):
        s._register(hyp, "D1_doc")


def test_invalidate_obs_marks_downstream_for_review():
    s = ModelStore()
    o1 = s.add_obs("觀察A", evidence=EV)
    i1 = s.add_inf("推斷B", depends_on=[o1.id])
    affected = s.invalidate_obs(o1.id, "發現係幻覺：從未發過呢個 request")
    assert i1.id in affected
    assert s.statements[i1.id].needs_review
    assert len(s.hallucination_log) == 1
    assert s.hallucination_rate() > 0


def test_hallucination_rate_zero_when_clean():
    s = ModelStore()
    s.add_obs("真觀察", evidence=EV)
    assert s.hallucination_rate() == 0.0
