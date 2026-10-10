"""測試 ModelStore 持久化"""
from agent.labels import Evidence, Label, ModelStore
from agent.persist import load_store, save_store

EV = Evidence(source="burp:req#1", excerpt="200 OK")


def test_roundtrip(tmp_path):
    s = ModelStore()
    o1 = s.add_obs("觀察A", EV, "D1_doc")
    i1 = s.add_inf("推斷B", [o1.id])
    s.add_hyp("假設C", "訊號")
    s.invalidate_obs(o1.id, "幻覺")
    p = tmp_path / "store.json"
    save_store(s, p)

    s2 = load_store(p)
    assert s2.statements[o1.id].label is Label.OBS
    assert s2.statements[i1.id].needs_review          # 待覆核標記保留
    assert s2.descriptions["D1_doc"] == [o1.id]
    assert len(s2.hallucination_log) == 1


def test_id_counter_continues_after_load(tmp_path):
    s = ModelStore()
    s.add_obs("A", EV)
    p = tmp_path / "s.json"
    save_store(s, p)
    s2 = load_store(p)
    new = s2.add_obs("B", EV)
    assert new.id > 1   # 唔會重用舊 id
