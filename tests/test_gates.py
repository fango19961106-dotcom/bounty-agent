"""測試三重驗證閘"""
from agent.gates import (ADVERSARIAL_QUESTIONS, Finding, TripleGate)
from agent.labels import Evidence, ModelStore

EV = Evidence(source="burp:req#7", excerpt="Location: /admin")


def _good_finding(store):
    obs = store.add_obs("未授權訪問 /admin 返回 200", evidence=EV)
    return Finding(
        title="IDOR in /admin",
        repro_steps=["登入低權帳號", "GET /admin", "觀察 200"],
        observation_ids=[obs.id],
        poc_artifacts=["poc_001/video.mp4"],
        reproductions=3,
    )


def _rebuttals():
    return {q: f"實驗回應：{q[:10]}…（已用對照實驗排除）" for q in ADVERSARIAL_QUESTIONS}


def _runner_ok(steps):
    return (len(steps) >= 2, "步驟太少" if len(steps) < 2 else "")


def test_all_gates_pass():
    store = ModelStore()
    f = _good_finding(store)
    ok, reports = TripleGate().run(f, store, _rebuttals(), _runner_ok)
    assert ok, [r.issues for r in reports]


def test_evidence_gate_blocks_low_reproduction():
    store = ModelStore()
    f = _good_finding(store)
    f.reproductions = 1   # 假裝重現（H4）
    ok, reports = TripleGate().run(f, store, _rebuttals(), _runner_ok)
    assert not ok
    assert any("重現次數" in i for i in reports[0].issues)


def test_evidence_gate_blocks_hyp_reference():
    store = ModelStore()
    hyp = store.add_hyp("或者有 IDOR", predicted_signal="200")
    f = Finding(title="x", repro_steps=["a", "b"], observation_ids=[hyp.id],
                poc_artifacts=["v.mp4"], reproductions=3)
    ok, reports = TripleGate().run(f, store, _rebuttals(), _runner_ok)
    assert not ok
    assert any("HYP" in i for i in reports[0].issues)


def test_adversarial_gate_requires_all_rebuttals():
    store = ModelStore()
    f = _good_finding(store)
    partial = {ADVERSARIAL_QUESTIONS[0]: "只答咗一條"}
    ok, reports = TripleGate().run(f, store, partial, _runner_ok)
    assert not ok
    assert len(reports[1].issues) == len(ADVERSARIAL_QUESTIONS) - 1


def test_blank_gate_blocks_bad_repro():
    store = ModelStore()
    f = _good_finding(store)
    ok, reports = TripleGate().run(f, store, _rebuttals(), lambda steps: (False, "第2步跟唔到"))
    assert not ok
    assert "空白重現失敗" in reports[2].issues[0]
