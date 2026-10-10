"""測試泳道狀態機同 Orchestrator"""
import pytest

from agent.scope import ScopeGate
from agent.workflow import (MAX_CONSECUTIVE_FAILURES, MAX_LANES,
                            Orchestrator, Phase)


def _orch():
    return Orchestrator(ScopeGate())


def test_legal_transitions():
    o = _orch()
    lane = o.open_lane("copilot.microsoft.com")
    lane.transition(Phase.DEEPEN)
    lane.transition(Phase.FIND_GAPS)
    lane.transition(Phase.PROBE)
    lane.transition(Phase.VERIFYING)
    lane.transition(Phase.REPORT)
    lane.transition(Phase.DONE)
    assert lane.phase is Phase.DONE


def test_illegal_transition_rejected():
    o = _orch()
    lane = o.open_lane("x")
    with pytest.raises(ValueError):
        lane.transition(Phase.REPORT)   # BUILD_MODEL → REPORT 非法


def test_max_lanes_enforced():
    o = _orch()
    for i in range(MAX_LANES):
        o.open_lane(f"target{i}")
    with pytest.raises(RuntimeError):
        o.open_lane("target-over")


def test_lane_frees_up_when_done():
    o = _orch()
    lanes = [o.open_lane(f"t{i}") for i in range(MAX_LANES)]
    lanes[0].transition(Phase.DEEPEN)
    lanes[0].transition(Phase.DONE)
    o.open_lane("new-target")   # 唔應該拋錯


def test_consecutive_failures_force_done():
    o = _orch()
    lane = o.open_lane("azure.portal")
    for _ in range(MAX_CONSECUTIVE_FAILURES):
        lane.record_failure()
    assert lane.phase is Phase.DONE


def test_stale_lane_deprioritized():
    o = _orch()
    fresh = o.open_lane("fresh")
    stale = o.open_lane("stale")
    stale.last_signal_ts -= 49 * 3600   # 49 小時無訊號
    order = o.standup_order()
    assert order[0].target == "fresh"
    assert stale.priority() < fresh.priority()


def test_kpi_snapshot():
    o = _orch()
    o.open_lane("t")
    o.record_prediction(True)
    o.record_prediction(False)
    o.model_corrections = 3
    kpi = o.kpi()
    assert kpi.prediction_accuracy == 0.5
    assert kpi.model_corrections == 3
    assert kpi.hallucination_rate == 0.0
