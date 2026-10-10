"""workflow.py — 並行泳道狀態機 + KPI + 主循環

泳道狀態機：BUILD_MODEL → DEEPEN → FIND_GAPS → PROBE → VERIFYING → REPORT → COOLING/DONE
- 最多 3 條泳道並行
- 同一目標連續 10 個假設失敗 → 強制 DONE（防沉沒成本）
- 48h 無訊號 → 自動降權
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

from .labels import ModelStore, Statement
from .scope import ScopeGate


class Phase(Enum):
    BUILD_MODEL = "BUILD_MODEL"
    DEEPEN = "DEEPEN"
    FIND_GAPS = "FIND_GAPS"
    PROBE = "PROBE"
    VERIFYING = "VERIFYING"     # 三重驗證閘
    REPORT = "REPORT"           # 等待人類批准提交
    COOLING = "COOLING"         # backoff
    DONE = "DONE"


# 合法嘅狀態轉移（fail-closed：唔喺表入面嘅轉移一律拒絕）
TRANSITIONS: dict[Phase, set[Phase]] = {
    Phase.BUILD_MODEL: {Phase.DEEPEN, Phase.DONE},
    Phase.DEEPEN: {Phase.FIND_GAPS, Phase.BUILD_MODEL, Phase.DONE},
    Phase.FIND_GAPS: {Phase.PROBE, Phase.DEEPEN, Phase.DONE},
    Phase.PROBE: {Phase.VERIFYING, Phase.DEEPEN, Phase.FIND_GAPS, Phase.COOLING, Phase.DONE},
    Phase.VERIFYING: {Phase.REPORT, Phase.DEEPEN},
    Phase.REPORT: {Phase.DONE, Phase.DEEPEN},
    Phase.COOLING: {Phase.PROBE, Phase.DONE},
    Phase.DONE: set(),
}

MAX_CONSECUTIVE_FAILURES = 10
MAX_LANES = 3


@dataclass
class Lane:
    """一條泳道 = 一個目標嘅獨立狀態機。"""
    target: str
    store: ModelStore = field(default_factory=ModelStore)
    phase: Phase = Phase.BUILD_MODEL
    hypotheses: list[Statement] = field(default_factory=list)
    consecutive_failures: int = 0
    last_signal_ts: float = field(default_factory=time.time)
    findings_count: int = 0

    def transition(self, to: Phase) -> None:
        if to not in TRANSITIONS[self.phase]:
            raise ValueError(f"[狀態機] {self.target}: {self.phase.value} → {to.value} 係非法轉移")
        self.phase = to

    def record_signal(self) -> None:
        self.last_signal_ts = time.time()

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            self.phase = Phase.DONE   # 強制轉場（防沉沒成本）

    def priority(self) -> float:
        """有最新訊號嘅泳道優先；48h 無訊號自動降權。"""
        if self.phase is Phase.DONE:
            return -1.0
        hours_idle = (time.time() - self.last_signal_ts) / 3600
        return 100.0 - hours_idle - (10.0 if hours_idle > 48 else 0.0)


@dataclass
class KpiSnapshot:
    prediction_accuracy: float     # 預測訊號命中率
    hallucination_rate: float      # 幻覺率
    model_corrections: int         # 模型修正次數
    contradictions_found: int      # 矛盾狩獵收穫
    reusable_patterns: int         # 可重用信任邊界模式
    total_cost_usd: float = 0.0    # 成本軸：總燒咗幾多錢


class Orchestrator:
    """泳道管理器：並行上限、優先級重排、每日 standup。"""

    def __init__(self, scope_gate: ScopeGate, cost_tracker=None) -> None:
        self.scope_gate = scope_gate
        self.cost_tracker = cost_tracker   # agent.cost.CostTracker（可選）
        self.lanes: list[Lane] = []
        self.model_corrections = 0
        self.contradictions = 0
        self.reusable_patterns = 0
        self._pred_total = 0
        self._pred_hit = 0

    def open_lane(self, target: str) -> Lane:
        active = [l for l in self.lanes if l.phase is not Phase.DONE]
        if len(active) >= MAX_LANES:
            raise RuntimeError(f"[泳道] 已達並行上限 {MAX_LANES}，完成或放棄一條先")
        lane = Lane(target)
        self.lanes.append(lane)
        return lane

    def standup_order(self) -> list[Lane]:
        """每日重排優先級：回傳按 priority 排序嘅活躍泳道。"""
        return sorted((l for l in self.lanes if l.phase is not Phase.DONE),
                      key=lambda l: l.priority(), reverse=True)

    def record_prediction(self, hit: bool) -> None:
        self._pred_total += 1
        if hit:
            self._pred_hit += 1

    def kpi(self) -> KpiSnapshot:
        total_h_rate = max((l.store.hallucination_rate() for l in self.lanes), default=0.0)
        return KpiSnapshot(
            prediction_accuracy=self._pred_hit / self._pred_total if self._pred_total else 0.0,
            hallucination_rate=total_h_rate,
            model_corrections=self.model_corrections,
            contradictions_found=self.contradictions,
            reusable_patterns=self.reusable_patterns,
            total_cost_usd=self.cost_tracker.total_usd() if self.cost_tracker else 0.0,
        )
