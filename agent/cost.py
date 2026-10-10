"""cost.py — 成本軸 KPI + 成本閘口（P1）

冇成本概念嘅 agent 會燒 $50 追一個上限 $250 嘅 Moderate 級漏洞。
每個假設追蹤 token / API call / wall-clock，超過閘值自動棄。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class HypothesisCost:
    hyp_id: int
    tokens_in: int = 0
    tokens_out: int = 0
    api_calls: int = 0
    started_at: float = field(default_factory=time.time)

    def wall_hours(self) -> float:
        return (time.time() - self.started_at) / 3600


class CostTracker:
    """成本追蹤 + 閘口。價格預設值可按實際 LLM 定價調整。"""

    def __init__(self, price_in_per_1m: float = 3.0,
                 price_out_per_1m: float = 15.0) -> None:
        self.price_in = price_in_per_1m
        self.price_out = price_out_per_1m
        self._costs: dict[int, HypothesisCost] = {}

    def open(self, hyp_id: int) -> None:
        self._costs[hyp_id] = HypothesisCost(hyp_id)

    def record(self, hyp_id: int, tokens_in: int = 0,
               tokens_out: int = 0, api_calls: int = 0) -> None:
        c = self._costs.setdefault(hyp_id, HypothesisCost(hyp_id))
        c.tokens_in += tokens_in
        c.tokens_out += tokens_out
        c.api_calls += api_calls

    def cost_usd(self, hyp_id: int) -> float:
        c = self._costs.get(hyp_id)
        if not c:
            return 0.0
        return (c.tokens_in / 1e6 * self.price_in
                + c.tokens_out / 1e6 * self.price_out)

    def should_abandon(self, hyp_id: int, expected_bounty: float,
                       max_ratio: float = 0.2) -> bool:
        """成本閘口：已燒成本超過期望獎金嘅 max_ratio（預設 20%）→ 建議棄。"""
        if expected_bounty <= 0:
            return False
        return self.cost_usd(hyp_id) > expected_bounty * max_ratio

    def total_usd(self) -> float:
        return sum(self.cost_usd(h) for h in self._costs)

    def report(self) -> dict[int, float]:
        return {h: round(self.cost_usd(h), 4) for h in self._costs}
