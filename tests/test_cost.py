"""測試成本軸"""
from agent.cost import CostTracker


def test_cost_calculation():
    t = CostTracker(price_in_per_1m=3.0, price_out_per_1m=15.0)
    t.record(1, tokens_in=1_000_000, tokens_out=100_000)
    assert abs(t.cost_usd(1) - (3.0 + 1.5)) < 1e-9


def test_abandon_gate():
    t = CostTracker(price_in_per_1m=3.0, price_out_per_1m=15.0)
    t.record(1, tokens_out=1_000_000)   # $15
    assert t.should_abandon(1, expected_bounty=50, max_ratio=0.2)    # $15 > $10
    assert not t.should_abandon(1, expected_bounty=5000, max_ratio=0.2)


def test_zero_bounty_never_abandons():
    t = CostTracker()
    t.record(1, tokens_out=10_000_000)
    assert not t.should_abandon(1, expected_bounty=0)


def test_total():
    t = CostTracker()
    t.record(1, tokens_in=1_000_000)
    t.record(2, tokens_in=1_000_000)
    assert abs(t.total_usd() - 6.0) < 1e-9
