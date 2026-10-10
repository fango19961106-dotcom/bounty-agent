"""測試 fail-closed scope 閘"""
import time

from agent.scope import RateLimiter, ScopeGate, Verdict


def test_fail_closed_when_whitelist_not_refreshed():
    g = ScopeGate()
    r = g.pre_request("example.microsoft.com", "researcher-MSOBB-01")
    assert r.verdict is Verdict.HARD_REJECT
    assert "fail-closed" in r.reason


def test_refresh_failure_closes_gate():
    g = ScopeGate()
    assert g.refresh_whitelist(["example.com"]) is True
    assert g.refresh_whitelist(None) is False   # 刷新失敗
    r = g.pre_request("example.com", "researcher-MSOBB-01")
    assert r.verdict is Verdict.HARD_REJECT


def test_out_of_scope_rejected():
    g = ScopeGate()
    g.refresh_whitelist(["microsoft.com"])
    r = g.pre_request("evil.com", "researcher-MSOBB-01")
    assert r.verdict is Verdict.HARD_REJECT
    assert "唔喺 scope" in r.reason


def test_subdomain_in_scope():
    g = ScopeGate()
    g.refresh_whitelist(["microsoft.com"])
    r = g.pre_request("portal.microsoft.com", "researcher-MSOBB-01")
    assert r.verdict is Verdict.ALLOW


def test_account_without_msobb_rejected():
    g = ScopeGate()
    g.refresh_whitelist(["microsoft.com"])
    r = g.pre_request("microsoft.com", "normal-user")
    assert r.verdict is Verdict.HARD_REJECT
    assert "MSOBB" in r.reason


def test_rate_limit_and_backoff():
    rl = RateLimiter(max_rps=1000)   # 高速率避免 test 慢
    assert rl.check("a.com").verdict is Verdict.ALLOW
    for _ in range(3):
        rl.report_block("a.com")
    r = rl.check("a.com")
    assert r.verdict is Verdict.BACKOFF   # 3 strikes → backoff
