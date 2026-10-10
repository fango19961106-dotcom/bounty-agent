"""proxy.py — mitmproxy 物理閘口 addon（P0）

將「靠 agent 記得 call pre_request」變成「物理上攔截所有出站請求」。
用法：mitmdump -s agent/proxy.py
所有經 proxy 嘅請求都會過 ScopeGate；HARD_REJECT 直接 403 截停，流量出唔到去。

部署時用環境變數配置：
  BOUNTY_SCOPE_FILE   — 白名單檔案（每行一個域名；檔案唔存在 = fail-closed）
  BOUNTY_ACCOUNT_TAG  — 研究帳號識別（預設 MSOBB）
  BOUNTY_AUDIT_LOG    — 審計鏈輸出路徑
"""
from __future__ import annotations

import os

from .audit import AuditChain
from .scope import ScopeGate, Verdict

_scope_gate: ScopeGate | None = None
_audit: AuditChain | None = None


def load(loader=None) -> None:
    """mitmproxy addon 入口。"""
    global _scope_gate, _audit
    _scope_gate = ScopeGate()
    scope_file = os.environ.get("BOUNTY_SCOPE_FILE", "")
    domains: list[str] | None = None
    if scope_file and os.path.exists(scope_file):
        with open(scope_file, encoding="utf-8") as f:
            domains = [l.strip() for l in f if l.strip()]
    _scope_gate.refresh_whitelist(domains)   # 失敗 → fail-closed
    _audit = AuditChain(os.environ.get("BOUNTY_AUDIT_LOG"))
    _audit.append("proxy_start", {"scope_loaded": bool(domains)})


def request(flow) -> None:
    """每個出站請求喺度被攔。flow 係 mitmproxy 嘅 HTTPFlow。"""
    if _scope_gate is None or _audit is None:
        flow.kill()
        return
    host = flow.request.pretty_host
    account_tag = flow.request.headers.get("X-Research-Account", "")
    result = _scope_gate.pre_request(host, account_tag,
                                     payload_fingerprint=flow.request.path)
    _audit.append("scope_verdict", {"host": host, "verdict": result.verdict.value,
                                    "reason": result.reason})
    if result.verdict is not Verdict.ALLOW:
        # 物理截停：回 403，請求永遠到唔到目標
        from mitmproxy import http
        flow.response = http.Response.make(
            403, f"[BountyAgent] {result.verdict.value}: {result.reason}".encode(),
            {"Content-Type": "text/plain"})


def response(flow) -> None:
    """目標回應：403/429 回報俾 RateLimiter 記 strike。"""
    if _scope_gate is None or flow.response is None:
        return
    if flow.response.status_code in (403, 429):
        _scope_gate.rate_limiter.report_block(flow.request.pretty_host)
