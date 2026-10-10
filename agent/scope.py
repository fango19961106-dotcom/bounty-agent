"""scope.py — Fail-closed 合規 middleware

每一個對外請求發出前必須過閘：
- 域名唔喺 scope 白名單 → HARD_REJECT
- 帳號無 MSOBB 識別 → HARD_REJECT
- 超速率 → BACKOFF
- 白名單刷新失敗 → fail-closed（預設拒絕）
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class Verdict(Enum):
    ALLOW = "ALLOW"
    HARD_REJECT = "HARD_REJECT"
    BACKOFF = "BACKOFF"


@dataclass
class GateResult:
    verdict: Verdict
    reason: str = ""


class RateLimiter:
    """每目標速率控制 + 403/429 exponential backoff。"""

    def __init__(self, max_rps: float = 1.0) -> None:
        self.max_rps = max_rps
        self._last: dict[str, float] = {}
        self._blocked_until: dict[str, float] = {}
        self._strikes: dict[str, int] = {}

    def check(self, host: str) -> GateResult:
        now = time.time()
        if now < self._blocked_until.get(host, 0):
            return GateResult(Verdict.BACKOFF, f"{host} backoff 中")
        last = self._last.get(host, 0)
        if now - last < 1.0 / self.max_rps:
            return GateResult(Verdict.BACKOFF, f"超過速率上限 {self.max_rps} req/s")
        self._last[host] = now
        return GateResult(Verdict.ALLOW)

    def report_block(self, host: str) -> None:
        """收到 403/429 → 記一 strike；連續 3 次 → exponential backoff（最少 1 小時）。"""
        self._strikes[host] = self._strikes.get(host, 0) + 1
        if self._strikes[host] >= 3:
            self._blocked_until[host] = time.time() + 3600 * (2 ** (self._strikes[host] - 3))


class ScopeGate:
    """Fail-closed scope 閘口。"""

    def __init__(self, rate_limiter: RateLimiter | None = None) -> None:
        self._whitelist: set[str] = set()
        self._whitelist_fresh = False   # 刷新失敗 → fail-closed
        self.rate_limiter = rate_limiter or RateLimiter()
        self.log: list[dict] = []

    # ---- 白名單管理 ----
    def refresh_whitelist(self, domains: list[str] | None) -> bool:
        """由官方來源刷新。傳 None / 空 = 刷新失敗 → fail-closed。"""
        if not domains:
            self._whitelist_fresh = False
            return False
        self._whitelist = {d.lower().lstrip("*.") for d in domains}
        self._whitelist_fresh = True
        return True

    def _in_scope(self, host: str) -> bool:
        host = host.lower()
        return any(host == d or host.endswith("." + d) for d in self._whitelist)

    # ---- 主閘口 ----
    def pre_request(self, url_host: str, account_tag: str,
                    payload_fingerprint: str = "") -> GateResult:
        if not self._whitelist_fresh:
            r = GateResult(Verdict.HARD_REJECT, "白名單未刷新（fail-closed）")
        elif not self._in_scope(url_host):
            r = GateResult(Verdict.HARD_REJECT, f"{url_host} 唔喺 scope 白名單")
        elif "MSOBB" not in account_tag:
            r = GateResult(Verdict.HARD_REJECT, "帳號無 MSOBB 識別字樣")
        else:
            r = self.rate_limiter.check(url_host)
        self.log.append({"host": url_host, "verdict": r.verdict.value,
                         "reason": r.reason, "ts": time.time(),
                         "fp": payload_fingerprint})
        return r
