"""scope_refresh.py — Scope 白名單自動刷新（P2）

由官方來源攞最新 scope，失敗即 fail-closed。
預設來源係本地快照檔（每日 cron 更新）；亦可以注入自訂 fetcher。
規則：寧願誤拒，唔好誤放。
"""
from __future__ import annotations

import json
import time
from pathlib import Path


class ScopeRefresher:
    def __init__(self, snapshot_path: str | Path,
                 max_age_hours: float = 24.0) -> None:
        self.path = Path(snapshot_path)
        self.max_age = max_age_hours * 3600

    def load(self) -> list[str] | None:
        """讀白名單快照。檔案唔存在、格式錯、或者過期 → 回傳 None（fail-closed）。"""
        if not self.path.exists():
            return None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        fetched_at = data.get("fetched_at", 0)
        if time.time() - fetched_at > self.max_age:
            return None   # 快照過期：官方可能改咗 scope，唔可以當有效
        domains = data.get("domains")
        if not isinstance(domains, list) or not domains:
            return None
        return [str(d) for d in domains]

    @staticmethod
    def write_snapshot(domains: list[str], path: str | Path) -> None:
        """畀每日爬取 job 用：寫入帶時間戳嘅快照。"""
        Path(path).write_text(json.dumps(
            {"fetched_at": time.time(), "domains": domains},
            ensure_ascii=False, indent=2), encoding="utf-8")
