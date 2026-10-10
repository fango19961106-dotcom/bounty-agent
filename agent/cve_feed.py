"""cve_feed.py — CVE 變種分析泳道（variant analysis）

理念：一個 CVE 公佈 = 有人證實咗「呢類寫法會出事」。
開發者極少只犯一次——同一個錯誤 pattern 通常散落成個 codebase。
Patch 係藏寶圖；我哋嘅工作係搵到地圖上未標記嘅 X。

流程：
  CVE 入 → 揀選（值唔值得跟）→ root cause 入 ModelStore（D2_code）
  → 衍生變種假設 → 觸發泳道
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from .labels import Evidence, ModelStore, Statement


class CveQuality(Enum):
    GOLD = "GOLD"         # 有 root cause + commit diff + 可泛化 pattern
    SILVER = "SILVER"     # 有 root cause 但細節有限
    SKIP = "SKIP"         # 得一句描述 / 唔喺泳道範圍 / 明星 CVE 紅海


@dataclass
class CveRecord:
    """一個 CVE 嘅結構化記錄。"""
    cve_id: str
    product: str                    # 對應泳道目標，如 "azure" / "chrome"
    root_cause: str                 # 錯誤嘅本質（冇就唔好跟）
    commit_ref: str = ""            # patch commit / fix reference（藏寶圖）
    error_pattern: str = ""         # 可泛化嘅錯誤 pattern，如 "missing length check"
    in_scope_products: tuple[str, ...] = ()
    hot: bool = False               # 明星 CVE（萬人跟）→ 紅海警告

    def quality(self) -> CveQuality:
        """揀 CVE 嘅標準：有 root cause、有 diff、pattern 可泛化、喺範圍內。"""
        if self.in_scope_products and self.product not in self.in_scope_products:
            return CveQuality.SKIP
        if not self.root_cause:
            return CveQuality.SKIP
        if self.hot:
            return CveQuality.SKIP   # 明星 CVE：幾萬人睇住，避開
        if self.commit_ref and self.error_pattern:
            return CveQuality.GOLD
        return CveQuality.SILVER


def ingest_cve(store: ModelStore, cve: CveRecord) -> list[Statement]:
    """CVE root cause 寫入模型：D2_code（漏洞 code）+ D1_doc（意圖對照）。
    證據指針用 cve: 前綴，可追溯返官方記錄。"""
    q = cve.quality()
    if q is CveQuality.SKIP:
        return []

    out: list[Statement] = []
    out.append(store.add_obs(
        f"[{cve.cve_id}] root cause：{cve.root_cause}",
        Evidence(source=f"cve:{cve.cve_id}" + (f"@{cve.commit_ref}" if cve.commit_ref else ""),
                 excerpt=cve.root_cause[:500]),
        "D2_code"))
    if cve.error_pattern:
        out.append(store.add_obs(
            f"[{cve.cve_id}] 錯誤 pattern：{cve.error_pattern}（可泛化搵變種）",
            Evidence(source=f"cve:{cve.cve_id}", excerpt=cve.error_pattern[:500]),
            "D2_code"))
    return out


# 變種假設嘅三個標準方向
VARIANT_ANGLES = (
    "同 pattern 喺同 codebase 嘅其他 function 重複出現？",
    "同 pattern 喺姊妹產品/相鄰組件出現？",
    "官方 patch 係咪只修咗觸發路徑 A，路徑 B/C 仲到達到同一個 sink？",
)


def derive_variant_hypotheses(store: ModelStore, cve: CveRecord) -> list[Statement]:
    """由 CVE 衍生變種假設（每個帶預測訊號，可證偽）。"""
    if cve.quality() is CveQuality.SKIP:
        return []
    hyps = []
    for angle in VARIANT_ANGLES:
        hyps.append(store.add_hyp(
            f"[{cve.cve_id} 變種] {angle}",
            predicted_signal=f"搵到未修補嘅同 pattern 位置，重現同類影響",
            model_ref=f"cve:{cve.cve_id}"))
    return hyps


@dataclass
class CveFeedStats:
    ingested: int = 0
    skipped: int = 0
    gold: int = 0
    silver: int = 0


class CveFeed:
    """CVE 饋入器：批量處理 + 統計，俾 Orchestrator 決定開唔開泳道。"""

    CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

    def __init__(self) -> None:
        self.stats = CveFeedStats()

    def process(self, store: ModelStore, cve: CveRecord) -> list[Statement]:
        if not self.CVE_ID_RE.match(cve.cve_id):
            raise ValueError(f"無效 CVE 編號：{cve.cve_id}")
        q = cve.quality()
        if q is CveQuality.SKIP:
            self.stats.skipped += 1
            return []
        self.stats.ingested += 1
        if q is CveQuality.GOLD:
            self.stats.gold += 1
        else:
            self.stats.silver += 1
        ingest_cve(store, cve)
        return derive_variant_hypotheses(store, cve)
