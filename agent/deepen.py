"""deepen.py — 深化引擎自動化（P2）

將 v3.1 嘅三個深化工序由「靠自覺」變「有工序」：
1. 自動矛盾狩獵：搵出跨描述（D1/D2/D3）講緊同一件事但結論唔同嘅陳述對
2. 建造者推導：先預測實作，對照現實，推導錯嘅位自動標記
3. 生命週期抽檢：隨機抽 data item 逼畫完整流程，斷點列為偵察目標
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass

from .labels import Label, ModelStore, Statement

# 中文/英文關鍵詞提取（夠用嘅輕量實現；接 LLM 後可換 embedding）
_STOP = {"the", "a", "an", "is", "are", "to", "of", "in", "on", "for",
         "嘅", "係", "咗", "唔", "會", "可以", "呢個", "嗰個"}


def _keywords(text: str) -> set[str]:
    tokens = set(re.findall(r"[a-zA-Z_]{3,}|[一-鿿]{2,}", text.lower()))
    return tokens - _STOP


@dataclass
class ContradictionCandidate:
    obs_a: int
    obs_b: int
    shared_keywords: set[str]
    reason: str


def find_contradiction_candidates(store: ModelStore,
                                  min_shared: int = 2) -> list[ContradictionCandidate]:
    """跨描述配對：同一主題（共享關鍵詞）但嚟自唔同描述（D1/D2/D3）嘅陳述，
    列為矛盾候選交俾 agent/LLM 覆核。純啟發式——寧濫勿缺，覆核層把關。"""
    by_desc: dict[str, list[Statement]] = {}
    for desc, ids in store.descriptions.items():
        by_desc[desc] = [store.statements[i] for i in ids
                         if store.statements[i].label is Label.OBS]

    candidates: list[ContradictionCandidate] = []
    descs = list(by_desc)
    for i in range(len(descs)):
        for j in range(i + 1, len(descs)):
            for a in by_desc[descs[i]]:
                ka = _keywords(a.text)
                for b in by_desc[descs[j]]:
                    shared = ka & _keywords(b.text)
                    if len(shared) >= min_shared:
                        candidates.append(ContradictionCandidate(
                            a.id, b.id, shared,
                            f"{descs[i]} vs {descs[j]} 同主題陳述，需覆核係咪矛盾"))
    return candidates


@dataclass
class DerivationResult:
    feature: str
    predicted: str
    actual_obs_id: int | None
    matched: bool
    note: str


def builder_derivation(feature: str, predicted: str,
                       actual_obs_id: int | None,
                       judge) -> DerivationResult:
    """建造者視角推導：預測 vs 現實。
    judge: callable(predicted, actual_text) -> (matched: bool, note: str)
    ——可注入 LLM 或規則。推導錯嘅位就係理解缺口或實作古怪。"""
    if actual_obs_id is None:
        return DerivationResult(feature, predicted, None, False,
                                "未有實測觀察對照——列為下一步 recon 目標")
    return DerivationResult(feature, predicted, actual_obs_id, False,
                            "待 judge 對照")  # 由調用方餵 judge


LIFECYCLE_STAGES = ("簽發", "傳輸", "儲存", "驗證", "cache", "撤銷", "刪除後")


def lifecycle_audit(item_description: str,
                    covered_stages: list[str]) -> list[str]:
    """生命週期抽檢：畫唔出嘅階段 = 理解嘅洞 = 偵察目標。"""
    return [s for s in LIFECYCLE_STAGES if s not in covered_stages]


def pick_lifecycle_item(store: ModelStore, rng: random.Random | None = None) -> Statement | None:
    """由流量版描述隨機抽一個觀察做抽檢對象。"""
    rng = rng or random.Random()
    ids = store.descriptions.get("D3_traffic", [])
    return store.statements[rng.choice(ids)] if ids else None
