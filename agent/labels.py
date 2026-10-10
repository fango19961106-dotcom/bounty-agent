"""labels.py — 觀察/推斷/假設 標籤制度（幻覺防火牆核心）

鐵律：每一句關於系統嘅陳述都要分得清係觀察定推斷。
- OBS（觀察）：必須附證據指針；無指針自動降級為 HYP
- INF（推斷）：必須列明依賴嘅 OBS 編號；依賴鏈斷咗 → 自動標記「待覆核」
- HYP（假設）：唔准入模型文件，唔准入報告
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import Enum


class Label(Enum):
    OBS = "OBS"   # 觀察：有原始證據
    INF = "INF"   # 推斷：基於 OBS 推理
    HYP = "HYP"   # 假設：未驗證


@dataclass(frozen=True)
class Evidence:
    """證據指針：指向原始 request/code/文檔位置。"""
    source: str          # 例如 "burp:req#1042" / "github:chromium/src/net/xxx.cc:L120"
    excerpt: str         # 原文節錄（唔准靠自己記憶改寫）


@dataclass
class Statement:
    id: int
    text: str
    label: Label
    evidence: Evidence | None = None      # OBS 必填
    depends_on: tuple[int, ...] = ()      # INF 必填：依賴嘅 statement id
    needs_review: bool = False            # 依賴鏈斷咗會被標記

    def validate(self) -> None:
        if self.label is Label.OBS and self.evidence is None:
            raise ValueError(f"[H 防火牆] OBS #{self.id} 無證據指針")
        if self.label is Label.INF and not self.depends_on:
            raise ValueError(f"[H 防火牆] INF #{self.id} 無依賴鏈")
        if self.label is Label.OBS and self.depends_on:
            raise ValueError(f"[H 防火牆] OBS #{self.id} 唔可以有依賴（觀察係原始嘅）")


class ModelStore:
    """三份描述（D1 文檔版 / D2 代碼版 / D3 流量版）嘅儲存同幻覺防控。"""

    DESCRIPTIONS = ("D1_doc", "D2_code", "D3_traffic")

    def __init__(self) -> None:
        self._counter = itertools.count(1)
        self.statements: dict[int, Statement] = {}
        self.descriptions: dict[str, list[int]] = {d: [] for d in self.DESCRIPTIONS}
        self.hallucination_log: list[dict] = []

    # ---- 寫入 ----
    def add_obs(self, text: str, evidence: Evidence | None,
                description: str | None = None) -> Statement:
        """寫入觀察。無證據指針 → 自動降級為 HYP（防火牆規則）。"""
        sid = next(self._counter)
        if evidence is None:
            st = Statement(sid, text, Label.HYP)
        else:
            st = Statement(sid, text, Label.OBS, evidence=evidence)
        st.validate()
        self._register(st, description)
        return st

    def add_inf(self, text: str, depends_on: list[int],
                description: str | None = None) -> Statement:
        """寫入推斷。依賴必須係已存在嘅 OBS。"""
        sid = next(self._counter)
        for dep in depends_on:
            if dep not in self.statements:
                raise ValueError(f"[H 防火牆] INF #{sid} 依賴不存在嘅 #{dep}")
            if self.statements[dep].label is not Label.OBS:
                raise ValueError(f"[H 防火牆] INF #{sid} 只能依賴 OBS，#{dep} 係 {self.statements[dep].label.value}")
        st = Statement(sid, text, Label.INF, depends_on=tuple(depends_on))
        st.validate()
        self._register(st, description)
        return st

    def add_hyp(self, text: str, predicted_signal: str,
                model_ref: str = "") -> Statement:
        """寫入假設（唔准入描述文件，只活喺假設清單）。"""
        sid = next(self._counter)
        st = Statement(sid, f"{text} | 預測訊號: {predicted_signal} | 模型出處: {model_ref}",
                       Label.HYP)
        self._register(st, None)
        return st

    def _register(self, st: Statement, description: str | None) -> None:
        self.statements[st.id] = st
        if description is not None:
            if description not in self.descriptions:
                raise ValueError(f"未知描述 {description}，只准 {self.DESCRIPTIONS}")
            if st.label is Label.HYP:
                raise ValueError("[H 防火牆] HYP 唔准寫入模型描述文件")
            self.descriptions[description].append(st.id)

    # ---- 幻覺事故處理 ----
    def invalidate_obs(self, obs_id: int, reason: str) -> list[int]:
        """一條 OBS 被證實係假 → 幻覺事故：追溯所有下游 INF/HYP 標記待覆核。"""
        if obs_id not in self.statements:
            raise KeyError(obs_id)
        st = self.statements[obs_id]
        if st.label is not Label.OBS:
            raise ValueError("只有 OBS 可以被 invalidate")
        downstream = self._collect_downstream(obs_id)
        for sid in downstream:
            self.statements[sid].needs_review = True
        self.hallucination_log.append({
            "obs_id": obs_id, "text": st.text, "reason": reason,
            "downstream_affected": sorted(downstream),
        })
        return sorted(downstream)

    def _collect_downstream(self, root: int) -> set[int]:
        affected: set[int] = set()
        changed = True
        while changed:
            changed = False
            for st in self.statements.values():
                if st.id in affected or st.id == root:
                    continue
                if root in st.depends_on or any(d in affected for d in st.depends_on):
                    affected.add(st.id)
                    changed = True
        return affected

    # ---- 統計 ----
    def hallucination_rate(self) -> float:
        """幻覺率 = 被推翻嘅 OBS+INF ÷ 總陳述數。"""
        total = sum(1 for s in self.statements.values() if s.label in (Label.OBS, Label.INF))
        if total == 0:
            return 0.0
        bad = len(self.hallucination_log) + sum(
            1 for s in self.statements.values()
            if s.label is Label.INF and s.needs_review)
        return bad / total
