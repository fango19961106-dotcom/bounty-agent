"""gates.py — 三重驗證閘（任何「命中」出閘前必過）

第一重：證據閘 —— 每個技術陳述有原始證據？
第二重：對抗閘 —— 獨立質疑者嘗試推翻；反駁必須用實驗回應
第三重：空白閘 —— 全新 context 實例淨攞重現步驟照做
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .labels import Label, ModelStore


@dataclass
class Finding:
    """一個聲稱嘅漏洞命中。"""
    title: str
    repro_steps: list[str]           # 重現步驟（可機械式照做）
    observation_ids: list[int]       # 引用 ModelStore 入面嘅 OBS
    poc_artifacts: list[str] = field(default_factory=list)  # 截圖/影片/請求原文路徑
    reproductions: int = 0           # 真實重現次數（需要 ≥3）


@dataclass
class GateReport:
    gate: str
    passed: bool
    issues: list[str] = field(default_factory=list)


class EvidenceGate:
    """第一重：證據閘。"""

    def check(self, finding: Finding, store: ModelStore) -> GateReport:
        issues: list[str] = []
        if finding.reproductions < 3:
            issues.append(f"重現次數 {finding.reproductions} < 3（H4 防火牆）")
        if not finding.poc_artifacts:
            issues.append("無 PoC 附件（證據必須係工具產出，唔係『我記得』）")
        if not finding.repro_steps:
            issues.append("無重現步驟")
        for oid in finding.observation_ids:
            st = store.statements.get(oid)
            if st is None:
                issues.append(f"引用咗不存在嘅陳述 #{oid}")
            elif st.label is not Label.OBS:
                issues.append(f"#{oid} 係 {st.label.value}，報告只准引用 OBS")
            elif st.needs_review:
                issues.append(f"#{oid} 嘅依賴鏈曾受幻覺事故影響，待覆核")
        return GateReport("EvidenceGate", not issues, issues)


# 質疑者固定問嘅四條問題
ADVERSARIAL_QUESTIONS = (
    "呢個行為用正常功能可唔可以解釋？",
    "有冇第三個解釋（cache / 負載平衡 / 自己 session）令結論唔成立？",
    "影響係咪真係跨咗安全邊界，定係自己郁自己？",
    "重現步驟係咪依賴觀察者嘅特殊狀態？",
)


class AdversarialGate:
    """第二重：對抗閘。質疑者提出嘅每條反駁，必須用實驗回應（唔係推理）。"""

    def check(self, finding: Finding,
              rebuttal_experiments: dict[str, str] | None) -> GateReport:
        """rebuttal_experiments: {質疑問題: 實驗證據描述}。每條問題都要有實驗回應。"""
        issues: list[str] = []
        rebuttal_experiments = rebuttal_experiments or {}
        for q in ADVERSARIAL_QUESTIONS:
            if q not in rebuttal_experiments:
                issues.append(f"質疑「{q}」無實驗回應")
        return GateReport("AdversarialGate", not issues, issues)


class BlankContextGate:
    """第三重：空白閘。全新 context 實例淨攞重現步驟照做。

    runner: 一個函數，接收 steps，回傳 (success, failure_reason)。
    真實部署時係一個獨立嘅 agent 實例；測試時可以注入假 runner。
    """

    def check(self, finding: Finding, runner) -> GateReport:
        ok, reason = runner(finding.repro_steps)
        issues = [] if ok else [f"空白重現失敗：{reason}"]
        return GateReport("BlankContextGate", ok, issues)


class TripleGate:
    """順序過三重閘；任何一重唔過 → 唔准交俾人類批准。"""

    def __init__(self) -> None:
        self.evidence_gate = EvidenceGate()
        self.adversarial_gate = AdversarialGate()
        self.blank_gate = BlankContextGate()

    def run(self, finding: Finding, store: ModelStore,
            rebuttal_experiments: dict[str, str] | None,
            blank_runner) -> tuple[bool, list[GateReport]]:
        reports = [
            self.evidence_gate.check(finding, store),
            self.adversarial_gate.check(finding, rebuttal_experiments),
            self.blank_gate.check(finding, blank_runner),
        ]
        return all(r.passed for r in reports), reports
