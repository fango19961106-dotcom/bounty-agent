"""adversarial.py — 跨模型對抗閘（P1）

同一個模型質疑自己係假對抗（correlated blind spots）。
呢個模組要求質疑者係**唔同 provider** 嘅模型，並記錄 provider 多樣性。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .gates import ADVERSARIAL_QUESTIONS


@dataclass
class ChallengerResponse:
    provider: str            # 質疑者模型嘅 provider（必須同主 agent 唔同）
    model: str
    question: str
    challenge: str           # 質疑內容
    needs_experiment: bool   # 質疑係咪要用實驗回應


class CrossModelChallenger:
    """管理多 provider 質疑者。challengers: {name: callable(question, context) -> str}"""

    def __init__(self, main_provider: str) -> None:
        self.main_provider = main_provider
        self.challengers: dict[str, tuple[str, object]] = {}  # name -> (provider, fn)

    def register(self, name: str, provider: str, fn) -> None:
        if provider == self.main_provider:
            raise ValueError(
                f"[對抗閘] 質疑者 {name} 同主 agent 同屬 {provider}——"
                "同一模型家族有相同盲點，唔算真對抗")
        self.challengers[name] = (provider, fn)

    def challenge(self, finding_context: str) -> list[ChallengerResponse]:
        """每個質疑者對每條固定問題出招。"""
        if not self.challengers:
            raise RuntimeError("[對抗閘] 未註冊任何跨模型質疑者")
        out: list[ChallengerResponse] = []
        for name, (provider, fn) in self.challengers.items():
            for q in ADVERSARIAL_QUESTIONS:
                out.append(ChallengerResponse(
                    provider=provider, model=name, question=q,
                    challenge=fn(q, finding_context),
                    needs_experiment=True))
        return out

    def provider_diversity(self) -> int:
        """質疑者橫跨幾多個 provider（≥2 先叫有多樣性）。"""
        return len({p for p, _ in self.challengers.values()})
