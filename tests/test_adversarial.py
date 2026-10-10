"""測試跨模型對抗閘"""
import pytest

from agent.adversarial import CrossModelChallenger
from agent.gates import ADVERSARIAL_QUESTIONS


def _fn(q, ctx):
    return f"質疑：{q}"


def test_same_provider_rejected():
    c = CrossModelChallenger(main_provider="openai")
    with pytest.raises(ValueError):
        c.register("gpt-x", "openai", _fn)   # 同 provider = 假對抗


def test_cross_provider_challenge():
    c = CrossModelChallenger(main_provider="openai")
    c.register("claude-x", "anthropic", _fn)
    c.register("gemini-x", "google", _fn)
    out = c.challenge("finding context")
    assert len(out) == 2 * len(ADVERSARIAL_QUESTIONS)
    assert c.provider_diversity() == 2
    assert all(r.needs_experiment for r in out)


def test_no_challenger_raises():
    c = CrossModelChallenger(main_provider="openai")
    with pytest.raises(RuntimeError):
        c.challenge("ctx")
