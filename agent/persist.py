"""persist.py — ModelStore 持久化（P1）

冇記憶嘅 agent 每次都由零開始。呢個模組將 ModelStore 落盤做 JSON，
支援 restart 後完整恢復（包括幻覺日誌同待覆核標記）。
"""
from __future__ import annotations

import json
from pathlib import Path

from .labels import Evidence, Label, ModelStore, Statement


def save_store(store: ModelStore, path: str | Path) -> None:
    data = {
        "counter": store.statements and max(store.statements) or 0,
        "statements": [
            {
                "id": s.id, "text": s.text, "label": s.label.value,
                "evidence": {"source": s.evidence.source, "excerpt": s.evidence.excerpt}
                            if s.evidence else None,
                "depends_on": list(s.depends_on),
                "needs_review": s.needs_review,
            }
            for s in store.statements.values()
        ],
        "descriptions": store.descriptions,
        "hallucination_log": store.hallucination_log,
    }
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2),
                          encoding="utf-8")


def load_store(path: str | Path) -> ModelStore:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    store = ModelStore()
    for d in data["statements"]:
        ev = Evidence(**d["evidence"]) if d["evidence"] else None
        st = Statement(id=d["id"], text=d["text"], label=Label(d["label"]),
                       evidence=ev, depends_on=tuple(d["depends_on"]),
                       needs_review=d["needs_review"])
        store.statements[st.id] = st
    store.descriptions = {k: list(v) for k, v in data["descriptions"].items()}
    store.hallucination_log = data["hallucination_log"]
    # 恢復計數器，避免 id 衝突
    max_id = max(store.statements, default=0)
    for _ in range(max_id):
        next(store._counter)
    return store
