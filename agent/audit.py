"""audit.py — 證據完整性 + append-only 審計鏈（P0）

兩個功能：
1. EvidenceVault：PoC artifact 落盤時即刻 SHA-256，報告引用 hash——防幻覺偽證、防事後篡改
2. AuditChain：每個關鍵事件（請求判決、閘口結果、幻覺事故）寫入 hash-chained log，
   任何一行被改，條鏈即刻斷——法律層面嘅不在場證明
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EvidenceVault:
    """PoC 證據保險庫：檔案入庫即 hash，之後任何引用都要對得返個 hash。"""

    def __init__(self, vault_dir: str | Path) -> None:
        self.dir = Path(vault_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index: dict[str, dict] = {}   # artifact_name -> {sha256, stored_at}

    def deposit(self, name: str, data: bytes) -> str:
        """證據入庫，回傳 SHA-256。同名覆寫會換 hash——呢個係特性：證據唔准靜靜雞變。"""
        h = sha256_bytes(data)
        (self.dir / name).write_bytes(data)
        self.index[name] = {"sha256": h, "stored_at": time.time()}
        return h

    def verify(self, name: str) -> bool:
        """驗證證據有冇俾人郁過。"""
        if name not in self.index:
            return False
        path = self.dir / name
        if not path.exists():
            return False
        return sha256_bytes(path.read_bytes()) == self.index[name]["sha256"]


@dataclass
class AuditEvent:
    seq: int
    ts: float
    kind: str          # scope_verdict / gate_result / hallucination / human_approval …
    payload: dict
    prev_hash: str
    hash: str


class AuditChain:
    """Append-only hash chain。每一行 hash 包含上一行 hash——改任何一行全鏈即斷。"""

    GENESIS = "0" * 64

    def __init__(self, log_path: str | Path | None = None) -> None:
        self.path = Path(log_path) if log_path else None
        self.events: list[AuditEvent] = []
        if self.path and self.path.exists():
            self._load()

    def _compute_hash(self, seq: int, ts: float, kind: str,
                      payload: dict, prev_hash: str) -> str:
        blob = json.dumps({"seq": seq, "ts": ts, "kind": kind,
                           "payload": payload, "prev_hash": prev_hash},
                          sort_keys=True, ensure_ascii=False).encode()
        return sha256_bytes(blob)

    def append(self, kind: str, payload: dict) -> AuditEvent:
        seq = len(self.events)
        prev = self.events[-1].hash if self.events else self.GENESIS
        ts = time.time()
        ev = AuditEvent(seq, ts, kind, payload, prev,
                        self._compute_hash(seq, ts, kind, payload, prev))
        self.events.append(ev)
        if self.path:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(ev), ensure_ascii=False) + "\n")
        return ev

    def verify_chain(self) -> bool:
        """全鏈覆核：任何一行被篡改都會 False。"""
        prev = self.GENESIS
        for ev in self.events:
            if ev.prev_hash != prev:
                return False
            if ev.hash != self._compute_hash(ev.seq, ev.ts, ev.kind, ev.payload, ev.prev_hash):
                return False
            prev = ev.hash
        return True

    def _load(self) -> None:
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                d = json.loads(line)
                self.events.append(AuditEvent(**d))
