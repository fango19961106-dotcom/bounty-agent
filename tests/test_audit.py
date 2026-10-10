"""測試證據完整性同審計鏈"""
from agent.audit import AuditChain, EvidenceVault


def test_vault_deposit_and_verify(tmp_path):
    v = EvidenceVault(tmp_path)
    h = v.deposit("req207.txt", b"HTTP/1.1 200 OK")
    assert len(h) == 64
    assert v.verify("req207.txt")


def test_vault_detects_tampering(tmp_path):
    v = EvidenceVault(tmp_path)
    v.deposit("poc.txt", b"original")
    (tmp_path / "poc.txt").write_bytes(b"tampered")   # 事後篡改
    assert not v.verify("poc.txt")


def test_vault_unknown_artifact():
    v = EvidenceVault("/tmp/nonexistent_vault_test")
    assert not v.verify("ghost.txt")


def test_chain_append_and_verify(tmp_path):
    c = AuditChain(tmp_path / "audit.jsonl")
    c.append("scope_verdict", {"host": "a.com", "verdict": "ALLOW"})
    c.append("gate_result", {"gate": "EvidenceGate", "passed": True})
    assert c.verify_chain()


def test_chain_detects_tampering():
    c = AuditChain()
    c.append("a", {"x": 1})
    c.append("b", {"x": 2})
    c.events[0].payload["x"] = 999   # 篡改歷史
    assert not c.verify_chain()


def test_chain_persistence_roundtrip(tmp_path):
    p = tmp_path / "audit.jsonl"
    c1 = AuditChain(p)
    c1.append("start", {"ok": True})
    c2 = AuditChain(p)   # 重新載入
    assert len(c2.events) == 1
    assert c2.verify_chain()
    c2.append("continue", {})
    assert c2.verify_chain()
