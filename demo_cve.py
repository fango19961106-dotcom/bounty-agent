"""demo_cve.py — CVE 主線工作流程示範（v4.2 主策略）

情境：MSRC 出咗個新 CVE → 揀選 → root cause 入模型
→ 衍生變種假設 → 開泳道驗證 → 三重閘。
"""
from agent.cve_feed import CveFeed, CveRecord
from agent.gates import ADVERSARIAL_QUESTIONS, Finding, TripleGate
from agent.labels import Evidence
from agent.scope import RateLimiter, ScopeGate
from agent.workflow import Orchestrator, Phase

LINE = "=" * 60


def main() -> None:
    print(LINE)
    print("CVE 主線工作流程示範（Variant Analysis as Main Line）")
    print(LINE)

    gate = ScopeGate(RateLimiter(max_rps=1e9))
    gate.refresh_whitelist(["portal.azure.com", "management.azure.com"])
    orch = Orchestrator(gate)
    feed = CveFeed()

    # ---- 1. 本週 security bulletin 入咗三個 CVE ----
    print("\n【Step 1】CVE 饋入：三個候選")
    cves = [
        CveRecord("CVE-2026-20001", "azure",
                  root_cause="Managed identity token endpoint 無驗證 request 嘅 tenant boundary，"
                             "cross-tenant token replay 可行",
                  commit_ref="azure-sdk@f3a91c",
                  error_pattern="missing tenant boundary check",
                  in_scope_products=("azure",)),
        CveRecord("CVE-2026-20002", "azure",
                  root_cause="",   # 冇 root cause 細節
                  in_scope_products=("azure",)),
        CveRecord("CVE-2026-20003", "azure",
                  root_cause="JWT audience validation bypass",
                  hot=True,        # 明星 CVE，萬人跟
                  in_scope_products=("azure",)),
    ]
    lane = orch.open_lane("management.azure.com")
    for c in cves:
        q = c.quality()
        print(f"  {c.cve_id} [{c.product}] → {q.value}")
        for h in feed.process(lane.store, c):   # SKIP 嘅會自動計入統計
            lane.hypotheses.append(h)
    print(f"  統計: ingested={feed.stats.ingested} skipped={feed.stats.skipped} "
          f"gold={feed.stats.gold}")

    # ---- 2. 變種假設（由 GOLD CVE 衍生）----
    print("\n【Step 2】衍生咗嘅變種假設：")
    for h in lane.hypotheses:
        print(f"  [HYP #{h.id}] {h.text[:80]}…")

    # ---- 3. 揀第一個假設做探針 ----
    print("\n【Step 3】PROBE：驗證『同 pattern 喺相鄰組件』")
    lane.transition(Phase.DEEPEN)
    lane.transition(Phase.FIND_GAPS)
    lane.transition(Phase.PROBE)
    probe = lane.store.add_obs(
        "實測：姊妹服務 Resource Graph 嘅 token endpoint 同樣無 tenant check，"
        "A tenant 嘅 token 可以讀 B tenant 嘅資源清單（雙自有測試租戶驗證）",
        Evidence("burp:req#310", "HTTP/1.1 200 OK {\"tenant\":\"B\",\"resources\":[...]}"),
        "D3_traffic")
    lane.record_signal()
    orch.record_prediction(hit=True)
    print(f"  命中！→ [OBS #{probe.id}]（雙自有租戶，冇掂第三方數據）")
    lane.transition(Phase.VERIFYING)

    # ---- 4. 三重閘 ----
    print("\n【Step 4】三重驗證閘")
    finding = Finding(
        title="[Azure Resource Graph] Missing tenant boundary check → cross-tenant read",
        repro_steps=["A tenant 攞 managed identity token",
                     "帶 A token call Resource Graph 查 B tenant 資源",
                     "觀察返回 B tenant 資源清單"],
        observation_ids=[probe.id],
        poc_artifacts=["poc_rg_001/video.mp4"],
        reproductions=3,
    )
    rebuttals = {q: f"實驗回應：{q[:10]}…（對照實驗已排除）" for q in ADVERSARIAL_QUESTIONS}
    passed, reports = TripleGate().run(finding, lane.store, rebuttals,
                                       lambda steps: (True, ""))
    for r in reports:
        print(f"  {r.gate}: {'PASS' if r.passed else 'FAIL'}")

    if passed:
        lane.transition(Phase.REPORT)
        print("\n【Step 5】過閘 → 等待人類批准提交 MSRC Portal")
        lane.transition(Phase.DONE)

    kpi = orch.kpi()
    print(f"\n【KPI】預測命中率 {kpi.prediction_accuracy:.0%}｜幻覺率 {kpi.hallucination_rate:.0%}")
    print(LINE)


if __name__ == "__main__":
    main()
