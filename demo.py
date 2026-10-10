"""demo.py — 端到端示範：模擬 agent 由建模到出報告行一次完整循環

情境：對（虛構嘅）Copilot 目標做一輪 Model-Gap-Probe 循環。
包括：三份描述建模 → 矛盾狩獵 → 假設 → fail-closed scope 檢查
→ 探針 → 三重驗證閘 → 人類批准 → KPI。
"""
from agent.gates import ADVERSARIAL_QUESTIONS, Finding, TripleGate
from agent.labels import Evidence, ModelStore
from agent.scope import RateLimiter, ScopeGate
from agent.workflow import Orchestrator, Phase

LINE = "=" * 60


def main() -> None:
    print(LINE)
    print("Bounty Agent v4.0 — 端到端工作流程示範")
    print(LINE)

    # ---- 0. 開工：scope 閘 fail-closed 檢查 ----
    print("\n【Phase 0】合規閘初始化")
    gate = ScopeGate(RateLimiter(max_rps=1e9))  # demo 用高速率；實戰預設 1 req/s
    ok = gate.refresh_whitelist(["copilot.microsoft.com", "chromium.googlesource.com"])
    print(f"  白名單刷新: {'成功' if ok else '失敗'}")
    r = gate.pre_request("evil-corp.com", "researcher-MSOBB-01")
    print(f"  試出界請求 evil-corp.com → {r.verdict.value}（{r.reason}）")
    r = gate.pre_request("copilot.microsoft.com", "normal-account")
    print(f"  試無識別帳號 → {r.verdict.value}（{r.reason}）")
    r = gate.pre_request("copilot.microsoft.com", "researcher-MSOBB-01")
    print(f"  合規請求 copilot.microsoft.com → {r.verdict.value}")

    # ---- 1. 開泳道 + 三份描述建模 ----
    print("\n【Phase 1】BUILD_MODEL：三份描述並行建模")
    orch = Orchestrator(gate)
    lane = orch.open_lane("copilot.microsoft.com")
    store = lane.store

    store.add_obs("文檔話：插件只能讀取用戶當前文件",
                  Evidence("docs:plugins/overview#permissions", "Plugins can only access the current document"),
                  "D1_doc")
    store.add_obs("代碼顯示：fetchDocument() 只檢查 token 有效，無檢查 doc 歸屬",
                  Evidence("repo:copilot/plugins/fetch.cc:L88", "if (!token.valid()) return 403;"),
                  "D2_code")
    store.add_obs("實測：正常流程下 GET /docs/{id} 帶住我嘅 token 返回我自己份 doc",
                  Evidence("burp:req#201", "HTTP/1.1 200 OK {\"docId\":\"A1\"}"),
                  "D3_traffic")
    print("  D1 文檔版 / D2 代碼版 / D3 流量版：各 1 條 [OBS]（附證據指針）")
    lane.transition(Phase.DEEPEN)

    # ---- 2. 深化引擎：矛盾狩獵 ----
    print("\n【Phase 2】DEEPEN：矛盾狩獵")
    print("  矛盾：D1 話『只能讀當前文件』，但 D2 顯示只驗 token 唔驗歸屬")
    orch.contradictions += 1
    print("  → 呢個縫暗示：插件權限係『用戶級』而唔係『文件級』")
    lane.transition(Phase.FIND_GAPS)

    # ---- 3. 搵落差：假設 + 預測訊號 ----
    print("\n【Phase 3】FIND_GAPS：產生可證偽假設")
    obs_d2 = [s for s in store.statements.values() if s.evidence and "fetch.cc" in s.evidence.source][0]
    store.add_inf("插件 API 嘅權限檢查缺失 doc 歸屬驗證", depends_on=[obs_d2.id], description="D2_code")
    hyp = store.add_hyp("用我嘅 token 換人哋嘅 docId，可能越權讀到 B 帳號嘅文件",
                        predicted_signal="返回 B 嘅 doc 內容（200）而唔係 403",
                        model_ref="D1 vs D2 矛盾 #1")
    print(f"  [HYP #{hyp.id}] {hyp.text}")
    print(f"  [INF] 插件 API 缺失歸屬驗證（依賴 OBS #{obs_d2.id}）")
    lane.transition(Phase.PROBE)

    # ---- 4. 探針驗證（模擬）----
    print("\n【Phase 4】PROBE：最小探針（每個請求先過 scope 閘）")
    for i in range(3):
        r = gate.pre_request("copilot.microsoft.com", "researcher-MSOBB-01")
        assert r.verdict.value == "ALLOW"
    probe_obs = store.add_obs("雙測試帳號實驗：A 帳號 token + B 嘅 docId → 200 返回 B 文件",
                              Evidence("burp:req#207", "HTTP/1.1 200 OK {\"docId\":\"B9\",\"owner\":\"B\"}"),
                              "D3_traffic")
    lane.record_signal()
    orch.record_prediction(hit=True)
    print(f"  3 次穩定重現成功（自有雙帳號）→ [OBS #{probe_obs.id}]")
    print("  預測訊號命中 ✓")
    lane.transition(Phase.VERIFYING)

    # ---- 5. 三重驗證閘 ----
    print("\n【Phase 5】VERIFYING：三重驗證閘")
    finding = Finding(
        title="[Copilot Plugin] IDOR in /docs/{id} → 跨用戶文件讀取",
        repro_steps=["A 帳號取 plugin token", "GET /docs/B9 帶 A token", "觀察返回 B 文件內容"],
        observation_ids=[probe_obs.id],
        poc_artifacts=["poc_001/video.mp4", "poc_001/req207.txt"],
        reproductions=3,
    )
    rebuttals = {
        ADVERSARIAL_QUESTIONS[0]: "對照實驗：正常功能下 A 永遠唔應該讀到 B9（req#208）",
        ADVERSARIAL_QUESTIONS[1]: "已排除 cache：換第三個 docId 重測，結果一致（req#209）",
        ADVERSARIAL_QUESTIONS[2]: "已跨邊界：B 係獨立測試帳號，A/B 無共享關係",
        ADVERSARIAL_QUESTIONS[3]: "已用全新 session 重現，無依賴特殊狀態",
    }
    passed, reports = TripleGate().run(
        finding, store, rebuttals,
        blank_runner=lambda steps: (True, ""))
    for rep in reports:
        print(f"  {rep.gate}: {'PASS' if rep.passed else 'FAIL ' + str(rep.issues)}")

    if passed:
        lane.transition(Phase.REPORT)
        print("\n【Phase 6】REPORT：已過三重閘 → 等待人類批准提交 MSRC Portal")
        lane.findings_count += 1
        lane.transition(Phase.DONE)

    # ---- 7. KPI ----
    print("\n【KPI 快照】")
    kpi = orch.kpi()
    print(f"  預測命中率:     {kpi.prediction_accuracy:.0%}")
    print(f"  幻覺率:         {kpi.hallucination_rate:.0%}")
    print(f"  矛盾發現:       {kpi.contradictions_found}")
    print(f"  模型修正:       {kpi.model_corrections}")

    # ---- 8. 示範幻覺事故追溯 ----
    print("\n【示範】幻覺事故：發現 D2 嗰條『觀察』原來係 agent 諗出嚟，冇真實讀過 code")
    affected = store.invalidate_obs(obs_d2.id, "幻覺：證據指針指向不存在嘅檔案")
    print(f"  受影響下游陳述: {affected} → 全部標記『待覆核』")
    print(f"  幻覺率上升至: {store.hallucination_rate():.0%}")
    print(LINE)


if __name__ == "__main__":
    main()
