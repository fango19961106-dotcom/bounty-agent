# Bounty Agent v4.1 — Model-Driven Bug Bounty Hunting Workflow

> **Disclaimer / 免責聲明**：This project is a **compliance and quality-control framework** for AI-assisted security research. It must only be used against assets within the official scope of authorized bug bounty programs (e.g., Microsoft MSRC, Google VRP). Unauthorized testing of systems you do not own is illegal. 本項目僅用於授權範圍內嘅安全研究。

A runnable workflow skeleton that turns a "model-driven, hallucination-zero" bug bounty methodology into executable guardrails for AI agents:

- **Evidence-anchored knowledge** — every statement about a target is labeled `[OBS]` (observation, requires evidence pointer), `[INF]` (inference, requires dependency chain), or `[HYP]` (hypothesis, never allowed in reports). Unprovenanced "observations" auto-downgrade to hypotheses.
- **Hallucination firewall** — invalidating a single observation automatically traces and flags every downstream inference for review.
- **Fail-closed scope gate** — every outbound request is checked against a whitelist, account tagging (e.g. `MSOBB`), and per-target rate limits with exponential backoff on 403/429. Whitelist refresh failure = deny by default.
- **Triple verification gates** — Evidence gate (≥3 real reproductions), Adversarial gate (independent challenger whose rebuttals must be answered with experiments), Blank-context gate (a fresh-context agent re-executes only the repro steps).
- **Parallel lane state machine** — up to 3 concurrent targets, legal transitions only, 10 consecutive failures force a target swap, 48h idle auto-deprioritizes.
- **Dual-axis KPIs** — depth axis (prediction accuracy, contradictions found, model corrections) × hallucination axis (hallucination rate, gate interception stats).

## Quick start

```bash
cd bounty_agent
python3 -m pytest tests/ -q    # 49 passed
python3 demo.py                # end-to-end demo run
```

## Structure

```
bounty_agent/
├── agent/
│   ├── labels.py        # OBS/INF/HYP label system + hallucination incident tracing
│   ├── scope.py         # Fail-closed scope gate + rate limiting + backoff
│   ├── gates.py         # Triple verification gates
│   ├── workflow.py      # Parallel lanes + orchestrator + dual-axis KPI (+ cost axis)
│   ├── audit.py         # Evidence vault (SHA-256) + append-only hash-chained audit log
│   ├── persist.py       # ModelStore JSON persistence (survive restarts)
│   ├── cost.py          # Per-hypothesis cost tracking + cost gate
│   ├── deepen.py        # Automated contradiction hunting + builder derivation + lifecycle audit
│   ├── adversarial.py   # Cross-model challenger (rejects same-provider = fake adversarial)
│   ├── proxy.py         # mitmproxy addon — physical outbound request interception
│   └── scope_refresh.py # Whitelist snapshot loader (stale/missing = fail-closed)
├── tests/               # 49 pytest tests
└── demo.py              # End-to-end demo run
```

### v4.1 highlights

- **Physical fail-closed**: run `mitmdump -s agent/proxy.py` so every outbound request is intercepted at the network layer — no reliance on agent discipline
- **Evidence integrity**: PoC artifacts are SHA-256 hashed on deposit; the audit chain detects any after-the-fact tampering
- **Real adversarial testing**: challengers must come from a *different* model provider than the main agent
- **Cost gate**: auto-abandon a hypothesis when its burn exceeds 20% of the expected bounty

## Integration points (for a real agent)

- `gates.BlankContextGate.check(finding, runner)` — swap `runner` for a fresh-context LLM instance fed only the repro steps
- `adversarial.CrossModelChallenger` — register challenger LLMs from *other* providers; each challenge must be answered with experiment evidence
- `scope.ScopeGate.refresh_whitelist(domains)` — wire to a daily job scraping official scope pages; failure auto-fail-closes
- Call `ScopeGate.pre_request(host, account_tag)` before every outbound HTTP request — or run the mitmproxy addon so this is enforced physically

## License

MIT — see [LICENSE](LICENSE).
