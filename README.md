# Bounty Agent v4.0 — Model-Driven Bug Bounty Hunting Workflow

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
python3 -m pytest tests/ -q    # 24 passed
python3 demo.py                # end-to-end demo run
```

## Structure

```
bounty_agent/
├── agent/
│   ├── labels.py     # OBS/INF/HYP label system + hallucination incident tracing
│   ├── scope.py      # Fail-closed scope gate + rate limiting + backoff
│   ├── gates.py      # Triple verification gates
│   └── workflow.py   # Parallel lanes + orchestrator + KPI
├── tests/            # 24 pytest tests
└── demo.py           # End-to-end demo: modeling → contradiction hunting → probe → gates → KPI
```

## Integration points (for a real agent)

- `gates.BlankContextGate.check(finding, runner)` — swap `runner` for a fresh-context LLM instance fed only the repro steps
- `gates.AdversarialGate.check(finding, rebuttals)` — rebuttals produced by an independent challenger instance; every challenge must be answered with experiment evidence
- `scope.ScopeGate.refresh_whitelist(domains)` — wire to a daily job scraping official scope pages; failure auto-fail-closes
- Call `ScopeGate.pre_request(host, account_tag)` before every outbound HTTP request

## License

MIT — see [LICENSE](LICENSE).
