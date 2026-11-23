# Submission kit

Submissions close **17 January 2027, 11:59 PM PT** on HackerEarth (ContextCon: Remember Everything).

## Checklist

- [ ] Registered on HackerEarth (name, email, company, LinkedIn, GitHub) and joined the Meko Discord
- [ ] Meko account created; `MEKO_API_KEY` and `ANTHROPIC_API_KEY` in `.env` (never committed; `.env` is in `.gitignore`)
- [ ] `uv run python scripts/meko_smoke.py` passes all checks against Meko Cloud
- [ ] `uv run trailguard setup` done; knowledge files show as indexed
- [ ] Benchmark run on **Meko Cloud** (`uv run trailguard bench --seeds 1-3 --events 1000`); `runs/bench-*/results.md` copied into `docs/METHODOLOGY.md` under "Meko Cloud results"
- [ ] At least one run's audit report stored in Meko (`trailguard audit --run <id>`) and its decisions visible under Datapack > Conversations
- [ ] Demo video recorded from `docs/DEMO_SCRIPT.md`, **under 5 minutes**, context banner reading "Meko Cloud"
- [ ] Public GitHub repository pushed, with a LICENSE file (Apache-2.0) and the README's setup steps checked on a clean clone
- [ ] The README's results table filled in with the Meko Cloud numbers
- [ ] Form submitted: video link, repo link, docs (ARCHITECTURE, METHODOLOGY)

## Theme

Challenge 03: "Remember the Attacker" (agentic fraud detection). It also delivers Challenge 07's auditability outcomes (10+ traced decisions, a non-engineer walkthrough, a generated audit report, resume from trace) and Challenge 08's measured baseline vs Meko comparison.

## Short description (≈50 words)

TrailGuard is a team of fraud agents (login, device, recovery and payments) that share risk signals through Meko and stop account takeovers before they complete. Every decision leaves a plain-English Meko decision trace. Confirmed attacks become analyst-approved patterns in collective memory, so the next attack from the same attackers is stopped earlier.

## Long description

**The problem.** Account takeover is a sequence: a support call to move a phone number, an SMS password reset, a new-device login, a new payee, a drain. Each step reaches a different team's system and looks harmless alone, so fraud gets through the gaps between agents.

**What we built.** Four channel agents each watch one stream and write only risk signals to a Meko datapack as single-line memories with exact identifiers. At every risky action they `memory_search` for what the other agents saw about this account, device, network and payee. A Sentinel decides escalated cases against a step-up policy held in Meko's knowledge base (retrieved with `context_search`). It logs each decision as a conversation turn with reasoning and plan, which Meko shows as a decision trace, and attributes Claude's token use with `track_token_usage`. Decisions are written back as shared signals, so a block on one account warns every agent that later meets the same device or payee. After a run, a Curator turns confirmed attacks into attacker patterns: infrastructure indicators, plus a signature of signals genuine customers almost never show. These stay Meko learnings until an analyst approves them with `memory_promote`. Two datapacks separate raw signals from confirmed patterns, and per-agent allowlists keep only the Curator writing patterns. Checkpoints and audit reports are Meko artifacts, so a crashed run resumes from its trace.

**How we know it works.** A seeded stream (up to 2,000 events) plants five takeover techniques among seven kinds of genuine look-alikes: travellers, phone upgrades, forgotten passwords, a lost phone, family devices, big purchases and new landlords. The same agents and rules run four ways, isolated, pasting all signals into prompts, Meko retrieval, and Meko plus approved patterns. We report, per mode, the attacks stopped before takeover, how many steps early, genuine customers held or stepped up, tokens, latency, Meko calls and cost.

**Meko features used.** Datapacks (2), `memory_add`, `memory_search`, `context_search`, knowledge base upload and indexing, learnings with `memory_promote` and keep-private, `memory_get_all(promoted)`, conversations with reasoning and plan (decision traces), `track_token_usage`, artifacts and `memory_delete_all`, over the MCP endpoint and the Datapack REST API.

## Prize mapping

- **Grand prize** ("collective memory in action: agents that learn, share and improve over time"): shared signals, plus the epoch-1 to epoch-2 learning curve.
- **Best use of shared memory** ("agents that build on each other's learning, with a clear decision-trace story"): the cross-agent reads on the trail and the decision cards.
- **People's choice:** the live trail visual and the plain-English cards.
