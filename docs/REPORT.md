# ContextCon 2026: research, challenge analysis and recommendation

Prepared 2026-11-09. Sources: the full ContextCon brief page (hackerearth.com/lp/challenges/contextcon), the Meko docs (docs.mekodata.ai: MCP server reference, Datapack API, memory, learnings, traces, observability, trace-and-resume, sharing and access), and the open-source repository github.com/yugabyte/meko (`src/meko/docs/api.md`, `cloud.md`, `memory-extraction.md`).

---

## 1. Summary

**Recommendation: Challenge 03, "Remember the Attacker" (agentic fraud detection).** We also take the best parts of the two open challenges: Challenge 07's readable decision traces and audit report, and Challenge 08's measured token comparison.

The project is called **TrailGuard**. In it, four channel agents (login, device, account recovery and support, payments) each see only their own events. They share risk signals through Meko. A Sentinel agent connects those signals before a takeover completes. A Curator agent turns each confirmed attack into an attacker pattern, an analyst approves it, and the pattern is promoted into collective memory, so the next attack of the same kind is caught earlier.

Why this theme wins on the published rubric:

| Lever | Why Challenge 03 is the strongest |
|---|---|
| **Use of Meko (30%)** | Shared memory *is* the detection mechanism. It is not an add-on. The design uses every Meko primitive: datapacks (2, governed), `memory_add`/`memory_search`, `context_search`, knowledge base (playbooks), learnings plus `memory_promote` (human-approved), conversations with `reasoning`/`plan` (decision traces), `track_token_usage`, artifacts (audit reports) and trace-and-resume checkpoints. |
| **Impact (25%)** | Account takeover is one of the most expensive consumer fraud types, and the brief's real pain (each signal looks harmless alone) is exactly what shared context solves. Yugabyte's own customer base includes financial services and cybersecurity, so the judges know this domain. |
| **Technical (20%)** | A real multi-agent system with a synthetic event stream, ground truth, interdiction and a reproducible benchmark. This is harder than a chatbot, and the difficulty shows. |
| **Innovation (15%)** | A clean controlled experiment. The *same* agents run isolated, run with naive context stuffing, run with Meko retrieval, and run with Meko plus learned patterns. Only the context layer changes. Few entries will prove the value of shared memory this directly. |
| **Presentation (10%)** | It is very visual. A live stream, signals passing between agents, a "caught 3 steps before takeover" badge, and a plain-English "why was this blocked?" card. |
| **Prize fit** | The grand prize is "collective memory in action: agents that learn, share and improve over time". Best use of shared memory is "agents that build on each other's learning, with a clear decision-trace story". Both describe TrailGuard's core loop almost word for word. |
| **Competition** | Coding agents (01) and support (02) are the obvious picks and will be crowded. Meko's own team already ships Kode, AgentK and Labs for 01. Fraud needs domain design, so fewer teams will attempt it and a strong entry stands out. |

**Fallback:** Challenge 02, "Never Solve It Twice", is the second-best option. It is lower risk, highly deployable and has a similar learning loop, but it faces more competition and offers less room to innovate (see section 5).

---

## 2. The event: facts that constrain the build

| Item | Detail |
|---|---|
| Format | Worldwide, fully virtual, free. Ages 18+. Solo or teams of 1–4. |
| Hard rule | **Every project must use Meko as its context layer.** Any model and any MCP client may be used. |
| Timeline | Build started Nov 7, 2026. **Submissions are due Jan 17, 2027, 11:59 PM PT.** Judging runs Jan 18–24. Final Demo Day for finalists is live and online (date TBD). Winners are announced Feb 2027. |
| Prizes ($10,000, open to all themes) | Grand $4,000 · Runner-up $2,500 · Second runner-up $1,500 · Best use of shared memory $1,000 · People's choice $1,000 (community vote). |
| Judging | Use of Meko **30%** ("depth of memory, knowledge, datapacks and the self-learning loop"). Impact **25%**. Technical execution **20%** (working demo, code quality, architecture). Innovation **15%**. Presentation **10%**. |
| Submission | (1) Demo video **under 5 minutes**. (2) **Public GitHub repo with setup instructions**. (3) Optional docs on architecture, Meko usage and measured token or relevance metrics. |
| Registration | Name, email, company, LinkedIn, GitHub. |

There is no per-theme prize. All entries compete for the same five awards, so the theme is a vehicle for the strongest overall build and does not need to be the "easiest" theme.

---

## 3. Meko: what we can actually use

### 3.1 Connection

- **MCP endpoint:** `https://mcp.mekodata.ai/mcp` (Streamable HTTP, one session per client). Send `Authorization: Bearer mko_tkn_…` and a `User-Agent`; Meko rejects requests that lack either.
- **REST (Datapack API):** `https://api.mekodata.ai/api/v1`. It covers datapack create, list, describe and update; knowledge-base upload (multipart), status, list and delete; `GET /memories?scope=learnings`; `POST /promote-memories`; `POST /keep-as-memory`; and artifacts. Rate limit: 60 requests/min per key (burst 10).
- **Keys** are account-scoped. Any key reaches all of the account's datapacks, and each agent picks a datapack per call with `datapack_id`.

### 3.2 The 28 MCP tools, grouped by how TrailGuard uses them

| Group | Tools | TrailGuard use |
|---|---|---|
| Context | `context_search` | The Sentinel's single call across signals memory, knowledge and past conversations. Results come back in separate buckets with a `token_savings` estimate. |
| Memory | `memory_add`, `memory_search`, `memory_get_all`, `memory_get_by_id`, `memory_update`, `memory_delete_by_id`, `memory_delete_all`, `memory_promote` | Channel agents write risk signals and read other agents' signals. The Curator writes candidate patterns. The analyst-approved promote moves them into collective memory. `memory_delete_all` resets signals between benchmark runs. |
| Conversations | `conversation_create`, `conversation_add_message` (with `reasoning`, `plan`, `metadata`), `conversation_get`, `conversation_list`, `conversation_update`, `conversation_delete`, `track_token_usage` | One case conversation per investigated account. Every decision is a turn whose reasoning and plan show up as a **Decision trace** in the portal (Langfuse). Token usage is attributed to each decision. |
| Knowledge | `knowledgebase_upload_document`, `knowledgebase_document_status`, `knowledgebase_search`, `knowledgebase_delete_document` | Fraud playbooks, the step-up policy and risk rules, indexed once and searched with hybrid retrieval. |
| Datapacks | `datapack_create`, `datapack_describe`, `datapack_search`, `datapack_list`, `datapack_update`, `datapack_delete` | Bootstrap: create or find `trailguard-signals` and `trailguard-patterns`, and read their counts for the dashboard. |
| Artifacts | `artifact_put`, `artifact_get` | Run reports and audit reports stored as versioned outputs. Run checkpoints are also stored this way for resume. |

### 3.3 Details that matter for correctness

1. **Meko Cloud refuses arguments it does not know.** The client reads `tools/list` at startup and sends only the arguments in each tool's schema.
2. **Most tools need a `conversation_id`**, except `conversation_create` and `conversation_list`. Every agent opens its own conversation per run and passes it on every call.
3. **`agent_id` is for attribution, not filtering.** One account's memories are visible to every agent on that account in the datapack. This is what makes cross-agent signal sharing work with a single key.
4. **Memory search is hybrid** (semantic + keyword + entity boost). Exact IDs such as account, device, IP and payee in the memory text are boosted, which suits indicator matching.
5. **Learnings → promote is one-way** and limited to owners and maintainers. That matches a human-approved "confirmed pattern" gate.
6. **Free-tier quotas: 1,000 conversation messages a month, 10,000 retrievals a month, 10 datapacks** (deleting one does not free its slot), and 100 MB of knowledge storage. The design keeps one decision per turn, gates retrieval on risk, and has a built-in call budget.
7. **Roles (viewer, contributor, maintainer) apply per datapack per account.** True Meko-enforced separation per agent needs a second Meko account invited as a viewer. With one key, separation is enforced by TrailGuard itself (each agent has a datapack allowlist) and documented as such.

---

## 4. Challenge-by-challenge analysis

Each brief is summarised from the page, followed by our assessment.

### 01: One Memory, Every Coding Agent (coding agents and the agent development lifecycle, ADLC)

- **Asks for:** one datapack of standards, decisions and history; 2+ different coding agents connected; a decision learned in one agent followed by another; design-to-merge lifecycle; before/after numbers (rule violations, rework). A review agent is encouraged.
- **Meko fit:** native. This is Meko's flagship use case.
- **Assessment:** the easiest theme to start, but the hardest to stand out in. Meko's own team already ships **Kode** (multi-session coding on Meko), **AgentK** (the PR reviewer) and an ADLC **Lab**, so an entry here is measured against the sponsor's own product. Much of the demo is configuration (connecting Claude Code, Cursor and Codex), not engineering. Expect the most entries here.
- **Verdict:** high Meko fit, low innovation headroom, very high competition.

### 02: Never Solve It Twice (agentic support)

- **Asks for:** search before solving; store verified fixes; human escalations fed back into memory; 30+ synthetic tickets with repeats; first-time vs repeat comparison (time, tokens, steps); one agent reusing another's fix. A human-in-the-loop "approved fixes only" step is encouraged.
- **Meko fit:** excellent. `context_search` + `memory_add` + learnings and promote map one to one.
- **Assessment:** clear metrics and an obvious business case; it could be deployed against a helpdesk. However, "support bot with memory" is the most common idea at any memory hackathon, and the metric (repeat tickets are faster) is expected rather than surprising.
- **Verdict:** strong and safe. Our **fallback**.

### 03: Remember the Attacker (agentic fraud detection) ← **chosen**

- **Asks for:** several detection agents (login, device, transaction, support channel) that read and write shared memory; spotting takeover across signals before it completes; reusing known attacker patterns; explaining every block, step-up or allow through traces; signals and confirmed patterns in **separate datapacks**; a synthetic stream of **up to ~2,000 events** with planted takeovers, saving only risk signals and confirmed patterns as memories; results showing attacks caught before takeover, false positives and **steps early**; trace walkthroughs for **≥3 decisions**. A comparison against the same agents without shared memory is encouraged.
- **Meko fit:** the best of all eight. The problem only exists *because* context is siloed, so the A/B result is a direct measurement of Meko's value.
- **Assessment:** the measurable outcomes are concrete and the "without shared memory" comparison is built into the brief. The domain gives us a built-in learning loop (confirmed fraud → pattern → earlier catch) and governance (who may write a confirmed pattern). It also needs more design work, which keeps competition down.
- **Verdict:** best balance of Meko depth, impact, innovation and demo appeal.

### 04: Campaigns That Know the Customer (agentic marketing)

- **Asks for:** a unified customer datapack; a multi-agent campaign team; 2 campaign cycles where cycle 2 uses what cycle 1 learned; governance over which agent sees which data; assets with traces.
- **Assessment:** the "results" of a synthetic campaign are invented, so the learning loop is hard to make convincing. Quality is subjective and the impact story is weaker for a database company's judges.
- **Verdict:** medium.

### 05: The Planner That Remembers (financial planning)

- **Asks for:** a synthetic household or business profile; specialist planners sharing one context; 3+ sessions with a life event changing the plan; trace-backed recommendations. A what-if planner is encouraged.
- **Assessment:** this mostly shows long-term memory for a single user, not *collective* memory across agents, which is what the grand prize rewards. It also carries the "not financial advice" constraint.
- **Verdict:** medium-low.

### 06: Patient Context, Governed (medical records)

- **Asks for:** synthetic patient records in governed datapacks; care agents (summariser, medication reconciliation, care plan); per-agent datapack access (e.g. billing can't see clinical notes); traces as the audit trail.
- **Assessment:** strong governance story and high impact. However, Meko keys are account-scoped, so *real* access separation needs several Meko accounts, and the learning loop is weak. Healthcare demos are also common.
- **Verdict:** medium-high, weaker on the 30% "self-learning loop" criterion.

### 07: Show Your Work (best auditability, any domain)

- **Asks for:** traces of every turn, retrieval, memory update and tool call; readable by a non-engineer; intact across agents; replay or resume; 10+ decisions traced; an "explain this decision" walkthrough and an audit report. Judging test: can a judge who has never seen the system explain one decision from its trace within 2 minutes?
- **Assessment:** strong as a layer, thin on its own. We fold its deliverables (10+ traced decisions, a plain-English explainer, an audit report, resume from checkpoint) into TrailGuard.

### 08: Do More With Fewer Tokens (token efficiency, any domain)

- **Asks for:** a 3+ agent task; baseline vs Meko on the same inputs (≥10 runs each); a table of tokens, latency, cost and quality; a methodology note.
- **Assessment:** rigorous but dry on its own, and it re-measures a claim Meko already publishes. We fold it in as the "naive context stuffing" baseline, which shows the retrieval-quality paradox from the ContextCon page on our own data.

---

## 5. Scoring matrix

The scores are our judgement (1–10) against the published weights. "Competition" is an estimate and not part of the weighted score.

| # | Theme | Meko (30) | Impact (25) | Tech (20) | Innov. (15) | Pres. (10) | **Weighted** | Competition |
|---|---|---|---|---|---|---|---|---|
| 01 | Coding agents | 8 | 8 | 6 | 4 | 6 | 6.80 | Very high |
| 02 | Support | 9 | 8 | 7 | 5 | 8 | 7.65 | High |
| **03** | **Fraud** | **10** | **9** | **9** | **9** | **9** | **9.30** | **Low–medium** |
| 04 | Marketing | 8 | 6 | 6 | 6 | 7 | 6.70 | Medium |
| 05 | Finance | 7 | 6 | 6 | 5 | 7 | 6.25 | Medium |
| 06 | Medical | 8 | 8 | 7 | 6 | 7 | 7.40 | Medium |
| 07 | Auditability (alone) | 7 | 7 | 7 | 6 | 7 | 6.85 | Medium |
| 08 | Token efficiency (alone) | 7 | 6 | 8 | 4 | 6 | 6.40 | Low |

Real-world deployability (the "real-time implementation" question):

- **03 Fraud:** the agents run asynchronously on risk events (logins, credential changes, payee adds, large transfers) and return a step-up, hold or block decision in seconds. That is how production risk engines already treat these events, while card authorisation stays on the millisecond rules path. The channel agents' signal writers map onto existing detection rules and models, and Meko replaces the case-management memory each team keeps separately.
- **02 Support:** the most direct to deploy (a helpdesk integration), which is why it is the fallback.

---

## 6. The plan for winning

**The claim we will prove with numbers:** *the same agents, with the same models and rules, catch account takeovers earlier when, and only when, they share context through Meko, and they keep improving as confirmed attacks become shared patterns.*

Four benchmark modes on identical event streams. Only the context layer changes:

| Mode | Context | What it shows |
|---|---|---|
| `isolated` | Each agent knows only its own channel | The brief's "without shared memory" baseline: most cross-channel attacks get through |
| `stuffed` | All agents' signals pasted into every prompt (no Meko) | Catches more, but tokens grow with history: the retrieval-quality paradox |
| `meko` | Signals shared and retrieved through Meko; playbooks in the knowledge base | Catches attacks before takeover at a fraction of `stuffed`'s tokens |
| `meko+patterns` | Plus analyst-approved attacker patterns from the previous epoch | Learning over time: the same attacker playbook is caught at the first step |

Mapping to the prizes:

- **Grand prize:** the learning curve. Epoch 1 to epoch 2 gives fewer misses and more steps early.
- **Best use of shared memory:** the decision-trace story ("login agent saw X → recovery agent saw Y → Sentinel blocked at step 2, citing memories #a and #b and playbook §3").
- **People's choice:** a polished live dashboard and a short, clear video.

---

## 7. Deliverables

| # | Deliverable | Where |
|---|---|---|
| 1 | This research and analysis report | `docs/REPORT.md` |
| 2 | Design spec | `docs/superpowers/specs/2026-11-09-trailguard-design.md` |
| 3 | Implementation plan | `docs/superpowers/plans/2026-11-09-trailguard.md` |
| 4 | Working system: simulator, 6 agents, Meko client, benchmark, dashboard, CLI | `src/trailguard/` |
| 5 | Knowledge base: fraud playbooks uploaded to Meko | `knowledge/` |
| 6 | Tests (offline, deterministic) | `tests/` |
| 7 | README with setup (hackathon requirement) | `README.md` |
| 8 | Architecture and Meko usage doc (optional requirement) | `docs/ARCHITECTURE.md` |
| 9 | Metrics methodology and results table (optional requirement, Challenge 08 style) | `docs/METHODOLOGY.md` + generated `runs/<id>/results.md` |
| 10 | Generated audit report and ≥3 trace walkthroughs (Challenge 03 and 07 style) | generated `runs/<id>/audit.md`, also stored as a Meko artifact |
| 11 | Demo video script under 5 minutes | `docs/DEMO_SCRIPT.md` |
| 12 | Submission checklist and copy | `docs/SUBMISSION.md` |

---

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| No Meko or LLM key in this environment yet | Everything runs offline against an in-process stand-in with the same interface (`--meko fake`) and a deterministic decider (`--llm heuristic`). Both are clearly labelled in the UI and in every report. The demo and submitted numbers must come from real Meko (`--meko cloud`). |
| Free-tier quotas (1,000 conversation messages a month) | Decisions are logged only for escalated cases. A built-in call budget stops a run before it exhausts the quota. Live runs default to small streams; large benchmarks use `--trace-sample`. |
| Meko latency on 2,000 events | Retrieval is gated on risk (most benign events never call Meko), calls run concurrently per agent, and the batch benchmark is separate from the live demo pace. |
| Memory extraction rewriting signal text | Signals are written with `memory_add` as one self-contained line that carries exact identifiers. The smoke test (`scripts/meko_smoke.py`) checks read-after-write and that the text comes back verbatim before any benchmark. |
| Results looking rigged on synthetic data | Benign "bait" cases (travellers, phone upgrades, forgotten passwords, shared family devices) give real false-positive pressure. We publish the generator, seeds and methodology, and report false positives next to the catches. |
| One key = no Meko-enforced separation between agents | Per-agent datapack allowlists are enforced in code. Optionally, invite a second Meko account as a viewer on `trailguard-patterns` to show Meko-level enforcement. |

---

## 9. What I need from you

1. **Register** on HackerEarth and **create a Meko account** (cloud.mekodata.ai/signup). Generate an API key under Settings > API Keys and put it in `.env` as `MEKO_API_KEY`.
2. **An Anthropic API key** (`ANTHROPIC_API_KEY`) for the Sentinel, Curator and Explainer agents. Without one, TrailGuard uses the heuristic decider.
3. Decide on a team (1–4) and who records the video.
