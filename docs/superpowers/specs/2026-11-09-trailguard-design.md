# TrailGuard: design

ContextCon Challenge 03, "Remember the Attacker", with Challenge 07 (auditability) and Challenge 08 (token efficiency) built in as supporting evidence. The reasons for this choice are in [docs/REPORT.md](../../REPORT.md).

## 1. Intent

Account takeover (ATO) unfolds over several steps, and each step reaches a different system: a credential-stuffing attempt, a new device, a support call asking to move a phone number, a new payee, a small test payment, then the drain. Each step looks harmless to the one agent that sees it. TrailGuard gives the detection agents one shared, governed context in Meko, so that:

1. a signal one agent sees is available to every other agent at once (**collective memory**),
2. the agents connect those signals into a takeover pattern **before the takeover completes**,
3. every confirmed attack becomes an analyst-approved **attacker pattern** that catches the next attack of that kind earlier (**self-learning loop**), and
4. every allow, step-up, hold or block can be explained to a non-engineer from its **decision trace** in under two minutes.

The project has to *prove* this with numbers. The same agents, rules and model run on the same event streams while only the context layer changes.

## 2. Goals, non-goals, anti-goals

**Goals**
- Meet every expected outcome in the Challenge 03 brief:
  - a synthetic stream of up to ~2,000 events with planted takeovers,
  - a multi-agent system sharing memory through Meko,
  - detection results (caught before takeover, false positives, steps early),
  - trace walkthroughs for at least 3 decisions,
  - the encouraged comparison without shared memory.
- Meet the Challenge 07 outcomes as a bonus: 10+ traced decisions, a plain-English "explain this decision" view, an audit report generated from trace data, and resume from checkpoint.
- Meet the Challenge 08 outcomes as a bonus: a baseline vs Meko results table (tokens, latency, cost, quality) and a methodology note.
- Use Meko deeply and correctly: two governed datapacks, memory, `context_search`, knowledge base, learnings with human-approved promote, conversations carrying `reasoning`/`plan`, `track_token_usage` and artifacts.
- Run end to end offline (no keys) for development and CI, and run live against Meko Cloud and Claude for the demo and the submitted numbers.
- Provide a dashboard that works as the 5-minute demo surface.

**Non-goals**
- A production fraud engine, real card authorisation latency (milliseconds) or ML model training.
- Real customer data. Everything is synthetic and generated from a seed.
- Multi-tenant SaaS, authentication or deployment beyond `localhost`.

**Anti-goals** (failures even if it "works")
- Results that only hold because the simulation is rigged. Benign bait cases must create real false-positive pressure, and seeds, generator and method are published.
- Calling the offline stand-in "Meko". Every artefact states which backend produced it, and submitted numbers come from Meko Cloud.
- Hiding Meko behind an abstraction so thick the judges can't see it. Meko tool names appear in traces, logs and the UI.
- Burning the free-tier quota by accident. Every run enforces a call budget.

## 3. Constraints (from research)

- Meko Cloud MCP: `https://mcp.mekodata.ai/mcp`, Streamable HTTP with a session. Every request needs `Authorization: Bearer mko_tkn_…` and a `User-Agent`.
- **Meko Cloud refuses unknown tool arguments.** The client filters arguments against each tool's `inputSchema` from `tools/list`.
- **`conversation_id` is required** by most tools (not `conversation_create` or `conversation_list`). It is 32 hex characters (hyphens stripped).
- `agent_id` attributes calls but does not filter results. All agents on one account read each other's memories in a datapack.
- Tool replies come back as text content holding JSON, also in `structuredContent.result`. Errors a caller can act on come back as `{"error": code, "detail": text}` with `isError: false`, so the client must check for this shape.
- REST: `https://api.mekodata.ai/api/v1`, `{data}` / `{data:null, error:{code,message}}` envelope, 60 requests/min per key. Used for knowledge-base multipart upload, the learnings list, `promote-memories` and `keep-as-memory`.
- Free tier: 1,000 `conversation_add_message` calls/month, 10,000 retrievals/month (`context_search`, `memory_search`, `knowledgebase_search`), 10 datapacks (no slot returned on delete), 100 MB of knowledge plus artifacts, 5 MB per artifact.
- Promote is one-way and limited to owners and maintainers.
- The development machine runs Windows 11, Python 3.12, uv and Node 22. No Meko or LLM keys exist yet.

## 4. Decisions made (builder's calls, flagged for review)

| Decision | Choice | Why |
|---|---|---|
| Language/runtime | Python 3.12, uv, async (`asyncio`) | Official `mcp` SDK and `anthropic` SDK; fastest to build and to read. |
| LLM | Claude via `anthropic` SDK; default `claude-opus-5-5` with structured JSON output and `fallbacks: "default"`; `--model claude-haiku-5-5` for cheap benchmark runs | The hackathon supports Claude first-class; model cost is the user's call, so the default is the most capable model and cheaper runs are one flag away. |
| Offline mode | `--meko fake` (in-process stand-in persisted to JSON) + `--llm heuristic` (deterministic policy) | No keys yet; CI must be deterministic. Labelled everywhere. |
| UI | FastAPI + Server-Sent Events + static HTML/CSS/JS, no build step | One process, zero toolchain risk on demo day. |
| Datapacks | `trailguard-signals` and `trailguard-patterns` | The brief asks for raw signals and confirmed patterns in separate datapacks. Playbooks live in the patterns knowledge base. |
| Signal format | One self-contained line, `TG-SIGNAL v1 \| key=value \| …`, with exact identifiers; parsed from text first, metadata second | Survives any reply shape; exact IDs get Meko's keyword and entity boost. |
| Decision policy | The Sentinel decides from evidence, playbook passages and pattern matches; the heuristic decider implements the same written policy | Same policy text drives both, so offline numbers are comparable. |

## 5. System overview

```
             synthetic event stream (seeded, ground truth attached)
                                 │  (replayed in time order)
      ┌──────────────┬───────────┴──────────┬────────────────┐
      ▼              ▼                      ▼                ▼
 Login agent    Device agent      Recovery/support agent   Payments agent
 (auth events)  (fingerprints)    (resets, MFA, phone,     (payees, card tests,
                                   email, support chats)     transfers)
      │  memory_add TG-SIGNAL           │                    │
      └──────────────► Meko datapack: trailguard-signals ◄───┘
                        (collective memory, case conversations,
      ▲  memory_search   decision traces, token usage, artifacts)
      │  at gates                        ▲
      │                                  │ conversation_add_message(reasoning, plan)
      │        escalate when             │ track_token_usage, memory_add TG-DECISION
      └────── case risk ≥ 40 ──────► Sentinel (Claude) ──context_search──► trailguard-patterns
                                         │                              (playbooks KB +
                                         ▼                               collective memory of
                         ALLOW / STEP_UP / HOLD / BLOCK                  confirmed patterns)
                                         │                                      ▲
                        interdiction applied to the stream                      │ memory_promote
                                         │                                      │ (analyst approves)
                       confirmed cases ─►  Curator (Claude) ── memory_add TG-PATTERN (learning)
                                         │
                                         ▼
                            Explainer → "why" cards, audit report → artifact_put
```

## 6. Synthetic world (`trailguard.sim`)

All values derive from `(seed, epoch)`, so the same inputs always produce the same stream.

**Customers** (~250 per stream): `C0001…`, home country and city, 1–2 known devices (`d-xxxx`), a home IP block, typical transfer amount ($20–$300), and 1–4 long-standing payees.

**Event** fields: `event_id`, `ts` (ISO-8601 UTC), `channel` (`login|device|recovery|payments`), `type`, `account_id`, `ip`, `country`, `device_id`, `attrs` (dict), and `truth` = `{attack_id, ttp, step, completes_takeover, benign_case}` (never shown to agents).

**Event types by channel**
- login: `login_failed`, `login_success`, `step_up_passed`, `step_up_failed`
- device: `device_seen` (attrs: `new_to_account`, `emulator`), emitted with every successful login
- recovery: `support_contact` (attrs: `topic`), `phone_change`, `email_change`, `password_reset_request`, `password_reset_complete`, `mfa_device_added`
- payments: `payee_add` (attrs: `payee_id`, `payee_country`), `card_test` (amount < $2), `transfer` (attrs: `amount`, `payee_id`)

**Attack TTPs**, each an ordered list of steps with one *completion* step (the first irreversible harm: money out or owner locked out):

| TTP | Steps (channel) | Completion |
|---|---|---|
| `credential_stuffing` | spray: 1–2 `login_failed` on ~30 accounts from a proxy IP pool (login) → on ~3 victims: `login_success` new device (login + device) → `payee_add` mule (payments) → `transfer` large (payments) | transfer |
| `sim_swap` | `support_contact` "lost phone, move my number" from new IP (recovery) → `phone_change` (recovery) → `password_reset_request` + `_complete` via SMS (recovery) → `login_success` new device (login + device) → `payee_add` → `transfer` | password_reset_complete |
| `session_hijack` | `login_success` from a foreign country within 2 h of a home login, new device (login + device) → `email_change` (recovery) → `password_reset_complete` (recovery) → `transfer` | password_reset_complete |
| `mule_ring` | one device fingerprint logs into 4–6 accounts, interleaved: `login_success` (login + device) → `card_test` (payments) → `payee_add` shared mule → `transfer` | transfer (per account) |
| `low_and_slow` | over 3 days: `password_reset_request` (abandoned) → 2× `login_failed` → `mfa_device_added` → `login_success` new device → `card_test` → `transfer` | transfer |

**Benign bait** (false-positive pressure): a traveller abroad on a *known* device; a phone upgrade (new device, home IP, step-up passed); a forgetful user (failed logins + reset from a known device); a shared family device (2 accounts); a large transfer to a long-standing payee; a new landlord payee from a known device and home IP.

**Epochs.** Epoch 2 uses new victims and a new seed. It reuses part of the attacker infrastructure (60% of mule payees, the ring device family, the proxy /24 subnets) and adds one variant TTP ordering. This is what "remember past attacks" can exploit.

**Scale.** `--events` sets a target size (default 600 for live runs; the benchmark uses 2,000). Attacks are about 8–12% of events.

## 7. Agents (`trailguard.agents`)

### 7.1 Channel agents (login, device, recovery, payments)

Each agent receives only its own channel's events. For each event:

1. **Detect.** Deterministic local detectors, the same in every mode, emit zero or more signals with type, severity and weight. Examples:
   - login: `ip_spray` (an IP failing on ≥5 accounts in 1 h, entity = IP), `new_device_login`, `geo_anomaly`, `impossible_travel`, `step_up_failed`
   - device: `device_multi_account` (≥3 accounts in 24 h), `new_device`, `emulator`
   - recovery: `risky_support_contact`, `phone_change`, `email_change`, `reset_unknown_device`, `mfa_change`
   - payments: `new_payee`, `card_test`, `large_transfer` (>5× typical), `fresh_payee_transfer` (payee <24 h old)
2. **Share.** In shared modes, each signal is written with `memory_add` to `trailguard-signals` as one `TG-SIGNAL v1` line. "Save only risk signals" holds: benign, signal-free events are never written.
3. **Gate.** Login success on a new device, any credential change, `payee_add`, `card_test` and `transfer` are *gates*. At a gate the agent builds the **case**, meaning the signals related to this account and to the device, IP and payee involved:
   - `isolated`: only this agent's own signals (in-process).
   - `stuffed`: every agent's signals so far (in-process log, perfect recall).
   - `meko`, `meko+patterns`: `memory_search` on `trailguard-signals` with a query naming the account, device, IP and payee (limit 25), then exact-entity filtering.
4. **Score.** Case risk = the sum of the weights of distinct signals in the last 72 h (decayed after 24 h), capped at 100. In `meko+patterns`, a `context_search` on `trailguard-patterns` adds `known_attacker_ioc` (+60) when a confirmed pattern's indicators match the case, and `ttp_match` (+30) when the case's signal sequence matches a confirmed TTP.
5. **Escalate** to the Sentinel when risk ≥ 40.

### 7.2 Sentinel (decision agent)

Input: the gate event, the case signals (with Meko memory IDs, writing agent and score), playbook passages, and pattern matches. In `meko*` modes it calls `context_search` on `trailguard-patterns` for playbooks and patterns. In `isolated` and `stuffed` modes, the same playbook text is passed from local files, so policy access is equal and only signal sharing differs. Output (JSON, validated):

```json
{"decision":"ALLOW|STEP_UP|HOLD|BLOCK","risk":0-100,"hypothesis":"sim_swap",
 "reasons":["..."],"evidence":[{"memory_id":"...","agent":"recovery-agent","summary":"..."}],
 "policy_refs":["step-up-policy §2"],"pattern_id":"PAT-…|null","plain_english":"..."}
```

The policy lives in `knowledge/step-up-policy.md` and is uploaded to the knowledge base:
- risk ≥ 80: BLOCK on money movement, HOLD on credential changes.
- 50–79: STEP_UP, **except** HOLD when the phone number or MFA device changed in the last 72 h (step-up would reach the attacker).
- Below 50: ALLOW.
- A known attacker indicator always means BLOCK.

The `heuristic` decider implements exactly this. The `claude` decider receives the passages and decides. It uses structured output, and the result is validated with one retry, falling back to the heuristic on failure (recorded in the trace).

Each decision is logged:
- `conversation_add_message` on the case conversation (one per account per run): `input` = case summary, `output` = decision JSON, `reasoning`, `plan` = the steps taken, `metadata` = run, event, mode and decision
- `track_token_usage` for each LLM call
- `memory_add` of a `TG-DECISION v1` line, so other agents see that the account is under watch
- a local trace record (JSONL) holding every Meko ID involved

### 7.3 Outcome simulation

- ALLOW: the event proceeds.
- STEP_UP: a benign user passes (counted as friction). An attacker passes only if the attack already controls the second factor (after `phone_change` in `sim_swap`, or after `mfa_device_added` in `low_and_slow`); otherwise the attacker fails, `step_up_failed` is emitted and the attack is interdicted.
- HOLD or BLOCK: the attack is interdicted (its remaining steps for that victim are dropped). For benign users this is a false positive.

### 7.4 Curator (learning loop)

After a run, confirmed cases come from the ground-truth labels, which stand in for the disputes and chargebacks that confirm fraud in real life. For each confirmed attack (caught or missed), the Curator writes a `TG-PATTERN v1` memory to `trailguard-patterns` containing:
- the TTP
- the observed step sequence
- indicators (proxy subnet, device fingerprint, mule payee)
- the earliest signal that would have worked
- the recommended action

Patterns are deduplicated per TTP and indicator set. Claude writes the human-readable summary, or a template does when Claude isn't available. These memories are **learnings** (candidates). The analyst approves them in the dashboard or with `trailguard learn --approve`, which calls `memory_promote` into collective memory. Rejecting a candidate calls REST `keep-as-memory`. Only the Curator and the analyst path can write to `trailguard-patterns`. Each agent has a datapack allowlist enforced by the client wrapper; channel agents and the Sentinel can only read it.

### 7.5 Explainer and audit report

Built deterministically from trace data. Claude optionally polishes the headline. Each decision card has:
- a headline in plain English
- "what happened", the triggering event
- "what the agents knew", each piece of evidence with its agent, time, Meko memory ID and match score
- "the rule applied", the playbook passage
- "the pattern recognised", if any
- "what happened next", e.g. the attacker's next step was blocked, or the user passed step-up
- the Meko conversation and message IDs, and the portal path

The audit report (Markdown) contains:
- the run header (backend, model, mode, seed)
- the metrics table
- a decision table (all decisions, at least 10)
- full walkthroughs for at least 3 decisions (one block, one step-up, one allow)
- learning-loop changes
- a Meko references appendix

It is stored with `artifact_put`, and its hash is remembered as a `TG-ARTIFACT` memory.

### 7.6 Resume

Every 100 events the engine writes a checkpoint: `{run_id, offset, decisions, interdicted, counters}`. It is stored with `artifact_put` to `trailguard-signals`, and its hash goes into a `TG-CHECKPOINT` memory. `run --resume RUN_ID` finds the latest checkpoint, fast-forwards local detector state over `events[0:offset]` (deterministic, no Meko calls) and continues. `--crash-at N` simulates a failure for the demo.

## 8. Meko client (`trailguard.meko`)

- `MekoCloud`:
  - MCP over the official `mcp` SDK (`streamablehttp_client` + `ClientSession`) with auth headers
  - `tools/list` cached at connect; arguments filtered to each schema's properties
  - JSON parsing of text content; in-band error detection (`{"error":…}`) raising `MekoError(code, detail)`
  - retry with backoff on 429/5xx and transport errors (max 3)
  - a concurrency semaphore (4)
  - REST through `httpx` for knowledge-base upload, learnings, promote and keep-as-memory
- `FakeMeko`: the same interface, in process, persisted to `runs/fake_meko.json`. It provides:
  - hybrid scoring (token overlap + exact-identifier boost)
  - knowledge-base chunking by Markdown heading
  - sha256 artifacts, learnings and promote semantics
- `Meter`: per-tool call counts and latency, plus **a per-run budget** (`max_retrievals`, `max_messages`; defaults 400 and 120). A shared-mode agent that hits the budget raises `BudgetExceeded`, and the run ends cleanly with partial results marked.
- `AgentScope`: wraps the client per agent with a fixed `agent_id`, the agent's conversation, and a datapack allowlist (read/write sets).

## 9. Benchmark and metrics (`trailguard.engine`, `trailguard.metrics`)

`trailguard bench --modes isolated,stuffed,meko,meko+patterns --seeds N --events 2000`. The procedure:
1. Run epoch 1 for each mode.
2. The Curator learns from the epoch-1 `meko` run, and the patterns are auto-approved in the bench (flag) or by hand in the demo.
3. Run epoch 2 for each mode. `meko+patterns` only differs from `meko` on epoch 2.

Metrics per run:
- attack outcomes: attacks, prevented (interdicted at or before the completion step), prevented early (before completion), missed, and mean and median steps early
- false positives: benign accounts held or blocked, benign accounts stepped up, and the false-positive rate
- decisions and escalations
- LLM tokens (in, out, total, per decision); measured with Claude, estimated at chars/4 with the heuristic decider and labelled `estimated`
- Meko calls by tool
- decision latency (p50/p95)
- estimated cost: a price table in config, set per model from current pricing

`results.md` and `results.json` are written for each benchmark, giving the mean ± stdev across seeds.

## 10. Dashboard (`trailguard.web`)

FastAPI app, `trailguard serve` on `127.0.0.1:8000`.

**API**
- `GET /api/status`
- `POST /api/runs` (mode, seed, epoch, events, pace)
- `GET /api/runs/{id}/stream` (SSE: `event`, `signal_written`, `signal_read`, `escalation`, `decision`, `interdiction`, `takeover_completed`, `metrics`, `done`)
- `GET /api/runs/{id}`
- `GET /api/runs/{id}/decisions/{n}`
- `GET /api/learnings`, `POST /api/learnings/{id}/approve|reject`
- `GET /api/bench`
- `GET /api/runs/{id}/audit`

**Views**
1. **Live**: an event ticker; four agent lanes plus the Sentinel; a Meko memory feed showing each signal as written and when another agent reads it ("learned by …"); attack tracker cards with "stopped N steps before takeover" or "takeover completed".
2. **Explain**: the decision card from section 7.5.
3. **Learnings**: pending patterns with approve and reject.
4. **Results**: the benchmark table and bar charts (hand-drawn SVG).
5. **Audit**: the rendered report with a download link.

A banner always shows the backend (`Meko Cloud` or `OFFLINE stand-in`) and the decider (`claude-haiku-5-5` or `heuristic`).

## 11. CLI (`trailguard`)

`doctor`, `setup` (datapacks + knowledge-base upload + wait for indexing → `.trailguard.json`), `generate`, `run`, `learn`, `bench`, `explain`, `audit`, `reset --signals`, `serve`. Global flags: `--meko cloud|fake`, `--llm claude|heuristic`, `--model`.

## 12. Testing

pytest, offline and deterministic:
- generator determinism and attack structure (each attack has exactly one completion step; benign cases are present)
- detectors
- case scoring and decay
- heuristic policy, including the SMS exception
- outcome simulation and interdiction
- metrics on a hand-built mini stream
- `FakeMeko` search semantics and promote
- `MekoCloud` argument filtering and error parsing against a mocked transport using the documented reply shapes
- web API smoke test (TestClient)
- end-to-end offline benchmark asserting the *direction* of results (`meko` prevents ≥ `isolated`; `meko` tokens < `stuffed` tokens), with no fixed numbers

`scripts/meko_smoke.py` checks a live key:
- connect and list tools
- create or find the datapacks
- `memory_add`, then `memory_search` read-after-write latency and verbatim text
- `context_search` buckets
- conversation and message
- `track_token_usage`
- artifact round trip

## 13. Left to the builder

The exact weights and thresholds (tuned so isolated agents face a real precision/recall trade-off), the visual design of the dashboard, the prompt wording, and the internal module boundaries within the structure above.
