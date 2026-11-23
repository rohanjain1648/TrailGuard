# TrailGuard architecture

TrailGuard is a team of fraud-detection agents that share one governed context in Meko. Each agent sees only its own channel. Meko is how a signal the login agent saw becomes something the payments agent knows before it lets money leave.

## The pieces

```
                synthetic event stream (seeded; ground truth hidden from agents)
                                   │ replayed in time order
     ┌──────────────┬──────────────┴───────────┬──────────────────┐
     ▼              ▼                          ▼                  ▼
 Login agent    Device agent      Recovery & support agent    Payments agent
     │  detect → memory_add TG-SIGNAL (only risk signals are saved)
     └──────────────► Meko datapack  trailguard-signals  ◄────────┘
                      collective memory of signals · case conversations
     ▲ memory_search  decision traces · token usage · checkpoints · reports
     │ at each gate               ▲
     │                            │ conversation_add_message (input, output, reasoning, plan)
     │  case risk ≥ 40            │ track_token_usage · memory_add (case outcome)
     └──────────► Sentinel ───────┘
                    │  context_search ──► Meko datapack  trailguard-patterns
                    ▼                     knowledge base: playbooks, step-up policy, risk rules
         ALLOW / STEP_UP / HOLD / BLOCK   collective memory: analyst-approved attacker patterns
                    │                                    ▲
                    ▼                                    │ memory_promote (analyst approves)
     confirmed attacks ──► Curator ── memory_add TG-PATTERN (Meko learnings: candidates)
                    │
                    ▼
     Explainer ── plain-English decision cards, audit report ── artifact_put
```

| Agent | Sees | Writes to Meko | Reads from Meko |
|---|---|---|---|
| Login | login attempts, step-up outcomes | signals | signals (at gates), approved patterns |
| Device | device fingerprints at session start | signals | signals, approved patterns |
| Recovery & support | resets, phone/email/MFA changes, support contacts | signals | signals, approved patterns |
| Payments | payees, card tests, transfers | signals | signals, approved patterns |
| Sentinel | escalated cases | decision turns, token usage, case outcomes, checkpoints, reports | playbooks and patterns (`context_search`) |
| Curator | confirmed attacks after a run | candidate patterns (learnings) | patterns pending review |

Least privilege is enforced in `trailguard/meko/scope.py`. Meko API keys are account-wide, so every agent gets an `AgentScope` with a datapack allowlist: channel agents and the Sentinel may write only `trailguard-signals`, and only the Curator writes `trailguard-patterns`. To have Meko itself enforce this, invite a second Meko account as a **viewer** on `trailguard-patterns` and run the channel agents with that account's key.

## How Meko is used, tool by tool

| Meko feature | Where | Why |
|---|---|---|
| **Datapacks** (2) | `engine.Runtime.create`, `bootstrap.ensure` | Raw signals and confirmed patterns are kept apart, as the brief asks, with different writers. |
| `memory_add` | `ChannelAgent.share`, `Sentinel._record`, `Curator.learn` | Every risk signal is one self-contained `TG-SIGNAL v1 \| …` line with exact identifiers (account, device, IP, payee) so hybrid search's keyword and entity boost finds it. Case outcomes and checkpoints use the same path. |
| `memory_search` | `ChannelAgent.handle` | At each gate the agent asks for signals on this account, device, IP and payee. Results from every agent come back because `agent_id` attributes but does not filter. |
| `context_search` | `Sentinel._playbook`, `engine.load_patterns` | One call across memory, knowledge and conversations for the policy passages behind a decision. Its `token_savings` estimate is reported. |
| **Knowledge base** | `bootstrap.ensure` (REST multipart upload, then status polling) | Playbooks, step-up policy, risk rules, SIM-swap and mule-ring indicators, chunked and searched with hybrid retrieval. |
| **Learnings → `memory_promote`** | `Curator.pending/approve`, dashboard Learnings tab | Candidate patterns stay private until an analyst approves. Promotion moves them into collective memory. |
| `memory_get_all(promoted=true)` | `engine.load_patterns` | Lists collective memory exactly, so only approved patterns are used. |
| `keep-as-memory` (REST) | `Curator.reject` | A rejected candidate stays private and leaves the review queue. |
| **Conversations + decision traces** | `Sentinel._record` | One case conversation per account per run. Each decision is a turn with `input`, `output`, `reasoning` and `plan`, which the Meko portal renders as a **Decision trace** with the full Langfuse execution trace behind it. |
| `track_token_usage` | `Sentinel._record` | Claude's token spend is attributed to the decision turn that caused it. |
| **Artifacts** | `engine._checkpoint`, `trailguard audit` | Checkpoints (for resume) and audit reports are stored whole and found again by a `TG-CHECKPOINT` / `TG-ARTIFACT` memory holding the content hash. |
| `memory_delete_all` | `trailguard reset --signals`, start of each run | Each run starts from clean signal memory. Patterns and playbooks are untouched. |

## Correctness rules for Meko Cloud

These come from Meko's docs and source and are enforced in `trailguard/meko/cloud.py`:

1. Send `Authorization: Bearer mko_tkn_…` and a `User-Agent` on every request.
2. **Meko Cloud refuses unknown tool arguments**, so arguments are filtered against each tool's `inputSchema` from `tools/list`.
3. Most tools need a `conversation_id`. `AgentScope` opens one conversation per agent per run, and the Sentinel opens one per case.
4. Actionable errors arrive **in band** (`{"error": code, "detail": …}` with `isError: false`) and are raised as `MekoError`. Plain-text `Error:` replies are raised too.
5. `metadata` is sent as a JSON string.
6. Retries with backoff cover transport errors and rate limits, with at most 4 calls in flight.
7. A per-run **budget** (`--max-retrievals`, `--max-messages`) protects the free tier (10,000 retrievals and 1,000 conversation messages a month). A run that hits it stops cleanly and is marked partial.

## Decisions and the policy

The Sentinel applies `knowledge/step-up-policy.md`:
- risk ≥ 80 blocks money movement and holds account changes
- 50–79 steps up, unless the phone or MFA device changed in the last 72 hours (then hold, because the step-up would reach the attacker)
- a confirmed attacker indicator always blocks

With an Anthropic key the Sentinel is Claude (`claude-opus-5-5` by default; `--model` to change), called with a JSON-schema structured output and Anthropic's server-side refusal fallback (`fallbacks: "default"`). If Claude's reply can't be used after one retry, the written policy decides and the decision is marked `fallback`. Without a key, the same policy runs deterministically, and its tokens are *estimated* from prompt size and labelled as such everywhere.

## Outcomes and the learning loop

- A **step-up** stops an attacker unless the attack already controls the second factor (after the phone move in a SIM swap, or after the attacker's MFA device was added). Genuine customers always pass.
- **Hold** and **block** stop the attack; for a genuine customer they count as a false positive.
- After a run, the **Curator** treats the ground-truth labels as confirmed fraud (in production: disputes and chargebacks). For each attack type it writes one pattern containing:
  - the attacker's indicators (proxy /24 subnets, device fingerprints, mule payees)
  - a signature of full-strength signals that genuine customers in the same stream almost never show (≤ 1%)

  Patterns wait as Meko learnings until an analyst approves them.

## Trace and resume

Every 100 events the engine checkpoints. The state goes to `artifact_put`, and a `TG-CHECKPOINT` memory holds the hash. `trailguard run --crash-at N` simulates a failure; `trailguard run --resume RUN_ID` finds the latest checkpoint in Meko (no local file needed), fast-forwards detector state without Meko calls, and continues. The test suite checks that a resumed run makes exactly the decisions an uninterrupted run makes.

## Code map

```
src/trailguard/
  sim/            seeded world, 5 attack TTPs, 7 benign look-alikes, generator
  agents/         detectors, case scoring, channel agents, Sentinel, Curator
  meko/           Meko interface, Cloud client (MCP + REST), offline stand-in, meter, scopes
  llm/            Claude decider (structured output) and the deterministic policy
  engine.py       replay, gates, outcomes, trace, checkpoints, resume
  metrics.py      detection, false positives, tokens, latency, cost
  bench.py        isolated / stuffed / meko / meko+patterns over seeds and epochs
  explain.py      plain-English decision cards
  report.py       audit report and benchmark tables
  web/            FastAPI + SSE dashboard (static HTML/CSS/JS, no build)
  cli.py          trailguard command
knowledge/        the playbooks uploaded to the Meko knowledge base
scripts/meko_smoke.py   live check of Meko Cloud behaviour before benchmarking
```
