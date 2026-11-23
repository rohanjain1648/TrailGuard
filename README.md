# TrailGuard

**Agents that remember the attacker.** A multi-agent account-takeover detector built on [Meko](https://mekodata.ai) for ContextCon 2026 (Challenge 03, "Remember the Attacker").

- [The problem](#the-problem)
- [What TrailGuard does](#what-trailguard-does)
- [Results](#results)
- [Quick start](#quick-start)
- [Running against Meko Cloud and Claude](#running-against-meko-cloud-and-claude)
- [How it works](#how-it-works)
- [How Meko is used](#how-meko-is-used)
- [The dashboard](#the-dashboard)
- [Command reference](#command-reference)
- [Configuration](#configuration)
- [The benchmark](#the-benchmark)
- [Auditability and resume](#auditability-and-resume)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Troubleshooting](#troubleshooting)
- [Limitations and honest caveats](#limitations-and-honest-caveats)
- [Documentation map](#documentation-map)

---

## The problem

Account takeover (ATO) is a sequence, not an event:

1. Support gets a call from someone claiming a lost phone and asking to move the number.
2. The number moves. A password reset arrives by SMS.
3. A login from a never-seen device follows.
4. A new payee is added. A transfer many times the usual size leaves.

Each step reaches a different team's system and looks harmless on its own. The login team sees a login. The support team sees a call. The payments team sees a transfer. Fraud gets through the gaps *between* agents, and when an account is finally blocked, analysts and regulators need to know exactly why.

## What TrailGuard does

Four **channel agents** each watch one stream, and see nothing else:

| Agent | Sees |
|---|---|
| Login | login attempts, step-up outcomes |
| Device | device fingerprints at session start |
| Recovery & support | password resets, phone/email/MFA changes, support contacts |
| Payments | payees, card tests, transfers |

They share what they see through **one governed memory in Meko**. At every risky action ("gate"), an agent asks Meko what the *other* agents saw about this account, device, network and payee, scores the case, and escalates if the risk is high. A **Sentinel** agent then decides: allow, ask for extra verification, hold for an analyst, or block.

Three properties make it more than a rules engine:

1. **Collective memory.** A signal one agent writes is searchable by every other agent immediately. A block on one account becomes a warning on every account that later touches the same device, network or payee.
2. **A trace for every decision.** Each decision is a Meko conversation turn carrying input, output, reasoning, plan and token cost. Meko renders it as a *decision trace*. TrailGuard also generates plain-English "why" cards from the same data.
3. **A reviewed learning loop.** After a run, a **Curator** agent turns confirmed attacks into attacker patterns. They sit in Meko as *learnings*, invisible to other agents, until an analyst approves them. Approval promotes them into collective memory, and the next attack from the same infrastructure is stopped earlier.

## Results

The benchmark changes **only the context layer**. The same agents, detectors, thresholds, policy and event streams run four ways:

| Mode | How agents share context |
|---|---|
| `isolated` | They don't. Each agent uses only its own signals. |
| `stuffed` | Every signal is pasted into the Sentinel's prompt. No Meko. |
| `meko` | Signals are written to and retrieved from Meko. |
| `meko+patterns` | As `meko`, plus analyst-approved attacker patterns from collective memory. |

**Offline reference run** (10 seeds × 2,000 events, deterministic decider, in-process stand-in for Meko):

| | Isolated | Paste everything | Meko | Meko + patterns (epoch 2) |
|---|---|---|---|---|
| Takeovers stopped before completion | 91% | 100% | 100% | 100% |
| Average steps before completion | 0.79 | 1.82 | 1.82 | **2.51** |
| Genuine customers held or blocked, per run | 0.0 | 0.0 | 0.0 | 0.2 |
| Model tokens per decision (estimated) | 920 | 11,687 | **987** | 1,095 |

> **These numbers are from the offline stand-in, not from Meko.** The stand-in finds related signals almost perfectly, which real hybrid search may not. They show the mechanism and verify the harness. The numbers that count come from `trailguard bench` with a Meko key; see [The benchmark](#the-benchmark). Full table, definitions and caveats: [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

What the offline run shows:

- **Sharing matters.** Isolated agents miss every slow, multi-day takeover and stop the rest late.
- **Retrieval beats pasting.** Same detection as pasting everything, about 92% fewer tokens per decision, and the pasted prompt keeps growing as history accumulates.
- **Learning pays off.** On new victims of the same attackers, approved patterns stop every attack and stop it earlier.

## Quick start

Needs Python 3.12+ and [uv](https://docs.astral.sh/uv/). No API keys are required for this path.

```bash
git clone <this repo> trailguard && cd trailguard
uv sync
uv run pytest -q                              # 86 tests, all offline
uv run trailguard doctor                      # shows which backend and decider are active
uv run trailguard run --mode meko             # one run, prints each decision
uv run trailguard serve                       # dashboard on http://127.0.0.1:8000
```

With no keys set, TrailGuard uses an in-process stand-in for Meko (`offline-fake`) and a deterministic decider (`heuristic`). Both are labelled in the CLI output, the dashboard banner and every generated report, so offline results can't be mistaken for real ones.

## Running against Meko Cloud and Claude

1. **Meko.** Create a free account at <https://cloud.mekodata.ai/signup>. Under **Settings > API Keys**, generate a key (it starts with `mko_tkn_`; it is shown once).
2. **Claude.** Create an API key at <https://console.anthropic.com>.
3. Copy `.env.example` to `.env` and fill in `MEKO_API_KEY` and `ANTHROPIC_API_KEY`. `.env` is git-ignored.

Then, in this order:

```bash
# 1. Verify the Meko behaviour TrailGuard depends on (about 6 retrievals, 1 message)
uv run python scripts/meko_smoke.py

# 2. Create the two datapacks and upload the playbooks to the knowledge base
uv run trailguard setup

# 3. Inspect: MCP tools, datapack IDs and counts
uv run trailguard doctor

# 4. Epoch 1: a run with shared memory
uv run trailguard run --mode meko --seed 1 --events 600

# 5. Learn from it, review, approve
uv run trailguard learn --run <run-id>        # writes candidate patterns (Meko learnings)
uv run trailguard pending                     # review them
uv run trailguard approve --all               # memory_promote into collective memory

# 6. Epoch 2: new victims, same attackers, now with approved patterns
uv run trailguard run --mode meko+patterns --seed 1 --epoch 2

# 7. Measure everything
uv run trailguard bench --seeds 1-3 --events 1000
uv run trailguard audit --run <run-id>        # audit report, also stored in Meko as an artifact
```

`meko_smoke.py` checks the things the design depends on: all expected tools are present, a memory written by one agent is searchable by another (and how long that takes), memory text comes back verbatim, decision traces and token usage can be logged, and artifacts round-trip. If a check fails, fix it before benchmarking; a benchmark on a misbehaving backend is meaningless.

**Free-tier budget.** Meko's free tier allows 10,000 retrievals and 1,000 conversation messages per month. Every run enforces a budget (`--max-retrievals`, default 400; `--max-messages`, default 120) and stops cleanly, marked *partial*, when it is spent. A 600-event run uses roughly 60–170 retrievals and 15–30 messages.

**Cost.** The default Claude model is `claude-opus-5-5`. For a much cheaper benchmark use `--model claude-haiku-5-5`, or `--llm heuristic` to run the written policy with no model at all.

## How it works

```
            synthetic event stream (seeded; ground truth hidden from the agents)
                               │ replayed in time order
    ┌──────────────┬───────────┴──────────────┬──────────────────┐
    ▼              ▼                          ▼                  ▼
 Login         Device            Recovery & support          Payments
 agent         agent             agent                       agent
    │ detect → memory_add  TG-SIGNAL   (only risk signals are saved)
    └────────────► Meko datapack  trailguard-signals  ◄──────────┘
                   signals · case conversations · decision traces
    ▲ memory_search          · token usage · checkpoints · reports
    │ at each gate                    ▲
    │ (case risk ≥ 40)                │ conversation_add_message (reasoning, plan)
    └──────────► Sentinel ────────────┘ track_token_usage · case outcome as a signal
                    │ context_search ─► Meko datapack  trailguard-patterns
                    ▼                   knowledge base: playbooks, step-up policy, risk rules
        ALLOW / STEP_UP / HOLD / BLOCK  collective memory: approved attacker patterns
                    │                                ▲
                    ▼                                │ memory_promote (analyst approves)
      confirmed attacks ──► Curator ── TG-PATTERN ───┘ (as Meko learnings first)
```

### 1. Detection

Each channel agent runs deterministic detectors over its own stream and turns what it finds into **signals**, each with a type, a risk weight, and identifiers (account, device, IP, payee). The detectors are identical in every benchmark mode. Examples:

| Agent | Signals |
|---|---|
| Login | `failed_logins`, `ip_spray`, `spray_ip_login`, `new_device_login`, `geo_anomaly`, `impossible_travel`, `step_up_failed` |
| Device | `new_device`, `emulator`, `device_multi_account` |
| Recovery & support | `risky_support_contact`, `phone_change`, `email_change`, `reset_unknown_device`, `mfa_change` |
| Payments | `new_payee`, `card_test`, `large_transfer`, `fresh_payee_transfer` |

Weights live in [knowledge/risk-rules.md](knowledge/risk-rules.md) (the copy agents can retrieve) and `src/trailguard/config.py` (the copy the code uses). Some signals soften in benign context, for example a new-device login on the customer's own home network is 10 points, not 20, and a login abroad on a *known* device is 5, not 15.

### 2. Sharing

In the Meko modes, every signal is written with `memory_add` as one self-contained line:

```
TG-SIGNAL v1 | type=phone_change | account=C1003 | sev=medium | w=20 | device=- | ip=185.220.123.41 | payee=- | ts=2026-10-03T08:14:02+00:00 | agent=recovery-agent | event=E1-00412 | run=meko-s1-e1-081522 | note=phone number changed via support
```

One line, with exact identifiers, because Meko's memory search is hybrid (semantic, keyword and entity-aware): an account, device or IP in the query gets a boost on memories that mention it. The parser (`memlines.py`) recovers fields from `key=value` pairs wherever the marker appears, so extra prose around the line, or reordered fields, don't break it.

Only risk signals are saved. Benign events that raise nothing are never written.

### 3. Gates and cases

A **gate** is a risky action that produced at least one local signal: a new-device login, a phone/email/MFA change, a password reset, a payee add, a card test, or a transfer. At a gate, the agent builds a **case**:

- `isolated`: only its own signals.
- `stuffed`: every agent's signals so far, passed around in full.
- `meko`: `memory_search` on the signals datapack with a query naming the account, device, IP and payee; hits are parsed, filtered to the current run, and kept only if they relate to the gate.
- `meko+patterns`: as `meko`, plus any approved pattern whose indicators match.

A signal about the *same account* counts. A signal about *another* account counts only when it describes shared infrastructure (`ip_spray`, `device_multi_account`) or comes from another account's blocked or failed case that shares this device, IP or payee (it becomes a `linked_case` signal, +30). Device signals count only for the device involved in the action, not for other devices on the same account.

**Risk** is the sum of distinct signals from the last 72 hours, halved for signals older than 24 hours, capped at 100. Cases at **40 or more** escalate to the Sentinel.

### 4. Decision

The Sentinel applies [knowledge/step-up-policy.md](knowledge/step-up-policy.md):

| Condition | Decision |
|---|---|
| A device, IP subnet or payee in the case is in a confirmed attacker pattern | **BLOCK** (whatever the score) |
| Risk ≥ 80 | **BLOCK** money movement; **HOLD** credential changes |
| Risk 50–79, and the phone number or an MFA device changed in the last 72 h | **HOLD** (a step-up would reach whoever made the change) |
| Risk 50–79 otherwise | **STEP_UP** |
| Risk < 40 (never escalated) or below 50 | **ALLOW** |

With an Anthropic key, the Sentinel is **Claude**: it receives the case, the retrieved policy passages and any matched patterns, and returns a JSON object validated against a schema (decision, risk, hypothesis, reasons, cited evidence ids, policy references, plain-English explanation). The request uses structured output and Anthropic's server-side refusal fallback. If the reply is unusable after one retry (refusal, bad JSON, API error), the written policy decides instead, and the decision is marked `fallback` in the trace. Without a key, the same policy runs deterministically; its token counts are *estimated* from prompt size and labelled as such everywhere.

### 5. Outcomes

How each decision plays out in the simulation:

- **ALLOW**: the action proceeds; the agents keep watching.
- **STEP_UP**: a genuine customer passes. An attacker fails (and the attack stops) unless the attack already controls the second factor, which is true after the phone move in a SIM swap and after the attacker's MFA device is added in a low-and-slow attack. In those cases the step-up goes to the attacker and passes.
- **HOLD / BLOCK**: the attack is stopped. For a genuine customer this is a false positive.

Once an attack is stopped, its remaining steps for that victim are dropped. The Sentinel also writes the outcome back as a shared signal (`under_watch` or `case_blocked`), so other agents learn from it.

### 6. Learning

After a run, the **Curator** treats the simulator's ground-truth labels as confirmed fraud (in production these would be disputes and chargebacks). For each attack technique it writes one `TG-PATTERN` memory to the patterns datapack:

- the attacker's **indicators**: proxy /24 subnets, device fingerprints, mule payees;
- a **signature**: the full-strength signals seen across that technique's attacks, *excluding any signal that more than 1% of genuine customers in the same stream also show*;
- the earliest useful signal and a recommended action.

The exclusion rule matters. An earlier version kept every signal, which made patterns match ordinary new-device logins and held 7 genuine customers per run. Filtering the signature by how common each signal is among genuine customers removed that, and nothing was hand-written.

These patterns are Meko **learnings**: candidates only the Curator can write, and nobody else's agents trust. An analyst approves them in the dashboard (or `trailguard approve`), which calls `memory_promote` and moves them into collective memory. A rejected candidate is kept private (`keep-as-memory`) and leaves the review queue. In `meko+patterns` mode the engine loads exactly the promoted patterns with `memory_get_all(promoted=true)`.

### Attack techniques in the simulator

Every identifier is synthetic and generated from a seed.

| Technique | Steps | Completes at |
|---|---|---|
| Credential stuffing | spray a few failures across ~30 accounts through rotating proxies (no IP touches more than 4 accounts), log into the few that succeed from a new device, add a mule payee, transfer | the transfer |
| SIM swap | support contact from an unfamiliar network, phone change, SMS password reset, new-device login, new payee, transfer | the password reset |
| Session hijack | login from abroad within 2 h of the customer's own login, email change, password reset, new payee | the password reset |
| Mule ring | one emulator fingerprint works through 4 accounts, interleaved: login, card test, shared mule payee, transfer | each transfer |
| Low and slow | over three days: abandoned reset, failed logins, attacker MFA device added, new-device login, card test, payee, transfer | the transfer |

Seven kinds of genuine look-alike create false-positive pressure: a traveller abroad on their own phone, a phone upgrade, a forgetful user, a genuinely lost phone moved through support, a shared family device, a big purchase to a known payee, and a new landlord payee. About 11% of events belong to attacks.

**Epoch 2** uses entirely new victims and reuses part of the attacker infrastructure (the proxy subnets, the ring device, 60% of the mule payees), which is what "remember past attacks" can exploit.

## How Meko is used

| Meko feature | What TrailGuard does with it |
|---|---|
| **Datapacks** (2) | `trailguard-signals` holds raw signals, case conversations, traces, checkpoints and reports. `trailguard-patterns` holds the playbooks and confirmed patterns. They are separate because they have different writers and different trust. |
| `memory_add` | Every signal, case outcome and checkpoint pointer, as single-line `TG-…` memories. |
| `memory_search` | Case building at each gate (top 25, filtered to the run and to related entities). |
| `context_search` | The Sentinel's policy retrieval; one call across memory, knowledge and conversations. Meko's `token_savings` estimate is captured. |
| **Knowledge base** | Playbooks, step-up policy, risk rules and indicator guides from `knowledge/`, uploaded by `trailguard setup` through the Datapack API and polled until indexed. |
| **Learnings and `memory_promote`** | The analyst-approval gate between a candidate pattern and collective memory. |
| `memory_get_all(promoted=true)` | Loads exactly the approved patterns. |
| `keep-as-memory` (REST) | Rejecting a candidate. |
| **Conversations + decision traces** | One case conversation per account per run; each decision is a turn with `input`, `output`, `reasoning`, `plan`. |
| `track_token_usage` | Attributes each Claude call's tokens to the decision turn that caused it. |
| **Artifacts** | Run checkpoints (for resume) and audit reports; found again through a memory holding the content hash. |
| `memory_delete_all` | Each run starts from clean signal memory. |

### Rules the Meko client enforces

These come from Meko's documentation and source, and are implemented in `src/trailguard/meko/cloud.py`:

- Every request carries `Authorization: Bearer mko_tkn_…` and a `User-Agent`; Meko rejects requests without them.
- **Meko Cloud refuses arguments a tool doesn't declare.** Arguments are filtered against each tool's `inputSchema` from `tools/list`.
- Most tools require a `conversation_id`. Each agent opens one conversation per run; the Sentinel opens one per case.
- Actionable errors arrive *in band* (`{"error": code, "detail": …}` with `isError: false`) and are raised as errors rather than treated as empty results. Plain-text `Error:` replies are raised too.
- `metadata` is sent as a JSON string.
- Rate limits and transport errors are retried with backoff, with at most four calls in flight.

### Least privilege

Meko API keys are account-wide, so any agent holding the key could write anywhere. TrailGuard gives each agent a scope with a datapack allowlist (`src/trailguard/meko/scope.py`): channel agents and the Sentinel can write only the signals datapack, and **only the Curator can write patterns**. This is enforced in code. To have Meko itself enforce it, invite a second Meko account as a *viewer* on `trailguard-patterns` and run the channel agents under that account's key.

## The dashboard

`uv run trailguard serve` serves a single-page dashboard (FastAPI plus Server-Sent Events, static HTML/CSS/JS, no build step). A banner always shows which backend and decider are active, in red when the backend is the offline stand-in.

| Tab | What it shows |
|---|---|
| **Live** | Start a run in any mode. **The trail** plots each agent's signals as dots on its own lane, draws a thread whenever another agent read a signal that shaped a case, and marks the Sentinel's decisions. Counters, a per-attack tracker (how many steps each planted attack had and where it was stopped) and a feed of decisions sit alongside. |
| **Explain a decision** | A plain-English card for any decision: what was attempted, what each agent already knew (with the Meko memory it came from), the policy rule applied, any pattern recognised, and what happened next. Written so a non-engineer can follow it in about two minutes. |
| **Learnings** | Create candidate patterns from a finished run, then approve (promote) or keep private. Shows what's already in collective memory. |
| **Results** | The latest benchmark as bar charts and a table, with headline sentences generated from the data. Can run a quick offline benchmark. |
| **Audit report** | The generated report for any run, rendered and downloadable as Markdown. |

## Command reference

Global flags (before the subcommand): `--meko cloud|fake`, `--llm claude|heuristic`, `--model <id>`, `--effort low|medium|high|xhigh|max`.

| Command | What it does |
|---|---|
| `trailguard doctor` | Shows the active backend and decider, Meko tools, datapack IDs and counts. |
| `trailguard setup` | Creates or finds both datapacks, uploads `knowledge/*.md`, waits for indexing. Safe to re-run; unchanged files are skipped. |
| `trailguard generate --seed N --epoch E --events N` | Writes a synthetic stream to JSONL. |
| `trailguard run --mode <m>` | Replays a stream. Options: `--seed`, `--epoch`, `--events`, `--pace` (events/s), `--run-id`, `--max-retrievals`, `--max-messages`, `--quiet`, `--keep-signals`, `--crash-at N`, `--resume RUN_ID`. |
| `trailguard learn --run ID [--approve]` | Curator writes candidate patterns from a run; `--approve` promotes them immediately. |
| `trailguard pending` | Lists candidate patterns waiting for review. |
| `trailguard approve [--all] [ids…]` | Promotes patterns into collective memory. |
| `trailguard bench` | Runs all modes over seeds and epochs. Options: `--seeds 1-3`, `--events`, `--modes`, `--max-retrievals`, `--max-messages`. |
| `trailguard explain --run ID -n K` | Prints the plain-English card for decision K. |
| `trailguard audit --run ID [--local]` | Generates the audit report; stores it in Meko as an artifact unless `--local`. |
| `trailguard reset --signals` | Deletes TrailGuard's signal memories from Meko (patterns and playbooks are untouched). |
| `trailguard serve [--host H] [--port P]` | Starts the dashboard. |

## Configuration

Set in `.env` (see `.env.example`) or the environment.

| Variable | Default | Meaning |
|---|---|---|
| `MEKO_API_KEY` | none | Meko Cloud key (`mko_tkn_…`). Without it, the offline stand-in is used. |
| `ANTHROPIC_API_KEY` | none | Claude key. Without it, the deterministic decider is used. |
| `TRAILGUARD_MEKO` | `cloud` if a key is set, else `fake` | Force the backend. |
| `TRAILGUARD_LLM` | `claude` if a key is set, else `heuristic` | Force the decider. |
| `TRAILGUARD_MODEL` | `claude-opus-5-5` | Claude model for the Sentinel. |
| `TRAILGUARD_EFFORT` | `medium` | Claude effort level. |
| `TRAILGUARD_RUNS` | `./runs` | Where traces, results and the offline stand-in's state are written. |
| `MEKO_MCP_URL`, `MEKO_API_URL` | Meko Cloud endpoints | Override for a self-hosted Meko. |

Each run writes to `runs/<run-id>/`: `trace.jsonl` (every event of interest), `decisions.jsonl`, `result.json`, `checkpoint.json` and `audit.md`. Benchmarks write `runs/bench-<timestamp>/results.{json,md}`.

## The benchmark

`trailguard bench` runs, for each seed:

1. **Epoch 1** in `isolated`, `stuffed` and `meko`.
2. **Learning:** the Curator writes patterns from the epoch-1 `meko` run, and they are approved.
3. **Epoch 2** (new victims, partly reused attacker infrastructure) in all four modes.

Per run it reports recall (attacks stopped at or before their completion step), steps early, genuine customers held or blocked, genuine customers stepped up (friction), decisions, tokens, latency (p50/p95), Meko calls and cost; then the mean and standard deviation over seeds. Quality is judged against ground truth, not by a model, so a token saving counts only if recall and false positives hold. Definitions, fairness controls and caveats are in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## Auditability and resume

**Decision traces.** Each decision is a turn in a per-account case conversation in `trailguard-signals`. In the Meko portal, open **Datapack > Conversations** and expand **Decision trace**, or use **Observe** for the full execution trace with tool spans and token usage. The audit report lists each decision's conversation and message IDs and the signal memories it cited.

**Audit report.** `trailguard audit` produces a Markdown report from trace data: run header (including the backend, so offline runs are labelled), an outcome table, a row for every decision, full walkthroughs of at least three (one stopped attack, one step-up, one allow where present), and Meko references. It is stored as a Meko artifact too.

**Resume.** Every 100 events the engine checkpoints: the state is stored with `artifact_put`, and a `TG-CHECKPOINT` memory holds the hash. To demonstrate:

```bash
uv run trailguard run --mode meko --crash-at 300 --run-id demo   # simulated failure at event 300
uv run trailguard run --resume demo                              # picks up from the checkpoint
```

Resume finds the latest checkpoint in Meko (no local file needed), fast-forwards detector state without any Meko calls, and continues. The test suite checks that a resumed run makes exactly the decisions an uninterrupted run makes.

## Testing

```bash
uv run pytest -q        # 86 tests, no network, about 30 seconds
```

The suite covers the simulator (determinism, one completion step per attack, all techniques and look-alikes present), memory-line parsing (including prose around a line), the detectors, case scoring and windowing, the written policy, the Claude decider (including malformed JSON falling back to policy), the engine (interdiction, budget exhaustion, resume equality, resume from a Meko checkpoint), the Curator and the approval gate, metrics, reports, the CLI and the dashboard API. The Meko Cloud client is tested against mocked replies in Meko's documented shapes and against a **real local MCP server over Streamable HTTP**. The benchmark test asserts the *direction* of results (Meko at least matches isolated; retrieval uses far fewer tokens than pasting; approved patterns don't make detection later), never fixed numbers.

## Project layout

```
src/trailguard/
  sim/            seeded world, five attack techniques, seven look-alikes, generator
  agents/         detectors, case scoring, channel agents, Sentinel, Curator
  meko/           Meko interface; Cloud client (MCP + REST); offline stand-in; call meter; agent scopes
  llm/            Claude decider (structured output) and the deterministic policy
  engine.py       replay, gates, outcomes, tracing, checkpoints, resume
  metrics.py      detection, false positives, tokens, latency, cost
  bench.py        the four-mode, two-epoch benchmark
  explain.py      plain-English decision cards
  report.py       audit report and results tables
  bootstrap.py    datapack and knowledge-base setup
  web/            FastAPI app and the static dashboard
  cli.py          the `trailguard` command
knowledge/        playbooks uploaded to the Meko knowledge base
scripts/          meko_smoke.py: live check of Meko Cloud behaviour
tests/            offline test suite
docs/             report, architecture, methodology, demo script, submission kit
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Banner says "OFFLINE stand-in" | No `MEKO_API_KEY` was found. Add it to `.env`, or check `trailguard doctor`. |
| `no_api_key` | `TRAILGUARD_MEKO=cloud` is set but `MEKO_API_KEY` is empty. |
| Calls fail with an authorization error | The key must be sent as `Bearer mko_tkn_…`. Keys expire after a year and can be revoked in **Settings > API Keys**. |
| `datapack_access_denied` | The datapack ID isn't visible to this key. Re-run `trailguard setup`. |
| Run ends *partial* with "budget" | The per-run retrieval or message budget was reached (protecting your free tier). Raise `--max-retrievals` / `--max-messages`, or run fewer events. |
| Signals written but not found by other agents | Meko indexing can lag. `scripts/meko_smoke.py` reports read-after-write latency; if it is slow, add a short delay between writes and reads before benchmarking. |
| Knowledge files show "still indexing" | Re-run `trailguard setup` in a minute; unchanged files are not re-uploaded. |
| Free-tier quota or datapack limit errors | Free accounts allow 10 datapacks (a deleted one doesn't free its slot) and 100 MB of knowledge storage. TrailGuard uses two. |
| Decisions show `fallback` | Claude's reply was unusable or declined; the written policy decided. The reason is in the decision's reasons. |
| `uv run trailguard` can't find the module after a fresh clone | Run `uv sync` first. |

## Limitations and honest caveats

- **The data is synthetic and the attackers are scripted.** Results demonstrate the mechanism, not real-world detection rates.
- **Confirmed fraud comes from simulator labels.** In production this would be disputes and chargebacks, which arrive later and noisier.
- **The offline numbers are not Meko numbers.** The stand-in is a faithful interface, not a faithful search engine. Judge the project on `trailguard bench` against Meko Cloud.
- **Two detector refinements were made after inspecting false positives** (home-network new-device logins score lower; device signals apply only to the device in question). Both apply to every mode and are documented in `knowledge/risk-rules.md`.
- **One Meko account serves all agents.** Least privilege between them is enforced in TrailGuard; a second account as a viewer would make Meko enforce it.
- **This is a prototype, not a fraud engine.** It does not model card-authorization latency, train models, or handle real customer data.

## Documentation map

| Document | Contents |
|---|---|
| [docs/REPORT.md](docs/REPORT.md) | Research: all eight ContextCon challenges analysed and scored, and why Challenge 03 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Agents, datapacks, every Meko tool used and where in the code |
| [docs/METHODOLOGY.md](docs/METHODOLOGY.md) | Benchmark design, metric definitions, fairness controls, results |
| [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | The under-5-minute demo video, beat by beat |
| [docs/SUBMISSION.md](docs/SUBMISSION.md) | Submission checklist and descriptions |
| [docs/superpowers/](docs/superpowers/) | Design spec and implementation plan |

## License

Apache-2.0. Add the `LICENSE` file before publishing the repository.
