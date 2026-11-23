# Methodology

## Question

Do the same fraud agents stop account takeovers more often, and earlier, when they share context through Meko? Does that cost fewer tokens than the obvious alternative of passing everything around? And do they keep improving as confirmed attacks become shared patterns?

## Data

`trailguard.sim.generate(seed, epoch, n_events)` builds a deterministic stream (same seed, same stream) of logins, device fingerprints, password resets, phone, email and MFA changes, support contacts, payees, card tests and transfers for about 1 customer per 7 events.

**Planted attacks**, about 11% of events. Each is a victim account with an ordered list of steps and exactly one *completion* step (the first irreversible harm).

| Technique | Completion |
|---|---|
| Credential stuffing over rotating residential proxies (≤ 4 accounts per IP, so no single IP looks noisy) | the transfer |
| SIM swap through support | the password reset |
| Session hijack from abroad shortly after a genuine login | the password reset |
| Mule ring: one emulator across 4 accounts, interleaved | each transfer |
| Low and slow over three days | the transfer |

**Genuine look-alikes** (false-positive pressure): a traveller abroad on their own phone, a phone upgrade, a forgetful user, a genuinely lost phone moved through support, a shared family device, a big purchase to a known payee, and a new landlord payee.

**Epoch 2** uses new victims (no overlap) and reuses part of the attacker infrastructure: the proxy subnets, the ring device, and 60% of the mule payees.

## What changes between modes, and what doesn't

Everything is identical across modes except what an agent can see when it builds a case. That includes:
- the detectors and their weights (`knowledge/risk-rules.md`)
- the escalation threshold (40)
- the step-up policy
- the decider
- the event stream

| Mode | Case evidence | Model prompt |
|---|---|---|
| `isolated` | the agent's own signals only | the case and the policy |
| `stuffed` | every agent's signals so far, in full (no Meko) | **every shared signal so far** and the policy |
| `meko` | signals returned by `memory_search` on the signals datapack (top 25, exact-entity filtered) | the case and policy passages from `context_search` |
| `meko+patterns` | as `meko`, plus analyst-approved patterns from collective memory | as `meko`, plus matched patterns |

Patterns are learned once per seed from the epoch-1 `meko` run and approved, and they are used only in `meko+patterns`. Each Meko run starts by deleting the previous run's signal memories, and signals are also filtered by run id, so runs can't leak into each other.

## Metrics (per run, then mean ± sd across seeds)

- **Recall**: share of attacks stopped at or before their completion step (held, blocked, or failing a step-up).
- **Stopped early**: attacks stopped before the completion step. **Steps early**: completion step minus the step where it was stopped, averaged over stopped attacks.
- **Genuine held/blocked**: accounts never attacked that received a HOLD or BLOCK (false positives that cost the customer).
- **Genuine stepped up**: accounts never attacked that were only asked for extra verification (friction).
- **Tokens/decision**: model input and output tokens per Sentinel decision. Measured from Claude's `usage` with an Anthropic key; with the deterministic decider, *estimated* as prompt characters / 4 and labelled `estimated`.
- **Latency**: wall time of the Sentinel step (context retrieval, model call, Meko logging), p50/p95.
- **Meko retrievals**: `memory_search` + `context_search` + `knowledgebase_search` calls (the free-tier metered ones).
- **Cost**: tokens × list price of the decider model (`config.PRICES`).

**Quality** is judged against ground truth, not by a model. Recall, steps early and false positives are the quality score. A token reduction only counts if recall and false positives hold.

## Offline reference results

10 seeds × 2,000 events, deterministic decider, **offline stand-in for Meko** (`--meko fake`). Reproduce with `uv run trailguard --meko fake --llm heuristic bench --seeds 1-10 --events 2000`.

| Epoch | Mode | Recall | Stopped early | Steps early | Genuine held/blocked | Genuine stepped up | Decisions | Tokens/decision (est.) | Meko retrievals |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `isolated` | 91% | 10.7 | 0.79 ± 0.32 | 0.0 | 7.0 | 43 | 920 | 0 |
| 1 | `stuffed` | 100% | 26.4 | 1.82 ± 0.04 | 0.0 | 7.0 | 58 | 11,687 | 0 |
| 1 | `meko` | 100% | 26.4 | 1.82 ± 0.04 | 0.0 | 7.0 | 58 | 987 | 170 |
| 2 | `isolated` | 91% | 11.2 | 0.83 ± 0.26 | 0.0 | 7.1 | 43 | 918 | 0 |
| 2 | `stuffed` | 100% | 25.4 | 1.78 ± 0.03 | 0.0 | 7.1 | 57 | 11,470 | 0 |
| 2 | `meko` | 100% | 25.4 | 1.78 ± 0.03 | 0.0 | 7.1 | 57 | 989 | 169 |
| 2 | `meko+patterns` | 100% | 35.0 | 2.51 ± 0.00 | 0.2 | 7.1 | 50 | 1,095 | 145 |

What this shows, on the offline stand-in:

- **Sharing matters.** Isolated agents miss every low-and-slow takeover (91% recall) and stop the rest late: about 11 of 35 before the completion step, against 26 with shared context.
- **Retrieval beats pasting.** Retrieving the relevant slice gives the same detection as pasting everything with **92% fewer tokens per decision**, and the pasted prompt keeps growing with history.
- **The learning loop pays off.** Approved patterns stop every epoch-2 attack before its completion step (35 of 35), 2.51 steps early on average against 1.78, with fewer decisions and fewer retrievals. The cost is 0.2 genuine customers held per run.
- **Friction is the same everywhere.** The 7 genuine step-ups per run are the new-landlord and big-transfer look-alikes. They are identical across modes because they come from one agent's own signals.

## Meko Cloud results

_To be filled from `uv run trailguard bench --seeds 1-3 --events 1000` with `MEKO_API_KEY` and `ANTHROPIC_API_KEY` set (results in `runs/bench-*/results.md`)._

Two things to expect against real Meko.

- **`meko` will not equal `stuffed` exactly.** The stand-in returns related signals almost perfectly. Meko's hybrid search ranks by meaning, keywords and entities, so a relevant signal can fall outside the top 25 (lower recall), or retrieval can surface linked context that pasting misses. Whatever happens is the measurement.
- **Latency and Meko call costs become real.** Run `scripts/meko_smoke.py` first: it records read-after-write latency and whether memory text comes back verbatim, both of which this design depends on.

## Fairness controls and limitations

- Weights and thresholds were set once from the written risk rules. Two detector refinements were made after inspecting false positives, both applied to every mode and both documented in `knowledge/risk-rules.md`:
  - a new-device login on the customer's home network counts 10 instead of 20;
  - device signals count only for the device in the action.
- Pattern signatures are learned from data. A signal enters an attacker signature only if ≤ 1% of genuine customers in the same stream show it at full strength. No signature was hand-written.
- Confirmed fraud comes from the simulator's labels. In production these would be disputes and chargebacks, which arrive later and noisier.
- The stream is synthetic, and the attacker's behaviour is scripted rather than adaptive. Results show the mechanism, not real-world detection rates.
- One Meko account serves all agents, so least privilege is enforced in TrailGuard's scopes. A second account invited as a viewer would make Meko enforce it.
