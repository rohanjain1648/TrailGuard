# TrailGuard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build TrailGuard, a multi-agent account-takeover detector whose agents share risk signals, attacker patterns and decision traces through Meko, with a benchmark that proves the effect and a dashboard for the demo.

**Architecture:** A seeded simulator produces a labelled event stream. Four channel agents detect signals, write them to Meko and build cases at gates. A Sentinel decides, and its decisions are logged to Meko conversations with reasoning. A Curator distils confirmed attacks into patterns that an analyst promotes. One engine replays streams in four modes (`isolated`, `stuffed`, `meko`, `meko+patterns`), and the same engine feeds the CLI, the benchmark and a FastAPI/SSE dashboard.

**Tech Stack:** Python 3.12, uv, asyncio, `mcp` (official SDK, Streamable HTTP), `httpx`, `anthropic`, FastAPI + uvicorn, python-dotenv, pytest + pytest-asyncio. Frontend: static HTML/CSS/JS with no build step.

**Spec:** `docs/superpowers/specs/2026-11-09-trailguard-design.md`

## Global Constraints

- Python `>=3.12`; package `trailguard` under `src/`; console script `trailguard = trailguard.cli:main`.
- Meko MCP URL `https://mcp.mekodata.ai/mcp`; REST base `https://api.mekodata.ai/api/v1`; headers `Authorization: Bearer <MEKO_API_KEY>` and `User-Agent: trailguard/0.1`.
- Send only arguments present in a tool's `inputSchema.properties` (Meko Cloud refuses unknown arguments).
- Datapack names: `trailguard-signals`, `trailguard-patterns`.
- Agent IDs: `login-agent`, `device-agent`, `recovery-agent`, `payments-agent`, `sentinel`, `curator`, `explainer`.
- Memory line prefixes: `TG-SIGNAL v1`, `TG-DECISION v1`, `TG-PATTERN v1`, `TG-CHECKPOINT v1`, `TG-ARTIFACT v1`; fields separated by ` | `, each `key=value`.
- Modes: `isolated`, `stuffed`, `meko`, `meko+patterns`. Only `meko*` call Meko.
- Escalation threshold 40. Policy: risk ≥80 → BLOCK (money) / HOLD (credential change); 50–79 → STEP_UP, except HOLD if phone or MFA changed ≤72 h; known attacker indicator → BLOCK; <50 → ALLOW.
- Default per-run budget: 400 retrievals, 120 `conversation_add_message` calls.
- Default model `claude-haiku-5-5`.
- Every output (trace, report, UI banner) records `backend` (`meko-cloud` or `offline-fake`) and `decider` (`claude:<model>` or `heuristic`).
- Offline tests must not touch the network.

## Review Focus

1. **Meko replies an in-band error (`{"error": "...", "detail": "..."}`, `isError: false`)**: the client must raise `MekoError`, not treat it as an empty result. Test in Task 5.
2. **Budget exhausted mid-run**: the run stops cleanly, results are marked `partial: true`, and nothing crashes. Test in Task 8.
3. **Claude returns malformed or invalid JSON**: one retry, then the heuristic fallback, with `fallback: true` recorded in the decision. Test in Task 7.
4. **Memory text comes back with extra prose or reordered fields**: `parse_signal` still recovers the fields from `key=value` pairs anywhere in the text, and non-TG memories are ignored. Test in Task 3.
5. **Resume after a crash at an arbitrary offset**: decisions before the offset are not repeated, and final metrics equal an uninterrupted run on the fake backend. Test in Task 8.

---

### Task 1: Scaffold, models, config

**Files:**
- Create: `pyproject.toml`, `.env.example`, `src/trailguard/__init__.py`, `src/trailguard/models.py`, `src/trailguard/config.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces:
  - `models.Truth(attack_id: str|None, ttp: str|None, step: int|None, completes_takeover: bool, benign_case: str|None)`
  - `models.Event(event_id, ts: datetime, channel, type, account_id, ip, country, device_id: str|None, attrs: dict, truth: Truth)` with `to_dict()` / `Event.from_dict()`
  - `models.Signal(type, severity, weight, account_id, agent, ts: datetime, event_id, run_id, device_id=None, ip=None, payee_id=None, note="", memory_id=None, score=None)`
  - `models.Decision(decision, risk, hypothesis, reasons: list[str], evidence: list[dict], policy_refs: list[str], pattern_id: str|None, plain_english, decider, tokens_in=0, tokens_out=0, tokens_estimated=False, latency_ms=0.0, fallback=False)`
  - `models.Pattern(pattern_id, ttp, sequence: list[str], iocs: dict[str, list[str]], earliest_signal, action, epoch: int, source_cases: list[str], memory_id=None)`
  - `config.Settings` (from env via `Settings.load()`): `meko_api_key`, `anthropic_api_key`, `meko_backend` (`cloud|fake`, default `fake` when no key), `llm` (`claude|heuristic`, default `heuristic` when no key), `model`, `mcp_url`, `api_url`, `runs_dir`
  - `config.SIGNAL_WEIGHTS: dict[str,int]`, `config.PRICES: dict[str, tuple[float,float]]` (USD per 1M input/output tokens)

- [ ] **Step 1:** Write `tests/test_models.py`. `test_event_roundtrip` asserts `Event.from_dict(e.to_dict()) == e`. `test_settings_defaults_offline` asserts that with no env keys, `Settings.load().meko_backend == "fake"` and `.llm == "heuristic"`.
- [ ] **Step 2:** Run `uv run pytest tests/test_models.py -v` and expect FAIL (module missing).
- [ ] **Step 3:** Implement the dataclasses and settings. The weights are copied from `knowledge/risk-rules.md` (Task 12): `failed_logins 10, ip_spray 25, spray_ip_login 35, new_device_login 20, geo_anomaly 15, impossible_travel 35, step_up_failed 50, new_device 10, device_multi_account 40, emulator 20, risky_support_contact 15, phone_change 20, email_change 25, reset_unknown_device 15, mfa_change 25, new_payee 10, card_test 20, large_transfer 25, fresh_payee_transfer 20, known_attacker_ioc 60, ttp_match 30, under_watch 15`.
- [ ] **Step 4:** Run the tests and expect PASS.

### Task 2: Simulator

**Files:**
- Create: `src/trailguard/sim/__init__.py`, `sim/world.py` (customers, infra), `sim/attacks.py` (5 TTP builders), `sim/benign.py` (baseline traffic + 7 bait cases), `sim/generator.py`
- Test: `tests/test_sim.py`

**Interfaces:**
- Produces:
  - `generate(seed: int, epoch: int = 1, n_events: int = 600) -> list[Event]`, sorted by `ts`
  - `attack_instances(events) -> dict[str, list[Event]]` (attack_id → its steps in order)
  - `save_jsonl(events, path)`, `load_jsonl(path) -> list[Event]`
  - Attacker infra for an epoch derives from `(seed, epoch)`. Epoch 2 reuses 60% of epoch-1 mule payees, the ring device family and the proxy /24 subnets.

- [ ] **Step 1:** Write the tests:
  - `test_deterministic`: same seed twice gives identical dicts.
  - `test_each_attack_has_one_completion`: every attack instance has exactly one `completes_takeover`.
  - `test_all_ttps_present`: all 5 TTPs present for `n_events=600`.
  - `test_benign_bait_present`: all 7 benign cases present.
  - `test_device_seen_precedes_login`: every `login_success` has a `device_seen` on the same account 1 s earlier.
  - `test_epoch2_reuses_infra`: ≥1 mule payee is shared between epoch 1 and 2 of the same seed, and no victim account is shared.
  - `test_size`: `len(generate(1, n_events=2000))` is in `[1700, 2300]`.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement with `random.Random(f"{seed}:{epoch}")`. The base timeline starts at `2026-10-01T00:00:00Z` and spans 7 days. Spray IP pool: 12 IPs over ~30 accounts, so no IP exceeds 4 accounts.
- [ ] **Step 4:** Run and expect PASS.

### Task 3: Memory line formats and channel detectors

**Files:**
- Create: `src/trailguard/memlines.py`, `src/trailguard/agents/__init__.py`, `agents/detectors.py`
- Test: `tests/test_memlines.py`, `tests/test_detectors.py`

**Interfaces:**
- Produces:
  - `memlines.format_signal(Signal) -> str`, `parse_signal(text) -> Signal|None`
  - `format_pattern(Pattern) -> str`, `parse_pattern(text) -> Pattern|None`
  - `format_decision(account_id, decision: Decision, event_id, run_id, ts) -> str`, `parse_decision(text) -> dict|None`
  - `detectors.Detector` base with `observe(event: Event, run_id: str) -> list[Signal]`; subclasses `LoginDetector`, `DeviceDetector`, `RecoveryDetector`, `PaymentsDetector`; `detectors.for_channel(channel) -> Detector`
  - Detector state is per instance (the agent's own history only).

- [ ] **Step 1:** Write the tests:
  - `test_signal_roundtrip`
  - `test_parse_signal_tolerates_prose`: text `"Note: TG-SIGNAL v1 | type=phone_change | account=C0001 | sev=medium | w=20 | agent=recovery-agent | ts=2026-10-01T00:00:00+00:00 | event=E1 | run=r1 (extracted)"` parses with `type == "phone_change"`.
  - `test_parse_signal_ignores_other_text`: `"user likes tea"` gives `None`.
  - detectors: `test_two_failed_logins_emit_failed_logins`, `test_device_on_three_accounts_emits_multi_account`, `test_impossible_travel`, `test_known_device_abroad_is_low_geo` (weight 5), `test_large_transfer_to_fresh_payee`.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. The parser finds `TG-<KIND> v1` anywhere in the text and then reads every `key=value` pair with the regex `(\w+)=([^|]+?)(?=\s*\||\s*$)`.
- [ ] **Step 4:** Run and expect PASS.

### Task 4: Meko interface, offline stand-in, meter and scopes

**Files:**
- Create: `src/trailguard/meko/__init__.py`, `meko/base.py`, `meko/fake.py`, `meko/meter.py`, `meko/scope.py`
- Test: `tests/test_fake_meko.py`, `tests/test_scope.py`

**Interfaces:**
- Produces:
  - `base.MekoError(code, detail)`, `base.BudgetExceeded`, `base.MemoryHit(id, text, score, agent_id, metadata)`, `base.KnowledgeHit(id, text, score, document_id)`, `base.ContextResult(memory: list[MemoryHit], knowledge: list[KnowledgeHit], conversation: list[dict], token_savings: dict)`
  - `base.Meko` (abstract, async):
    - `ensure_datapack(name, description) -> str`
    - `open_conversation(datapack_id, agent_id, session_id, title, metadata=None) -> str`
    - `add_memory(datapack_id, conversation_id, agent_id, text, metadata=None) -> str`
    - `search_memory(datapack_id, conversation_id, agent_id, query, limit=25) -> list[MemoryHit]`
    - `context_search(datapack_id, conversation_id, agent_id, query, limit=10) -> ContextResult`
    - `add_message(datapack_id, conversation_id, agent_id, input, output, reasoning, plan: list[str], metadata) -> str`
    - `track_tokens(datapack_id, conversation_id, name, input_tokens, output_tokens, model, message_id=None)`
    - `delete_agent_memories(datapack_id, conversation_id, agent_id)`
    - `list_learnings(datapack_id) -> list[dict]`
    - `promote(datapack_id, conversation_id, agent_id, memory_ids) -> dict`
    - `keep_private(datapack_id, memory_ids) -> dict`
    - `put_artifact(datapack_id, conversation_id, agent_id, filename, content: bytes, content_type) -> str` (returns the hash)
    - `get_artifact(datapack_id, conversation_id, agent_id, content_hash) -> bytes`
    - `upload_knowledge(datapack_id, path) -> str`
    - `knowledge_ready(datapack_id, key) -> bool`
    - `describe(datapack_id) -> dict`
    - `close()`
    - attributes `backend: str` and `meter: Meter`
  - `meter.Meter(max_retrievals=400, max_messages=120)` with `record(tool, ms, ok)`, `check(tool)` (raises `BudgetExceeded`), `summary() -> dict`
  - `fake.FakeMeko(path: Path|None)` with `backend = "offline-fake"`; `save()`
  - `scope.AgentScope(meko, agent_id, conversations: dict[str,str], read: set[str], write: set[str])`, with the same memory, search and message methods minus the `agent_id`/`conversation_id` arguments. It raises `PermissionError` on a datapack outside the allowlist.

- [ ] **Step 1:** Write the tests:
  - `test_search_prefers_exact_ids`: of 3 memories, the one containing `C0042` ranks first for query `"account=C0042"`.
  - `test_context_search_buckets`: returns both memory and knowledge hits.
  - `test_promote_moves_learning`: after `promote`, `list_learnings` no longer contains the id and `context_search` still returns it.
  - `test_artifact_roundtrip`
  - `test_persist`: save, reload, memory still searchable.
  - `test_meter_budget`: the 401st retrieval raises `BudgetExceeded`.
  - `test_scope_blocks_write`: a scope with write `{signals}` raises on `add_memory` to patterns.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. Fake search score = 0.6 × token Jaccard + 0.4 × (exact identifier hits / query identifiers), where identifiers match `[A-Z]\d{3,}|[a-z]-[0-9a-f]{4}|\d+\.\d+\.\d+\.\d+|P-\d+`. Learnings = the patterns datapack's unpromoted memories written by `curator`.
- [ ] **Step 4:** Run and expect PASS.

### Task 5: Meko Cloud client (MCP + REST)

**Files:**
- Create: `src/trailguard/meko/cloud.py`
- Test: `tests/test_cloud_client.py`

**Interfaces:**
- Consumes: `base.Meko`, `Meter`, `MekoError`
- Produces: `cloud.MekoCloud(settings, meter)` with `backend = "meko-cloud"`, `async connect()`, `tools: dict[str, dict]` (name → inputSchema), and `async call(tool, **args) -> Any` (filters args, records meter, parses the reply, raises `MekoError`)

- [ ] **Step 1:** Write the tests with a fake session object (`list_tools`/`call_tool` returning MCP `CallToolResult`-shaped objects) and `httpx.MockTransport`:
  - `test_unknown_args_dropped`: the schema has `query`, `datapack_id`; the call passes `foo=1`; the sent args lack `foo`.
  - `test_inband_error_raises`: the reply text `{"error":"datapack_access_denied","detail":"x"}` raises `MekoError` with that code.
  - `test_parses_structured_result`: `structuredContent={"result": "{\"results\": []}"}` gives `{"results": []}`.
  - `test_memory_add_returns_id`: the reply `{"results":[{"id":"m1","memory":"…","event":"ADD"}]}` gives `"m1"`.
  - `test_rest_promote_envelope`: a `{data:{inserted_ids:[…]}}` envelope is unwrapped.
  - `test_rest_error_envelope_raises`.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement with `mcp.client.streamable_http` + `mcp.ClientSession`, held open in an `AsyncExitStack`. Use a semaphore of 4 and retry with backoff (0.5 s, 1 s, 2 s) on transport errors and on `MekoError` codes containing `RATE_LIMIT`. For `context_search`, normalise buckets into `ContextResult`, accepting either a list or `{hits}` in each bucket.
- [ ] **Step 4:** Run and expect PASS.

### Task 6: Cases and channel agents

**Files:**
- Create: `src/trailguard/agents/case.py`, `agents/channel.py`
- Test: `tests/test_case.py`

**Interfaces:**
- Consumes: detectors, memlines, `AgentScope`
- Produces:
  - `case.Case(gate: Event, signals: list[Signal], patterns: list[tuple[Pattern, str]], risk: int, playbook: list[str])`
  - `case.score(signals, now: datetime) -> int`: distinct (type, entity) pairs within 72 h; weight halves after 24 h; capped at 100
  - `case.is_gate(event) -> bool`
  - `case.related(signals, gate) -> list[Signal]`: same account, or same device, IP or payee
  - `channel.ChannelAgent(channel, mode, scope: AgentScope|None, shared_log: list[Signal])` with `async handle(event, run_id) -> tuple[list[Signal], Case|None]`
  - `channel.pattern_bonus(patterns, gate, signals) -> list[Signal]`

- [ ] **Step 1:** Write the tests:
  - `test_score_decay_and_cap`
  - `test_related_matches_device_across_accounts`
  - `test_isolated_sees_only_own_channel`: a payments agent in `isolated` mode at a transfer gate does not see a `phone_change` signal in the shared log.
  - `test_stuffed_sees_all`
  - `test_meko_mode_reads_from_fake`: a signal written by the login agent through FakeMeko is in the payments agent's case.
  - `test_known_ioc_adds_60`
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. Gate types: `login_success` with a new device, `phone_change`, `email_change`, `password_reset_complete`, `mfa_device_added`, `payee_add`, `card_test`, `transfer`. In `meko*` modes the query is `f"TG-SIGNAL account={a} device={d} ip={ip} payee={p}"`; keep only hits that parse and whose `run` equals the current run.
- [ ] **Step 4:** Run and expect PASS.

### Task 7: Policy, deciders, Sentinel

**Files:**
- Create: `src/trailguard/llm/__init__.py`, `llm/heuristic.py`, `llm/claude.py`, `src/trailguard/agents/sentinel.py`
- Test: `tests/test_policy.py`, `tests/test_sentinel.py`

**Interfaces:**
- Consumes: `Case`, `Decision`, `AgentScope`
- Produces:
  - `heuristic.decide(case: Case) -> Decision`
  - `claude.ClaudeDecider(settings)` with `async decide(case, prompt: str) -> Decision`
  - `sentinel.build_prompt(case, mode) -> str`
  - `sentinel.Sentinel(decider, scope|None, mode)` with `async decide(case, run_id) -> Decision` (logs the message, tokens and the TG-DECISION memory in `meko*` modes)

- [ ] **Step 1:** Write the tests:
  - `test_policy_thresholds`: risk 39→ALLOW, 55→STEP_UP, 85 at a transfer→BLOCK, 85 at `email_change`→HOLD.
  - `test_sms_exception`: risk 55 with a `phone_change` signal ≤72 h→HOLD.
  - `test_known_ioc_blocks`
  - `test_claude_invalid_json_falls_back`: a mocked client returns `"not json"` twice; the decision has `fallback is True` and `decider` starting with `"claude"`.
  - `test_prompt_tokens_grow_in_stuffed`: the stuffed prompt with 200 signals is longer than the meko prompt with 5.
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. The Claude call uses `AsyncAnthropic().messages.create` with a JSON-schema structured output for the decision (see the claude-api skill for the current parameter form), `max_tokens=800`, and token counts from `response.usage`. The heuristic estimates tokens as `len(prompt)//4` with `tokens_estimated=True`.
- [ ] **Step 4:** Run and expect PASS.

### Task 8: Engine, outcomes, trace, checkpoint/resume

**Files:**
- Create: `src/trailguard/engine.py`, `src/trailguard/trace.py`
- Test: `tests/test_engine.py`

**Interfaces:**
- Consumes: everything above
- Produces:
  - `engine.RunConfig(run_id, mode, seed, epoch, n_events=600, pace=0.0, crash_at=None, resume=False, checkpoint_every=100)`
  - `engine.Runtime(settings, meko: Meko|None, decider, datapacks: dict[str,str])` with `classmethod async create(settings, mode)` (picks the backend, ensures datapacks)
  - `engine.run(events, cfg, rt, emit: Callable[[str, dict], Awaitable|None] | None) -> RunResult`
  - `engine.RunResult(run_id, cfg, decisions: list[dict], outcomes: dict, partial: bool, meter: dict, backend, decider)`
  - `trace.TraceWriter(run_dir)` with `write(kind, **data)` and `read(run_dir) -> list[dict]`
  - Emits SSE kinds exactly: `event`, `signal_written`, `signal_read`, `escalation`, `decision`, `interdiction`, `takeover_completed`, `checkpoint`, `metrics`, `done`.

- [ ] **Step 1:** Write the tests (fake backend, heuristic decider):
  - `test_interdiction_drops_remaining_steps`
  - `test_stepup_passes_after_phone_change` (a sim_swap step-up after `phone_change` doesn't interdict)
  - `test_budget_exhausted_marks_partial` (budget 5 → `partial is True`)
  - `test_resume_matches_uninterrupted` (crash at 250, resume → same decisions as a clean run)
  - `test_trace_has_decisions_with_meko_ids`
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. Per event: route to its channel agent → write signals → at a gate build the case → escalate if risk ≥40 → Sentinel → apply the outcome → emit. `pace` > 0 sleeps `1/pace` s per event. Checkpoint = JSON artifact plus a `TG-CHECKPOINT` memory, and a local copy in `runs/<id>/checkpoint.json`. On resume: replay detectors over `events[:offset]` without I/O, restore decisions and interdictions, then continue.
- [ ] **Step 4:** Run and expect PASS.

### Task 9: Metrics and benchmark

**Files:**
- Create: `src/trailguard/metrics.py`, `src/trailguard/bench.py`
- Test: `tests/test_metrics.py`, `tests/test_bench_e2e.py`

**Interfaces:**
- Produces:
  - `metrics.compute(events, result: RunResult, prices) -> dict` with keys `attacks, prevented, prevented_early, missed, steps_early_mean, steps_early_median, benign_accounts, fp_hold_block, fp_stepup, fp_rate, decisions, escalations, tokens_in, tokens_out, tokens_per_decision, tokens_estimated, latency_p50_ms, latency_p95_ms, meko_calls, cost_usd`
  - `bench.run_bench(modes, seeds, n_events, settings, approve=True) -> dict`, which writes `runs/bench-<ts>/results.json|md`

- [ ] **Step 1:** Write the tests:
  - `test_metrics_on_hand_built_stream` (2 attacks: one interdicted at step 1 of a 4-step attack with completion at 3 gives steps_early 2; one missed; one benign held gives fp_hold_block 1)
  - `test_bench_direction` (seeds 1–3, 800 events, fake + heuristic: mean prevented_early `meko` ≥ `isolated`; tokens `meko` < `stuffed`; `meko+patterns` epoch-2 steps_early_mean ≥ `meko` epoch 2)
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. The bench runs epoch 1 for all modes, then the Curator learns from the `meko` epoch-1 run (auto-approve), then epoch 2. It resets signals before each `meko*` run.
- [ ] **Step 4:** Run and expect PASS.

### Task 10: Curator and learning loop

**Files:**
- Create: `src/trailguard/agents/curator.py`
- Test: `tests/test_curator.py`

**Interfaces:**
- Produces:
  - `curator.Curator(scope, summariser=None)` with `async learn(events, result: RunResult, epoch) -> list[Pattern]` (writes TG-PATTERN memories)
  - `async approve(pattern_ids|"all") -> dict` (promote)
  - `async reject(memory_ids)`
  - `curator.load_patterns(meko, datapack_id, conv, query) -> list[Pattern]`

- [ ] **Step 1:** Write the tests:
  - `test_one_pattern_per_ttp_and_ioc_set`
  - `test_iocs_include_subnet_device_payee`
  - `test_approve_promotes_in_fake`
  - `test_patterns_found_by_context_search`
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. Pattern id = `PAT-<ttp>-<sha1(iocs)[:6]>`.
- [ ] **Step 4:** Run and expect PASS.

### Task 11: Explainer and audit report

**Files:**
- Create: `src/trailguard/explain.py`, `src/trailguard/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Produces:
  - `explain.card(decision_record: dict, events_by_id: dict) -> dict` with keys `headline, what_happened, what_agents_knew[], rule, pattern, what_next, meko_refs`
  - `report.audit_markdown(run_dir) -> str`
  - `report.results_markdown(bench: dict) -> str`

- [ ] **Step 1:** Write the tests:
  - `test_card_headline_plain` (no `TG-` tokens and no `_` identifiers in the headline)
  - `test_audit_has_10_decisions_and_3_walkthroughs`
  - `test_audit_records_backend`
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. The headline template is `"{Action} {gate verb} on account {acct}: {n} agents saw {k} warning signs within {h}"`. Signal and gate names map to plain English through a dictionary.
- [ ] **Step 4:** Run and expect PASS.

### Task 12: CLI, setup, knowledge base, smoke script

**Files:**
- Create: `src/trailguard/cli.py`, `src/trailguard/__main__.py`, `src/trailguard/setup.py`, `knowledge/ato-playbook.md`, `knowledge/step-up-policy.md`, `knowledge/risk-rules.md`, `knowledge/sim-swap-indicators.md`, `knowledge/mule-ring-indicators.md`, `scripts/meko_smoke.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Produces:
  - `cli.main(argv=None) -> int` with subcommands `doctor, setup, generate, run, learn, bench, explain, audit, reset, serve`
  - `setup.ensure(meko) -> dict[str,str]`, which creates or finds the datapacks, uploads the knowledge files once and writes `.trailguard.json`

- [ ] **Step 1:** Write the tests:
  - `test_cli_run_offline` (`main(["run","--mode","meko","--seed","1","--events","300"])` returns 0 and creates `runs/*/trace.jsonl`)
  - `test_cli_generate`
  - `test_cli_doctor_offline_ok`
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement with argparse. The policy text in `step-up-policy.md` must state the exact thresholds from Global Constraints.
- [ ] **Step 4:** Run and expect PASS.

### Task 13: Dashboard

**Files:**
- Create: `src/trailguard/web/__init__.py`, `web/app.py`, `web/static/index.html`, `web/static/app.js`, `web/static/styles.css`
- Test: `tests/test_web.py`

**Interfaces:**
- Consumes: `engine.run`, `bench`, `explain`, `report`, `curator`
- Produces: `web.app.create_app(settings) -> FastAPI` exposing the routes in spec §10

- [ ] **Step 1:** Write the tests:
  - `test_status`
  - `test_start_run_and_stream_done` (POST a run with 200 events and pace 0, read the SSE until `done`)
  - `test_decision_card_endpoint`
  - `test_learnings_approve`
- [ ] **Step 2:** Run and expect FAIL.
- [ ] **Step 3:** Implement. Each run gets an `asyncio.Queue` fan-out and a backlog buffer, so late subscribers get history. The UI shows the backend and decider banner.
- [ ] **Step 4:** Run and expect PASS. Then open the dashboard in a browser and check the Live, Explain, Learnings, Results and Audit views.

### Task 14: Docs, offline benchmark, submission kit

**Files:**
- Create: `README.md`, `docs/ARCHITECTURE.md`, `docs/METHODOLOGY.md`, `docs/DEMO_SCRIPT.md`, `docs/SUBMISSION.md`

- [ ] **Step 1:** Run `uv run trailguard bench --seeds 1-10 --events 2000` offline. Copy the table into METHODOLOGY as an *offline reference* run, labelled as such.
- [ ] **Step 2:** Write the README (what, why, quick start offline, live with keys, commands, repo map), ARCHITECTURE (diagram, Meko usage table tool by tool), METHODOLOGY (modes, metrics definitions, quality scoring, fairness controls, limitations), DEMO_SCRIPT (≤5 min, timed beats), SUBMISSION (checklist + copy).
- [ ] **Step 3:** Run the full `uv run pytest -q` and expect everything to pass.
