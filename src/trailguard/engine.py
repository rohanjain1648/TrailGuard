"""Replays an event stream through the agents in one mode and records what happened.

The same engine drives the CLI, the benchmark and the dashboard (through ``emit``).
"""
from __future__ import annotations

import asyncio
import inspect
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable

from trailguard.agents.case import Case
from trailguard.agents.channel import MEKO_MODES, ChannelAgent
from trailguard.agents.sentinel import Sentinel
from trailguard.config import CHANNEL_AGENTS, ESCALATE_AT, PATTERNS_DATAPACK, SENTINEL, SIGNALS_DATAPACK, Settings
from trailguard.llm.claude import make_decider
from trailguard.memlines import format_checkpoint, parse_fields, parse_pattern
from trailguard.meko.base import BudgetExceeded, Meko, MekoError
from trailguard.meko.scope import AgentScope
from trailguard.models import Event, Pattern, Signal
from trailguard.trace import TraceWriter

Emit = Callable[[str, dict], Awaitable[None] | None] | None


class SimulatedCrash(RuntimeError):
    """Raised by --crash-at to demonstrate resume from a Meko checkpoint."""


@dataclass
class RunConfig:
    run_id: str
    mode: str
    seed: int = 1
    epoch: int = 1
    n_events: int = 600
    pace: float = 0.0
    crash_at: int | None = None
    resume: bool = False
    checkpoint_every: int = 100
    reset_signals: bool = True
    max_retrievals: int = 400
    max_messages: int = 120


@dataclass
class RunResult:
    run_id: str
    cfg: dict[str, Any]
    decisions: list[dict[str, Any]]
    interdicted: dict[str, int]  # attack_id -> event index where it was stopped
    completed: list[str]  # attack_ids whose takeover completed
    partial: bool
    partial_reason: str
    meter: dict[str, Any]
    backend: str
    decider: str
    seconds: float
    patterns_used: list[str] = field(default_factory=list)
    run_dir: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Runtime:
    settings: Settings
    meko: Meko | None
    decider: Any
    datapacks: dict[str, str]

    @classmethod
    async def create(cls, settings: Settings, need_meko: bool = True, meko: Meko | None = None) -> "Runtime":
        if meko is None and need_meko:
            if settings.meko_backend == "cloud":
                from trailguard.meko.cloud import MekoCloud

                meko = await MekoCloud(settings).connect()
            else:
                from trailguard.meko.fake import FakeMeko

                meko = FakeMeko(settings.runs_dir / "fake_meko.json")
        datapacks: dict[str, str] = {}
        if meko is not None:
            datapacks = {
                "signals": await meko.ensure_datapack(SIGNALS_DATAPACK, "TrailGuard: raw risk signals, case "
                                                                        "conversations and decision traces"),
                "patterns": await meko.ensure_datapack(PATTERNS_DATAPACK, "TrailGuard: fraud playbooks and "
                                                                          "analyst-confirmed attacker patterns"),
            }
        return cls(settings, meko, make_decider(settings), datapacks)

    @property
    def backend(self) -> str:
        return self.meko.backend if self.meko else "none"

    async def close(self) -> None:
        if self.meko:
            await self.meko.close()


def scope_for(rt: Runtime, agent: str, run_id: str) -> AgentScope:
    write = {"patterns"} if agent == "curator" else {"signals"}
    return AgentScope(rt.meko, agent, rt.datapacks, read={"signals", "patterns"}, write=write, session=run_id)


async def load_patterns(scope: AgentScope) -> list[Pattern]:
    """Approved patterns only: those an analyst promoted into the datapack's collective memory.

    memory_get_all(promoted=true) lists collective memory exactly; a context_search over
    shared knowledge supplements it (it only returns promoted memories, never private ones)."""
    out: dict[str, Pattern] = {}

    def add(mid: str, text: str) -> None:
        p = parse_pattern(text)
        if p and p.pattern_id not in out:
            p.memory_id = mid
            out[p.pattern_id] = p

    for m in await scope.list_promoted("patterns"):
        add(m["id"], m["memory"])
    res = await scope.context_search("patterns", "TG-PATTERN confirmed attacker pattern indicators", limit=50)
    for h in res.knowledge:
        add(h.id, h.text)
    return list(out.values())


def second_factor_compromised(e: Event) -> bool:
    t = e.truth
    return (t.ttp == "sim_swap" and (t.step or 0) >= 2) or (t.ttp == "low_and_slow" and (t.step or 0) >= 3)


def _sig_dict(s: Signal) -> dict[str, Any]:
    return {"type": s.type, "weight": s.weight, "agent": s.agent, "account": s.account_id, "ts": s.ts.isoformat(),
            "note": s.note, "memory_id": s.memory_id, "score": s.score, "device": s.device_id, "ip": s.ip,
            "payee": s.payee_id, "event_id": s.event_id}


async def _emit(emit: Emit, kind: str, payload: dict) -> None:
    if emit is None:
        return
    r = emit(kind, payload)
    if inspect.isawaitable(r):
        await r


def _step_up_failed(e: Event) -> Event:
    return Event(f"{e.event_id}-su", e.ts + timedelta(seconds=30), "login", "step_up_failed", e.account_id, e.ip,
                 e.country, e.device_id, {"gate": e.type}, e.truth)


async def run(events: list[Event], cfg: RunConfig, rt: Runtime, emit: Emit = None) -> RunResult:
    t_start = time.perf_counter()
    meko_mode = cfg.mode in MEKO_MODES
    run_dir = rt.settings.runs_dir / cfg.run_id
    tw = TraceWriter(run_dir, append=cfg.resume)
    if rt.meko:
        rt.meko.meter.reset()
        rt.meko.meter.max_retrievals, rt.meko.meter.max_messages = cfg.max_retrievals, cfg.max_messages

    shared_log: list[Signal] = []
    patterns: list[Pattern] = []
    scopes: dict[str, AgentScope] = {}
    if meko_mode:
        for agent in [*CHANNEL_AGENTS.values(), SENTINEL]:
            scopes[agent] = scope_for(rt, agent, cfg.run_id)
        if cfg.reset_signals and not cfg.resume:
            for sc in scopes.values():
                await sc.delete_own_memories("signals")
        if cfg.mode == "meko+patterns":
            patterns = await load_patterns(scopes[SENTINEL])
    agents = {ch: ChannelAgent(ch, cfg.mode, cfg.run_id, scopes.get(a), shared_log, patterns)
              for ch, a in CHANNEL_AGENTS.items()}
    sentinel = Sentinel(rt.decider, cfg.mode, cfg.run_id, scopes.get(SENTINEL), shared_log)

    completion = {e.truth.attack_id: e.truth.step for e in events if e.truth.completes_takeover}
    decisions: list[dict[str, Any]] = []
    interdicted: dict[str, int] = {}
    completed: list[str] = []
    start = 0
    if cfg.resume:
        ck = await _load_checkpoint(run_dir, cfg.run_id, scopes.get(SENTINEL))
        start, decisions, interdicted, completed = ck["offset"], ck["decisions"], ck["interdicted"], ck["completed"]
        by_event = {d["event_id"]: d for d in decisions}
        for idx, e in enumerate(events[:start]):  # fast-forward local state, no Meko calls
            if e.truth.attack_id in interdicted and idx > interdicted[e.truth.attack_id]:
                continue
            agents[e.channel].observe_only(e)
            d = by_event.get(e.event_id)
            if d and d["outcome"] == "step_up_failed":
                agents["login"].observe_only(_step_up_failed(e))
        tw.write("resume", offset=start, decisions=len(decisions))

    await _emit(emit, "start", {"run_id": cfg.run_id, "mode": cfg.mode, "events": len(events), "start": start,
                                "backend": rt.backend, "decider": rt.decider.label,
                                "patterns": [p.pattern_id for p in patterns]})
    tw.write("start", cfg=asdict(cfg), backend=rt.backend, decider=rt.decider.label,
             patterns=[p.pattern_id for p in patterns], datapacks=rt.datapacks)
    partial, reason, errors = False, "", 0
    try:
        for idx in range(start, len(events)):
            e = events[idx]
            if cfg.crash_at is not None and idx == cfg.crash_at:
                await _checkpoint(tw, cfg, idx, decisions, interdicted, completed, scopes.get(SENTINEL))
                raise SimulatedCrash(f"simulated crash at event {idx}")
            aid = e.truth.attack_id
            if aid in interdicted:
                continue
            await _emit(emit, "event", {"idx": idx, "event_id": e.event_id, "ts": e.ts.isoformat(),
                                        "channel": e.channel, "type": e.type, "account": e.account_id,
                                        "attack": bool(aid), "ttp": e.truth.ttp if aid else None,
                                        "attack_id": aid, "step": e.truth.step,
                                        "completes": e.truth.completes_takeover})
            try:
                step = await agents[e.channel].handle(e)
                for s in step.signals:
                    await _emit(emit, "signal_written", _sig_dict(s))
                for r in step.reads:
                    await _emit(emit, "signal_read", {"reader": agents[e.channel].agent, **_sig_dict(r)})
                if step.case is not None and step.case.risk >= ESCALATE_AT:
                    rec = await _decide(step.case, e, idx, len(decisions) + 1, cfg, sentinel, agents, emit)
                    decisions.append(rec)
                    tw.write("decision", record=rec)
                    if rec["interdicted"]:
                        interdicted[aid] = idx
                        await _emit(emit, "interdiction", {"attack_id": aid, "ttp": e.truth.ttp,
                                                           "step": e.truth.step, "event_id": e.event_id,
                                                           "completion_step": completion.get(aid)})
            except MekoError as err:
                errors += 1
                tw.write("meko_error", event_id=e.event_id, code=err.code, detail=err.detail)
                if errors > 20:
                    partial, reason = True, f"too many Meko errors (last: {err.code})"
                    break
            if e.truth.completes_takeover and aid not in interdicted:
                completed.append(aid)
                tw.write("takeover_completed", attack_id=aid, ttp=e.truth.ttp, event_id=e.event_id)
                await _emit(emit, "takeover_completed", {"attack_id": aid, "ttp": e.truth.ttp,
                                                         "account": e.account_id})
            if cfg.checkpoint_every and (idx + 1) % cfg.checkpoint_every == 0:
                await _checkpoint(tw, cfg, idx + 1, decisions, interdicted, completed, scopes.get(SENTINEL))
                await _emit(emit, "checkpoint", {"offset": idx + 1})
            if cfg.pace > 0:
                await asyncio.sleep(1 / cfg.pace)
    except BudgetExceeded as b:
        partial, reason = True, str(b)
        tw.write("budget_exceeded", detail=str(b))
    except SimulatedCrash:
        tw.close()
        raise

    result = RunResult(
        run_id=cfg.run_id, cfg=asdict(cfg), decisions=decisions, interdicted=interdicted, completed=completed,
        partial=partial, partial_reason=reason, meter=rt.meko.meter.summary() if rt.meko and meko_mode else {},
        backend=rt.backend if meko_mode else "none", decider=rt.decider.label,
        seconds=round(time.perf_counter() - t_start, 2), patterns_used=[p.pattern_id for p in patterns],
        run_dir=str(run_dir))
    tw.write("done", partial=partial, reason=reason)
    tw.write_json("result.json", result.to_dict())
    tw.close()
    await _emit(emit, "done", {"run_id": cfg.run_id, "partial": partial, "reason": reason,
                               "decisions": len(decisions), "interdicted": len(interdicted),
                               "completed": len(completed)})
    return result


async def _decide(case: Case, e: Event, idx: int, n: int, cfg: RunConfig, sentinel: Sentinel,
                  agents: dict[str, ChannelAgent], emit: Emit) -> dict[str, Any]:
    await _emit(emit, "escalation", {"event_id": e.event_id, "account": e.account_id, "risk": case.risk,
                                     "agent": agents[e.channel].agent, "signals": len(case.signals)})
    t0 = time.perf_counter()
    res = await sentinel.decide(case)
    decision_ms = round((time.perf_counter() - t0) * 1000, 1)
    d = res.decision
    attack = e.truth.attack_id is not None
    if d.decision == "ALLOW":
        outcome, stop = "allowed", False
    elif d.decision == "STEP_UP":
        if attack and not second_factor_compromised(e):
            outcome, stop = "step_up_failed", True
            await agents["login"].handle(_step_up_failed(e))
        else:
            outcome, stop = "step_up_passed", False
    else:
        outcome, stop = ("stopped" if attack else "held_benign"), attack
    rec = {
        "n": n, "idx": idx, "event_id": e.event_id, "ts": e.ts.isoformat(), "account": e.account_id,
        "gate": e.type, "channel": e.channel, "escalated_by": agents[e.channel].agent, "mode": cfg.mode,
        "risk": case.risk, **{k: v for k, v in d.to_dict().items() if k != "risk"},
        "model_risk": d.risk, "signals": [_sig_dict(s) for s in case.signals],
        "patterns": [{"pattern_id": p.pattern_id, "ttp": p.ttp, "kind": k, "memory_id": p.memory_id}
                     for p, k in case.patterns],
        "playbook": [{"id": p.get("id"), "score": p.get("score"), "text": p["text"][:400]} for p in res.playbook],
        "query": case.query, "retrieved": case.retrieved, "prompt_chars": res.prompt_chars, "meko": res.meko,
        "event": {"ip": e.ip, "country": e.country, "device": e.device_id, "attrs": e.attrs},
        "truth": asdict(e.truth), "outcome": outcome, "interdicted": stop, "decision_ms": decision_ms,
    }
    await _emit(emit, "decision", rec)
    return rec


async def _checkpoint(tw: TraceWriter, cfg: RunConfig, offset: int, decisions: list, interdicted: dict,
                      completed: list, scope: AgentScope | None) -> None:
    ck = {"run_id": cfg.run_id, "offset": offset, "decisions": decisions, "interdicted": interdicted,
          "completed": completed}
    tw.write_json("checkpoint.json", ck)
    if scope is not None:
        body = json.dumps(ck, default=str).encode()
        h = await scope.put_artifact("signals", f"checkpoint-{cfg.run_id}-{offset}.json", body, "application/json")
        await scope.add_memory("signals", format_checkpoint(cfg.run_id, offset, h),
                               {"kind": "checkpoint", "run": cfg.run_id, "offset": offset})
        tw.write("checkpoint", offset=offset, artifact=h)


async def _load_checkpoint(run_dir: Path, run_id: str, scope: AgentScope | None) -> dict[str, Any]:
    local = run_dir / "checkpoint.json"
    if local.exists():
        return json.loads(local.read_text(encoding="utf-8"))
    if scope is None:
        raise FileNotFoundError(f"no checkpoint for {run_id}")
    best = None
    for h in await scope.search_memory("signals", f"TG-CHECKPOINT run={run_id}", limit=25):
        f = parse_fields(h.text, "CHECKPOINT")
        if f and f.get("run") == run_id and (best is None or int(f["offset"]) > int(best["offset"])):
            best = f
    if best is None:
        raise FileNotFoundError(f"no checkpoint for {run_id} in Meko")
    return json.loads(await scope.get_artifact("signals", best["hash"]))
