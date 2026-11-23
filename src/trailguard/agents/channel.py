"""A channel agent: detects signals on its own stream, shares them, and builds cases at gates.

What it can *see* when building a case depends only on the mode:
  isolated       its own signals (each team's silo)
  stuffed        every agent's signals, passed around in full (no Meko)
  meko           signals retrieved from the shared Meko datapack (memory_search)
  meko+patterns  as meko, plus analyst-approved attacker patterns from collective memory
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from trailguard.agents.case import Case, case_signals, gate_payee, is_gate, pattern_bonus, score
from trailguard.agents.detectors import for_channel
from trailguard.memlines import format_signal, parse_signal
from trailguard.meko.scope import AgentScope
from trailguard.models import Event, Pattern, Signal

MEKO_MODES = {"meko", "meko+patterns"}


@dataclass
class AgentStep:
    signals: list[Signal]
    case: Case | None = None
    reads: list[Signal] = field(default_factory=list)  # other agents' signals this agent read from Meko
    meko_ms: float = 0.0


def signal_query(g: Event) -> str:
    parts = [f"account={g.account_id}"]
    if g.device_id:
        parts.append(f"device={g.device_id}")
    if g.ip:
        parts.append(f"ip={g.ip}")
    if gate_payee(g):
        parts.append(f"payee={gate_payee(g)}")
    return "TG-SIGNAL " + " ".join(parts)


class ChannelAgent:
    def __init__(self, channel: str, mode: str, run_id: str, scope: AgentScope | None, shared_log: list[Signal],
                 patterns: list[Pattern]) -> None:
        self.detector = for_channel(channel)
        self.agent = self.detector.agent
        self.channel = channel
        self.mode = mode
        self.run_id = run_id
        self.scope = scope
        self.shared_log = shared_log
        self.patterns = patterns
        self.own: list[Signal] = []

    def observe_only(self, e: Event) -> list[Signal]:
        """Update local detector state without any I/O (used when resuming a run)."""
        sigs = self.detector.observe(e, self.run_id)
        self.own.extend(sigs)
        self.shared_log.extend(sigs)
        return sigs

    async def share(self, s: Signal) -> None:
        if self.mode in MEKO_MODES and self.scope is not None:
            s.memory_id = await self.scope.add_memory(
                "signals", format_signal(s),
                {"kind": "signal", "run": self.run_id, "account": s.account_id, "type": s.type})

    async def handle(self, e: Event) -> AgentStep:
        sigs = self.observe_only(e)
        t0 = time.perf_counter()
        for s in sigs:
            await self.share(s)
        step = AgentStep(sigs)
        if not is_gate(e, sigs):
            step.meko_ms = (time.perf_counter() - t0) * 1000
            return step
        query = ""
        if self.mode == "isolated":
            candidates = list(self.own)
        elif self.mode == "stuffed":
            candidates = list(self.shared_log)
        else:
            query = signal_query(e)
            hits = await self.scope.search_memory("signals", query, limit=25)
            candidates = []
            for h in hits:
                s = parse_signal(h.text)
                if s is None or s.run_id != self.run_id:
                    continue
                s.memory_id, s.score = h.id, h.score
                candidates.append(s)
            ids = {(c.event_id, c.type) for c in candidates}
            candidates += [s for s in sigs if (s.event_id, s.type) not in ids]  # read-after-write safety
        related = case_signals(candidates, e)
        if self.mode in MEKO_MODES:  # other agents' signals that actually shaped this case
            step.reads = [c for c in related if c.agent != self.agent and c.memory_id]
        bonus = pattern_bonus(self.patterns, e, related) if self.mode == "meko+patterns" else []
        all_sigs = related + bonus
        case = Case(gate=e, signals=all_sigs, risk=score(all_sigs, e.ts), query=query,
                    retrieved=len(candidates) if self.mode in MEKO_MODES else 0)
        case.patterns = [(p, b.type) for b in bonus for p in self.patterns if p.pattern_id in b.note]
        step.case = case
        step.meko_ms = (time.perf_counter() - t0) * 1000
        return step
