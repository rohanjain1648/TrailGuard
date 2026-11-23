"""The Sentinel: decides escalated cases and leaves a decision trace in Meko.

For each decision in a Meko mode it
  * retrieves playbook passages (and, in meko+patterns, confirmed patterns) with
    ``context_search`` on the patterns datapack,
  * logs the turn with ``conversation_add_message`` (input, output, reasoning, plan) on a
    per-account case conversation, which Meko shows as a Decision trace,
  * attributes model spend with ``track_token_usage``,
  * writes the outcome back as a shared signal (``under_watch`` / ``case_blocked``) so every
    agent that later meets this account, device, IP or payee knows.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from trailguard.agents.case import Case, gate_payee
from trailguard.config import ROOT, SIGNAL_WEIGHTS
from trailguard.memlines import format_signal, parse_pattern
from trailguard.meko.scope import AgentScope
from trailguard.models import Decision, Signal

MEKO_MODES = {"meko", "meko+patterns"}

SYSTEM = """You are the Sentinel in TrailGuard, a team of fraud-detection agents that share risk signals.
You decide one escalated case at a time: ALLOW, STEP_UP (extra verification), HOLD (pause for an analyst) or BLOCK.
Apply the step-up policy you are given exactly. The risk score is computed for you from the case signals; you may
adjust it by at most 10 points if the evidence clearly warrants it, and say why.
Cite the memory ids of the evidence you relied on in evidence_ids, and the policy sections in policy_refs.
Write plain_english for a non-engineer in one or two sentences: what happened, what the agents saw, and why this
action. Do not use internal signal names or ids in plain_english."""


def policy_text() -> str:
    return (ROOT / "knowledge" / "step-up-policy.md").read_text(encoding="utf-8")


@dataclass
class SentinelResult:
    decision: Decision
    prompt_chars: int
    playbook: list[dict] = field(default_factory=list)
    meko: dict[str, Any] = field(default_factory=dict)  # conversation_id, message_id, decision memory_id


def _sig_line(s: Signal) -> str:
    return f"- [{s.memory_id or 'local'}] {format_signal(s)}"


def build_prompt(case: Case, mode: str, playbook: list[dict], shared_log: list[Signal] | None = None) -> str:
    g = case.gate
    lines = [
        f"GATE EVENT {g.event_id} at {g.ts.isoformat()}: {g.type} on account {g.account_id} "
        f"(channel {g.channel}, ip {g.ip}, country {g.country}, device {g.device_id or '-'}, "
        f"payee {gate_payee(g) or '-'}, attrs {json.dumps(g.attrs, sort_keys=True)})",
        f"COMPUTED RISK: {case.risk}/100",
        "",
    ]
    if mode == "stuffed" and shared_log is not None:
        lines.append(f"ALL SHARED SIGNALS SO FAR ({len(shared_log)}; find the ones relevant to this case):")
        lines += [_sig_line(s) for s in shared_log]
    else:
        lines.append(f"CASE SIGNALS ({len(case.signals)}):")
        lines += [_sig_line(s) for s in case.signals] or ["- none"]
    if case.patterns:
        lines += ["", "CONFIRMED ATTACKER PATTERNS MATCHED:"]
        lines += [f"- {p.pattern_id} ({kind}): {p.ttp}, sequence {' > '.join(p.sequence)}, action {p.action}"
                  for p, kind in case.patterns]
    lines += ["", "STEP-UP POLICY:"]
    lines += [f"[{p.get('id', 'local')}] {p['text']}" for p in playbook]
    return "\n".join(lines)


class Sentinel:
    agent = "sentinel"

    def __init__(self, decider: Any, mode: str, run_id: str, scope: AgentScope | None,
                 shared_log: list[Signal]) -> None:
        self.decider = decider
        self.mode = mode
        self.run_id = run_id
        self.scope = scope
        self.shared_log = shared_log
        self._local_policy = [{"id": "local:step-up-policy.md", "text": policy_text(), "score": None}]

    async def _playbook(self, case: Case) -> list[dict]:
        if self.mode not in MEKO_MODES or self.scope is None:
            return self._local_policy
        types = " ".join(sorted({s.type for s in case.signals}))
        res = await self.scope.context_search(
            "patterns", f"step-up policy for {case.gate.type} with signals {types}", limit=6)
        out = []
        for hid, text, sc in res.texts():
            if parse_pattern(text) is not None:  # patterns are matched by the channel agents, not re-read
                continue
            out.append({"id": hid, "text": text, "score": sc})
        return out[:4] or self._local_policy

    async def decide(self, case: Case) -> SentinelResult:
        playbook = await self._playbook(case)
        case.playbook = playbook
        prompt = build_prompt(case, self.mode, playbook, self.shared_log)
        d = await self.decider.decide(case, SYSTEM, prompt)
        if self.mode in MEKO_MODES and not any("Step-up policy" in r for r in d.policy_refs):
            d.policy_refs += [f"KB:{p['id']}" for p in playbook[:2]]
        res = SentinelResult(d, len(prompt), playbook)
        await self._record(case, d, prompt, res)
        return res

    async def _record(self, case: Case, d: Decision, prompt: str, res: SentinelResult) -> None:
        g = case.gate
        outcome: Signal | None = None
        if d.decision in ("STEP_UP", "HOLD", "BLOCK"):
            t = "under_watch" if d.decision == "STEP_UP" else "case_blocked"
            outcome = Signal(t, "medium", SIGNAL_WEIGHTS[t], g.account_id, self.agent, g.ts, g.event_id,
                             self.run_id, g.device_id, g.ip, gate_payee(g),
                             note=f"Sentinel {d.decision} at {g.type} (risk {d.risk}, {d.hypothesis})")
        if self.mode == "stuffed" and outcome:
            self.shared_log.append(outcome)
        if self.mode not in MEKO_MODES or self.scope is None:
            return
        thread = f"case:{g.account_id}"
        plan = [
            f"read gate {g.type} {g.event_id}",
            f"memory_search signals datapack: {case.retrieved} hits, {len(case.signals)} related",
            f"context_search patterns datapack: {len(case.playbook)} policy passages",
            f"risk {case.risk}/100" + (f", patterns {[p.pattern_id for p, _ in case.patterns]}" if case.patterns else ""),
            f"apply {', '.join(d.policy_refs[:2])}",
            f"decide {d.decision}",
        ]
        reasoning = "; ".join(d.reasons[:12])
        conv, mid = await self.scope.add_message(
            "signals", thread,
            input=f"Case {g.account_id}: {g.type} at {g.ts.isoformat()} (risk {case.risk}). "
                  f"Evidence from {', '.join(case.agents) or 'no other agents'}.",
            output=json.dumps({"decision": d.decision, "risk": d.risk, "hypothesis": d.hypothesis,
                               "plain_english": d.plain_english, "policy_refs": d.policy_refs}),
            reasoning=reasoning, plan=plan,
            metadata={"run": self.run_id, "event": g.event_id, "account": g.account_id, "mode": self.mode,
                      "decision": d.decision, "decider": d.decider, "fallback": d.fallback})
        res.meko = {"conversation_id": conv, "message_id": mid}
        if d.tokens_in or d.tokens_out:
            model = d.decider.split(":", 1)[-1]
            await self.scope.track_tokens("signals", thread, "sentinel.decide", d.tokens_in, d.tokens_out,
                                          model, mid)
        if outcome:
            outcome.memory_id = await self.scope.add_memory(
                "signals", format_signal(outcome),
                {"kind": "decision", "run": self.run_id, "account": g.account_id, "decision": d.decision})
            res.meko["decision_memory_id"] = outcome.memory_id
