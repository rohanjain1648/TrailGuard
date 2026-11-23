"""Claude as the Sentinel's decider, with structured JSON output.

Uses the beta Messages endpoint so the server-side refusal fallback
(`fallbacks: "default"`) can re-run a declined request on another model. If the reply
can't be used after one retry (refusal, bad JSON, API error) the deterministic policy
decides instead and the decision is marked ``fallback=True``.
"""
from __future__ import annotations

import json
import time
from typing import Any

from trailguard.agents.case import Case
from trailguard.config import Settings
from trailguard.llm import heuristic
from trailguard.models import Decision

DECISIONS = ["ALLOW", "STEP_UP", "HOLD", "BLOCK"]

DECISION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "decision": {"type": "string", "enum": DECISIONS},
        "risk": {"type": "integer"},
        "hypothesis": {"type": "string"},
        "reasons": {"type": "array", "items": {"type": "string"}},
        "evidence_ids": {"type": "array", "items": {"type": "string"}},
        "policy_refs": {"type": "array", "items": {"type": "string"}},
        "plain_english": {"type": "string"},
    },
    "required": ["decision", "risk", "hypothesis", "reasons", "evidence_ids", "policy_refs", "plain_english"],
    "additionalProperties": False,
}

FALLBACK_BETA = "server-side-fallback-2026-07-01"


def _validate(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or data.get("decision") not in DECISIONS:
        raise ValueError("decision missing or invalid")
    for k in ("reasons", "evidence_ids", "policy_refs"):
        if not isinstance(data.get(k), list):
            raise ValueError(f"{k} must be a list")
    data["risk"] = max(0, min(100, int(data.get("risk", 0))))
    return data


class ClaudeDecider:
    def __init__(self, settings: Settings, client: Any = None) -> None:
        if client is None:
            from anthropic import AsyncAnthropic

            client = AsyncAnthropic(api_key=settings.anthropic_api_key or None)
        self.client = client
        self.model = settings.model
        self.effort = settings.effort
        self.label = f"claude:{settings.model}"

    async def decide(self, case: Case, system: str, prompt: str) -> Decision:
        import anthropic

        t0 = time.perf_counter()
        tin = tout = 0
        why = ""
        for _ in range(2):
            try:
                resp = await self.client.beta.messages.create(
                    model=self.model,
                    max_tokens=8000,
                    betas=[FALLBACK_BETA],
                    fallbacks="default",
                    system=system,
                    messages=[{"role": "user", "content": prompt}],
                    output_config={"effort": self.effort,
                                   "format": {"type": "json_schema", "schema": DECISION_SCHEMA}},
                )
            except anthropic.APIError as e:
                why = f"api error: {type(e).__name__}"
                break
            tin += getattr(resp.usage, "input_tokens", 0) or 0
            tout += getattr(resp.usage, "output_tokens", 0) or 0
            if resp.stop_reason == "refusal":
                why = "refusal"
                break
            text = next((b.text for b in resp.content if getattr(b, "type", "") == "text"), "")
            try:
                data = _validate(json.loads(text))
            except (ValueError, TypeError) as e:
                why = f"unusable reply: {e}"
                continue
            by_id = {e["memory_id"]: e for e in heuristic.evidence(case) if e["memory_id"]}
            cited = [by_id[i] for i in data["evidence_ids"] if i in by_id]
            return Decision(
                decision=data["decision"], risk=data["risk"], hypothesis=data["hypothesis"],
                reasons=data["reasons"], evidence=cited or heuristic.evidence(case),
                policy_refs=data["policy_refs"], pattern_id=next((p.pattern_id for p, _ in case.patterns), None),
                plain_english=data["plain_english"], decider=self.label, tokens_in=tin, tokens_out=tout,
                latency_ms=(time.perf_counter() - t0) * 1000)
        d = heuristic.decide(case)
        d.decider, d.fallback = self.label, True
        d.reasons = [f"Claude reply not used ({why}); written policy applied"] + d.reasons
        d.tokens_in, d.tokens_out = tin, tout
        d.latency_ms = (time.perf_counter() - t0) * 1000
        return d


class HeuristicDecider:
    """Same interface as ClaudeDecider; tokens are what the prompt *would* cost (estimated)."""

    label = "heuristic"

    async def decide(self, case: Case, system: str, prompt: str) -> Decision:
        t0 = time.perf_counter()
        d = heuristic.decide(case)
        d.tokens_in = (len(system) + len(prompt)) // 4
        d.tokens_out = 120
        d.tokens_estimated = True
        d.latency_ms = (time.perf_counter() - t0) * 1000
        return d


def make_decider(settings: Settings) -> ClaudeDecider | HeuristicDecider:
    return ClaudeDecider(settings) if settings.llm == "claude" else HeuristicDecider()
