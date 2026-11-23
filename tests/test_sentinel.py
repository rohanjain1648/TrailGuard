from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from trailguard.agents.case import Case
from trailguard.agents.sentinel import Sentinel, build_prompt
from trailguard.config import Settings
from trailguard.llm.claude import ClaudeDecider, HeuristicDecider
from trailguard.meko.fake import FakeMeko
from trailguard.meko.scope import AgentScope
from trailguard.models import Event, Signal

T0 = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def sig(i, acct="C1001"):
    return Signal("email_change", "medium", 25, acct, "recovery-agent", T0 - timedelta(minutes=i), f"E{i}", "r1",
                  note="account email changed")


def mkcase(risk=55, signals=None):
    g = Event("G1", T0, "payments", "transfer", "C1001", "5.5.5.5", "IN", "d-aaaa",
              {"payee_id": "P-9001", "amount": 900, "typical_amount": 100, "payee_known": False})
    return Case(gate=g, signals=signals if signals is not None else [sig(1)], risk=risk)


def settings():
    return Settings("", "sk-test", "fake", "claude", "claude-opus-5-5", "medium", "", "", Path("runs"))


class FakeClient:
    def __init__(self, texts):
        self.texts = list(texts)
        self.calls = 0
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    async def create(self, **kw):
        self.calls += 1
        assert kw["fallbacks"] == "default" and kw["output_config"]["format"]["type"] == "json_schema"
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.texts.pop(0))], stop_reason="end_turn",
                               usage=SimpleNamespace(input_tokens=100, output_tokens=20))


async def test_claude_invalid_json_falls_back():
    client = FakeClient(["not json", "still not json"])
    d = await ClaudeDecider(settings(), client=client).decide(mkcase(), "sys", "prompt")
    assert client.calls == 2
    assert d.fallback is True and d.decider.startswith("claude")
    assert d.decision == "STEP_UP" and d.tokens_in == 200


async def test_claude_valid_json_used():
    reply = ('{"decision":"HOLD","risk":60,"hypothesis":"sim_swap","reasons":["phone changed"],'
             '"evidence_ids":[],"policy_refs":["§2"],"plain_english":"Paused."}')
    d = await ClaudeDecider(settings(), client=FakeClient([reply])).decide(mkcase(), "sys", "prompt")
    assert d.decision == "HOLD" and not d.fallback and d.plain_english == "Paused."


def test_prompt_tokens_grow_in_stuffed():
    log = [sig(i, acct=f"C{1000 + i}") for i in range(200)]
    stuffed = build_prompt(mkcase(), "stuffed", [{"id": "p", "text": "policy"}], log)
    meko = build_prompt(mkcase(signals=[sig(i) for i in range(5)]), "meko", [{"id": "p", "text": "policy"}], log)
    assert len(stuffed) > 5 * len(meko)


async def test_sentinel_logs_trace_to_meko():
    m = FakeMeko(None)
    dps = {"signals": await m.ensure_datapack("trailguard-signals", ""),
           "patterns": await m.ensure_datapack("trailguard-patterns", "")}
    scope = AgentScope(m, "sentinel", dps, read={"signals", "patterns"}, write={"signals"}, session="r1")
    s = Sentinel(HeuristicDecider(), "meko", "r1", scope, [])
    res = await s.decide(mkcase())
    assert res.decision.decision == "STEP_UP"
    assert res.meko["message_id"] and res.meko["decision_memory_id"]
    conv = m.state["conversations"][res.meko["conversation_id"]]
    assert conv["messages"][0]["plan"][-1] == "decide STEP_UP"
    assert m.meter.calls["track_token_usage"] == 1
