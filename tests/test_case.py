from datetime import datetime, timedelta, timezone

from trailguard.agents.case import case_signals, is_gate, pattern_bonus, score
from trailguard.agents.channel import ChannelAgent
from trailguard.meko.fake import FakeMeko
from trailguard.meko.scope import AgentScope
from trailguard.models import Event, Pattern, Signal

T0 = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def s(type, w, account="C1001", ts=T0, agent="login-agent", device=None, ip=None, payee=None, run="r1"):
    return Signal(type, "medium", w, account, agent, ts, "E", run, device, ip, payee)


def gate(type="transfer", account="C1001", ts=T0 + timedelta(minutes=5), device="d-aaaa", ip="5.5.5.5", **attrs):
    return Event("G1", ts, "payments", type, account, ip, "IN", device, attrs)


def test_score_decay_and_cap():
    now = T0 + timedelta(hours=30)
    assert score([s("phone_change", 20, ts=T0)], now) == 10  # older than 24 h: halved
    assert score([s("phone_change", 20), s("phone_change", 20)], T0) == 20  # de-duplicated
    assert score([s(f"t{i}", 30) for i in range(5)], T0) == 100


def test_case_signals_links_infra_across_accounts():
    g = gate(device="d-f111")
    other_infra = s("device_multi_account", 40, account="C1009", device="d-f111")
    other_noise = s("new_device_login", 20, account="C1009", device="d-f111")
    blocked = s("case_blocked", 15, account="C1009", device="d-f111", agent="sentinel")
    out = case_signals([other_infra, other_noise, blocked], g)
    types = sorted(x.type for x in out)
    assert types == ["device_multi_account", "linked_case"]


def test_window_excludes_future_and_old():
    g = gate()
    out = case_signals([s("phone_change", 20, ts=g.ts + timedelta(minutes=1)),
                        s("email_change", 25, ts=g.ts - timedelta(hours=80))], g)
    assert out == []


def test_is_gate_needs_local_signal():
    e = gate()
    assert is_gate(e, [s("large_transfer", 25)])
    assert not is_gate(e, [])
    assert not is_gate(gate(type="device_seen"), [s("new_device", 10)])


def test_known_ioc_and_ttp_bonus():
    p = Pattern("PAT-x", "sim_swap", ["risky_support_contact", "phone_change"],
                {"ip_subnet": ["5.5.5"], "device": [], "payee": []}, "risky_support_contact", "HOLD", 1)
    g = gate(type="phone_change")
    sigs = [s("risky_support_contact", 15, ts=T0), s("phone_change", 20, ts=g.ts)]
    bonus = pattern_bonus([p], g, sigs)
    assert {b.type for b in bonus} == {"known_attacker_ioc", "ttp_match"}
    assert sum(b.weight for b in bonus) == 90


async def _agents(mode):
    m = FakeMeko(None)
    dps = {"signals": await m.ensure_datapack("trailguard-signals", ""),
           "patterns": await m.ensure_datapack("trailguard-patterns", "")}
    shared: list[Signal] = []

    def mk(channel, agent):
        scope = AgentScope(m, agent, dps, read={"signals", "patterns"}, write={"signals"}, session="r1") \
            if mode.startswith("meko") else None
        return ChannelAgent(channel, mode, "r1", scope, shared, [])

    return mk("recovery", "recovery-agent"), mk("payments", "payments-agent")


def _phone_change():
    return Event("E1", T0, "recovery", "phone_change", "C1001", "5.5.5.5", "IN", None,
                 {"via": "support", "known_device": False})


def _transfer():
    return Event("E2", T0 + timedelta(minutes=30), "payments", "transfer", "C1001", "5.5.5.5", "IN", "d-bbbb",
                 {"amount": 5000, "payee_id": "P-9001", "typical_amount": 100, "payee_known": False})


async def test_isolated_sees_only_own_channel():
    rec, pay = await _agents("isolated")
    await rec.handle(_phone_change())
    step = await pay.handle(_transfer())
    assert step.case is not None
    assert "phone_change" not in {x.type for x in step.case.signals}


async def test_stuffed_sees_all():
    rec, pay = await _agents("stuffed")
    await rec.handle(_phone_change())
    step = await pay.handle(_transfer())
    assert "phone_change" in {x.type for x in step.case.signals}


async def test_meko_mode_reads_from_meko():
    rec, pay = await _agents("meko")
    await rec.handle(_phone_change())
    step = await pay.handle(_transfer())
    got = [x for x in step.case.signals if x.type == "phone_change"]
    assert got and got[0].memory_id  # it came back from Meko, with its memory id
    assert step.reads and step.reads[0].agent == "recovery-agent"
