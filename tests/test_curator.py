from pathlib import Path

from trailguard.agents.curator import Curator, build_patterns
from trailguard.config import Settings
from trailguard.engine import RunConfig, Runtime, load_patterns, run, scope_for
from trailguard.meko.fake import FakeMeko
from trailguard.sim import generate


def test_one_pattern_per_ttp_with_iocs():
    pats = build_patterns(generate(1, 1, 600), 1)
    assert sorted(p.ttp for p in pats) == sorted({"credential_stuffing", "sim_swap", "session_hijack", "mule_ring",
                                                  "low_and_slow"})
    ring = next(p for p in pats if p.ttp == "mule_ring")
    assert ring.iocs["device"] and ring.iocs["payee"] and ring.iocs["ip_subnet"]


def test_signature_excludes_signals_genuine_customers_show():
    for p in build_patterns(generate(2, 1, 2000), 1):
        assert "new_device" not in p.sequence and "new_payee" not in p.sequence


async def test_approve_promotes_and_patterns_load(tmp_path):
    m = FakeMeko(None)
    rt = await Runtime.create(Settings("", "", "fake", "heuristic", "x", "medium", "", "", tmp_path), meko=m)
    cur = Curator(scope_for(rt, "curator", "r1"))
    ev = generate(1, 1, 600)
    pats = await cur.learn(ev, None, 1)
    assert len(await cur.pending()) == len(pats)
    assert await load_patterns(scope_for(rt, "sentinel", "r2")) == []  # not approved yet
    res = await cur.approve("all")
    assert len(res["inserted_ids"]) == len(pats) and await cur.pending() == []
    loaded = await load_patterns(scope_for(rt, "sentinel", "r2"))
    assert {p.pattern_id for p in loaded} == {p.pattern_id for p in pats}


async def test_only_curator_writes_patterns(tmp_path):
    rt = await Runtime.create(Settings("", "", "fake", "heuristic", "x", "medium", "", "", tmp_path), meko=FakeMeko(None))
    import pytest

    with pytest.raises(PermissionError):
        await scope_for(rt, "payments-agent", "r").add_memory("patterns", "TG-PATTERN v1 | id=x | ttp=y")


async def test_patterns_stop_epoch2_earlier(tmp_path):
    rt = await Runtime.create(Settings("", "", "fake", "heuristic", "x", "medium", "", "", tmp_path), meko=FakeMeko(None))
    e1 = generate(4, 1, 800)
    r1 = await run(e1, RunConfig("e1", "meko", 4, 1, 800), rt)
    cur = Curator(scope_for(rt, "curator", "e1"))
    await cur.learn(e1, r1, 1)
    await cur.approve("all")
    e2 = generate(4, 2, 800)
    base = await run(e2, RunConfig("e2m", "meko", 4, 2, 800), rt)
    learned = await run(e2, RunConfig("e2p", "meko+patterns", 4, 2, 800), rt)
    from trailguard.metrics import compute

    assert compute(e2, learned)["steps_early_mean"] > compute(e2, base)["steps_early_mean"]
    assert learned.patterns_used
