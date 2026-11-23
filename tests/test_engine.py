from dataclasses import replace
from pathlib import Path

import pytest

from trailguard.config import Settings
from trailguard.engine import RunConfig, Runtime, SimulatedCrash, run, second_factor_compromised
from trailguard.meko.fake import FakeMeko
from trailguard.models import Event, Truth
from trailguard.sim import attack_instances, generate
from trailguard.trace import read


def settings(tmp_path: Path) -> Settings:
    return Settings("", "", "fake", "heuristic", "claude-opus-5-5", "medium", "", "", tmp_path)


async def runtime(tmp_path, meko=None):
    return await Runtime.create(settings(tmp_path), meko=meko or FakeMeko(None))


async def test_interdiction_drops_remaining_steps(tmp_path):
    rt = await runtime(tmp_path)
    events = generate(1, n_events=600)
    res = await run(events, RunConfig("r-int", "meko", n_events=600), rt)
    assert res.interdicted
    seen_after = {d["event_id"] for d in res.decisions}
    for aid, idx in res.interdicted.items():
        later = [e for e in events[idx + 1:] if e.truth.attack_id == aid]
        assert not ({e.event_id for e in later} & seen_after)
        assert aid not in res.completed


def test_stepup_passes_after_phone_change():
    def e(ttp, step):
        return Event("E", None, "recovery", "x", "C", "1", "IN", None, {}, Truth("A", ttp, step, False))

    assert not second_factor_compromised(e("sim_swap", 1))
    assert second_factor_compromised(e("sim_swap", 3))
    assert second_factor_compromised(e("low_and_slow", 4))
    assert not second_factor_compromised(e("mule_ring", 3))


async def test_budget_exhausted_marks_partial(tmp_path):
    rt = await runtime(tmp_path)
    res = await run(generate(2, n_events=600), RunConfig("r-bud", "meko", max_retrievals=5), rt)
    assert res.partial is True and "budget" in res.partial_reason
    assert (tmp_path / "r-bud" / "result.json").exists()


async def test_resume_matches_uninterrupted(tmp_path):
    events = generate(3, n_events=600)
    clean = await run(events, RunConfig("r-clean", "meko"), await runtime(tmp_path / "a"))
    rt = await runtime(tmp_path / "b")
    with pytest.raises(SimulatedCrash):
        await run(events, RunConfig("r-res", "meko", crash_at=250), rt)
    resumed = await run(events, RunConfig("r-res", "meko", resume=True), rt)
    pick = lambda r: [(d["event_id"], d["decision"]) for d in r.decisions]  # noqa: E731
    assert pick(resumed) == pick(clean)
    assert resumed.interdicted == clean.interdicted and resumed.completed == clean.completed


async def test_resume_from_meko_checkpoint_without_local_file(tmp_path):
    events = generate(3, n_events=400)
    rt = await runtime(tmp_path)
    with pytest.raises(SimulatedCrash):
        await run(events, RunConfig("r-m", "meko", crash_at=250), rt)
    (tmp_path / "r-m" / "checkpoint.json").unlink()
    res = await run(events, RunConfig("r-m", "meko", resume=True), rt)
    assert res.decisions


async def test_trace_has_decisions_with_meko_ids(tmp_path):
    rt = await runtime(tmp_path)
    await run(generate(4, n_events=600), RunConfig("r-tr", "meko"), rt)
    decisions = read(tmp_path / "r-tr", "decisions.jsonl")
    assert len(decisions) >= 3
    d = decisions[0]
    assert d["meko"]["message_id"] and d["signals"] and all(s["memory_id"] for s in d["signals"])


async def test_isolated_uses_no_meko(tmp_path):
    rt = await runtime(tmp_path)
    res = await run(generate(5, n_events=400), RunConfig("r-iso", "isolated"), rt)
    assert res.backend == "none" and res.meter == {}
    assert sum(rt.meko.meter.calls.values()) == 0


async def test_all_attacks_accounted(tmp_path):
    rt = await runtime(tmp_path)
    events = generate(6, n_events=600)
    res = await run(events, RunConfig("r-acc", "stuffed"), rt)
    for aid in attack_instances(events):
        assert aid in res.interdicted or aid in res.completed
