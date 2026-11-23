import pytest

from trailguard.meko.base import BudgetExceeded
from trailguard.meko.fake import FakeMeko
from trailguard.meko.meter import Meter


@pytest.fixture
async def mk(tmp_path):
    m = FakeMeko(tmp_path / "fake.json")
    dp = await m.ensure_datapack("trailguard-signals", "signals")
    conv = await m.open_conversation(dp, "login-agent", "r1:login-agent", "login")
    return m, dp, conv


async def test_ensure_datapack_idempotent(mk):
    m, dp, _ = mk
    assert await m.ensure_datapack("trailguard-signals", "x") == dp


async def test_search_prefers_exact_ids(mk):
    m, dp, conv = mk
    for acct in ("C1041", "C1042", "C1043"):
        await m.add_memory(dp, conv, "login-agent", f"TG-SIGNAL v1 | type=new_device_login | account={acct}")
    hits = await m.search_memory(dp, conv, "payments-agent", "TG-SIGNAL account=C1042", limit=3)
    assert hits[0].text.endswith("C1042")


async def test_context_search_buckets(mk):
    m, dp, conv = mk
    await m.add_memory(dp, conv, "login-agent", "TG-SIGNAL v1 | type=phone_change | account=C1001")
    kb = m.state["datapacks"][dp]
    kb  # noqa: B018 - datapack exists
    p = m.path.parent / "policy.md"
    p.write_text("# Step-up policy\n\n## 2. Phone changes\nHold when the phone number changed.\n", encoding="utf-8")
    await m.upload_knowledge(dp, p)
    res = await m.context_search(dp, conv, "sentinel", "phone number changed C1001")
    assert res.memory and res.knowledge
    assert res.token_savings["sent"] > 0


async def test_promote_moves_learning(mk):
    m, _, _ = mk
    pdp = await m.ensure_datapack("trailguard-patterns", "patterns")
    conv = await m.open_conversation(pdp, "curator", "r1:curator", "curator")
    mid = await m.add_memory(pdp, conv, "curator", "TG-PATTERN v1 | id=PAT-x | ttp=sim_swap")
    assert [x["id"] for x in await m.list_learnings(pdp)] == [mid]
    res = await m.promote(pdp, conv, "curator", [mid])
    assert res["inserted_ids"] == [mid]
    assert await m.list_learnings(pdp) == []
    found = await m.context_search(pdp, conv, "sentinel", "PAT-x sim_swap")
    assert any(h.id == mid for h in found.knowledge + found.memory)


async def test_artifact_roundtrip(mk):
    m, dp, conv = mk
    h = await m.put_artifact(dp, conv, "sentinel", "a.txt", b"hello", "text/plain")
    assert await m.get_artifact(dp, conv, "sentinel", h) == b"hello"


async def test_persist(tmp_path):
    m = FakeMeko(tmp_path / "f.json")
    dp = await m.ensure_datapack("trailguard-signals", "s")
    conv = await m.open_conversation(dp, "a", "s", "t")
    await m.add_memory(dp, conv, "a", "TG-SIGNAL v1 | type=x | account=C1777")
    m.save()
    m2 = FakeMeko(tmp_path / "f.json")
    assert (await m2.search_memory(dp, conv, "b", "C1777"))[0].text.endswith("C1777")


async def test_delete_agent_memories(mk):
    m, dp, conv = mk
    await m.add_memory(dp, conv, "login-agent", "TG-SIGNAL v1 | type=x | account=C1888")
    await m.delete_agent_memories(dp, conv, "login-agent")
    assert await m.search_memory(dp, conv, "b", "C1888") == []


def test_meter_budget():
    meter = Meter(max_retrievals=400, max_messages=120)
    for _ in range(400):
        meter.check("memory_search")
        meter.record("memory_search", 1.0, True)
    with pytest.raises(BudgetExceeded):
        meter.check("context_search")
    meter.check("memory_add")  # writes are not budgeted
