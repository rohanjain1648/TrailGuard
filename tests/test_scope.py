import pytest

from trailguard.meko.fake import FakeMeko
from trailguard.meko.scope import AgentScope


async def test_scope_blocks_write(tmp_path):
    m = FakeMeko(None)
    dps = {"signals": await m.ensure_datapack("trailguard-signals", ""),
           "patterns": await m.ensure_datapack("trailguard-patterns", "")}
    s = AgentScope(m, "login-agent", dps, read={"signals", "patterns"}, write={"signals"}, session="r1")
    await s.add_memory("signals", "TG-SIGNAL v1 | type=x | account=C1001")
    with pytest.raises(PermissionError):
        await s.add_memory("patterns", "TG-PATTERN v1 | id=x | ttp=y")
    assert await s.search_memory("patterns", "anything") == []


async def test_scope_reuses_conversation(tmp_path):
    m = FakeMeko(None)
    dps = {"signals": await m.ensure_datapack("trailguard-signals", "")}
    s = AgentScope(m, "sentinel", dps, read={"signals"}, write={"signals"}, session="r1")
    a = await s.conversation("signals", "case:C1001")
    b = await s.conversation("signals", "case:C1001")
    c = await s.conversation("signals", "case:C1002")
    assert a == b != c
