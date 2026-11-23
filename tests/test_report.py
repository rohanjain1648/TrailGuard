import re

import pytest

from trailguard.config import Settings
from trailguard.engine import RunConfig, Runtime, run
from trailguard.explain import card
from trailguard.meko.fake import FakeMeko
from trailguard.report import audit_markdown
from trailguard.sim import generate
from trailguard.trace import read


@pytest.fixture
async def run_dir(tmp_path):
    rt = await Runtime.create(Settings("", "", "fake", "heuristic", "x", "medium", "", "", tmp_path), meko=FakeMeko(None))
    await run(generate(1, 1, 1200), RunConfig("rep", "meko", 1, 1, 1200), rt)
    return tmp_path / "rep"


async def test_card_headline_plain(run_dir):
    for rec in read(run_dir, "decisions.jsonl"):
        c = card(rec)
        assert "TG-" not in c["headline"] and not re.search(r"[a-z]_[a-z]", c["headline"])
        assert c["what_agents_knew"] and c["what_next"] and c["rule"]


async def test_audit_has_10_decisions_and_3_walkthroughs(run_dir):
    md = audit_markdown(run_dir)
    table = md.split("## Every decision")[1].split("## Walkthroughs")[0]
    assert sum(1 for line in table.splitlines() if re.match(r"\| \d+ \|", line)) >= 10
    assert md.count("#### Decision") >= 3


async def test_audit_records_backend(run_dir):
    assert "OFFLINE stand-in (not Meko)" in audit_markdown(run_dir)
