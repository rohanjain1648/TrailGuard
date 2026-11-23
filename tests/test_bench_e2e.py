"""End to end, offline: assert the direction of results, never fixed numbers."""
from pathlib import Path

from trailguard.bench import run_bench
from trailguard.config import Settings
from trailguard.meko.fake import FakeMeko


async def test_bench_direction(tmp_path):
    s = Settings("", "", "fake", "heuristic", "claude-opus-5-5", "medium", "", "", tmp_path)
    b = await run_bench(s, [1, 2], 800, meko_factory=lambda seed: FakeMeko(None), out_dir=tmp_path / "bench")
    agg = {(a["epoch"], a["mode"]): a for a in b["aggregate"]}
    iso, meko, stuffed = agg[(1, "isolated")], agg[(1, "meko")], agg[(1, "stuffed")]
    assert meko["prevented_early"] >= iso["prevented_early"]
    assert meko["recall"] >= iso["recall"]
    assert meko["tokens_per_decision"] < stuffed["tokens_per_decision"] / 3
    assert agg[(2, "meko+patterns")]["steps_early_mean"] >= agg[(2, "meko")]["steps_early_mean"]
    assert b["backend"] == "offline-fake"
    md = (tmp_path / "bench" / "results.md").read_text(encoding="utf-8")
    assert "OFFLINE stand-in" in md and "meko+patterns" in md
