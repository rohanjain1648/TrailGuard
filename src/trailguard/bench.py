"""Benchmark: the same agents on the same streams, changing only the context layer.

Per seed:
  epoch 1: isolated, stuffed, meko         (no learned patterns yet)
  learn:   the Curator turns epoch 1's confirmed attacks into patterns; approved (promoted)
  epoch 2: isolated, stuffed, meko, meko+patterns   (new victims, partly reused attacker infra)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from trailguard.agents.curator import Curator
from trailguard.config import Settings
from trailguard.engine import RunConfig, Runtime, run, scope_for
from trailguard.meko.base import Meko
from trailguard.metrics import aggregate, compute
from trailguard.sim import generate

EPOCH1_MODES = ("isolated", "stuffed", "meko")
EPOCH2_MODES = ("isolated", "stuffed", "meko", "meko+patterns")


async def run_bench(settings: Settings, seeds: list[int], n_events: int = 2000, modes: tuple[str, ...] | None = None,
                    meko_factory: Callable[[int], Meko] | None = None, out_dir: Path | None = None,
                    max_retrievals: int = 2000, max_messages: int = 400,
                    progress: Callable[[str], None] | None = None) -> dict[str, Any]:
    """meko_factory(seed) gives a fresh backend per seed (the offline bench uses a fresh stand-in
    so seeds are independent). With Meko Cloud, one connection is reused and patterns accumulate."""
    say = progress or (lambda _m: None)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out = Path(out_dir or settings.runs_dir / f"bench-{stamp}")
    out.mkdir(parents=True, exist_ok=True)
    s = Settings(**{**settings.__dict__, "runs_dir": out})
    rows: list[dict[str, Any]] = []
    shared_rt: Runtime | None = None
    learned: list[dict[str, Any]] = []
    try:
        for seed in seeds:
            if meko_factory is not None:
                rt = await Runtime.create(s, meko=meko_factory(seed))
            else:
                shared_rt = shared_rt or await Runtime.create(s)
                rt = shared_rt
            for epoch, epoch_modes in ((1, EPOCH1_MODES), (2, EPOCH2_MODES)):
                events = generate(seed, epoch, n_events)
                for mode in epoch_modes:
                    if modes and mode not in modes:
                        continue
                    run_id = f"s{seed}-e{epoch}-{mode.replace('+', '-')}"
                    say(f"seed {seed} epoch {epoch} {mode}")
                    res = await run(events, RunConfig(run_id, mode, seed, epoch, n_events, max_retrievals=max_retrievals,
                                                      max_messages=max_messages), rt)
                    rows.append(compute(events, res))
                    if epoch == 1 and mode == "meko":
                        cur = Curator(scope_for(rt, "curator", run_id))
                        pats = await cur.learn(events, res, epoch)
                        approved = await cur.approve([p.memory_id for p in pats])
                        learned.append({"seed": seed, "patterns": [p.pattern_id for p in pats],
                                        "promoted": len(approved.get("inserted_ids", []))})
            if meko_factory is not None:
                await rt.close()
    finally:
        if shared_rt:
            await shared_rt.close()
    summary = {"created": stamp, "seeds": seeds, "n_events": n_events, "rows": rows, "aggregate": aggregate(rows),
               "learned": learned, "backend": next((r["backend"] for r in rows if r["backend"] != "none"), "none"),
               "decider": rows[0]["decider"] if rows else "?"}
    (out / "results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    from trailguard.report import results_markdown

    (out / "results.md").write_text(results_markdown(summary), encoding="utf-8")
    summary["out_dir"] = str(out)
    return summary
