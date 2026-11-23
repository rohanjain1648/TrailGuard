"""trailguard: command line for TrailGuard.

  trailguard doctor                       check keys, Meko connection, datapacks
  trailguard setup                        create datapacks, upload playbooks to the knowledge base
  trailguard run --mode meko              replay a stream through the agents
  trailguard learn --run RUN [--approve]  distil confirmed attacks into patterns (Meko learnings)
  trailguard pending | approve            review learnings; approve = memory_promote
  trailguard bench                        isolated vs stuffed vs meko vs meko+patterns
  trailguard explain --run RUN -n 3       plain-English card for one decision
  trailguard audit --run RUN              audit report (also stored as a Meko artifact)
  trailguard reset --signals              delete this tool's signal memories in Meko
  trailguard serve                        dashboard on http://127.0.0.1:8000
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from trailguard.config import CHANNEL_AGENTS, MODES, SENTINEL, Settings


def _settings(a: argparse.Namespace) -> Settings:
    s = Settings.load()
    if a.meko:
        s = replace(s, meko_backend=a.meko)
    if a.llm:
        s = replace(s, llm=a.llm)
    if a.model:
        s = replace(s, model=a.model)
    if a.effort:
        s = replace(s, effort=a.effort)
    return s


def _seeds(text: str) -> list[int]:
    out: list[int] = []
    for part in text.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            out += list(range(int(lo), int(hi) + 1))
        elif part:
            out.append(int(part))
    return out


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


async def cmd_doctor(a, s: Settings) -> int:
    from trailguard.engine import Runtime

    print(f"Meko backend : {s.meko_backend}  (MEKO_API_KEY {'set' if s.meko_api_key else 'not set'})")
    print(f"Decider      : {s.decider_label}  (ANTHROPIC_API_KEY {'set' if s.anthropic_api_key else 'not set'})")
    if s.meko_backend == "fake":
        print("  note: offline stand-in. Set MEKO_API_KEY in .env to use Meko Cloud.")
    rt = await Runtime.create(s)
    try:
        if s.meko_backend == "cloud":
            print(f"MCP tools    : {len(rt.meko.tools)} ({', '.join(sorted(rt.meko.tools)[:6])}, ...)")
        for k, dp in rt.datapacks.items():
            d = await rt.meko.describe(dp)
            print(f"datapack {k:9}: {dp}  memories={d.get('memory_count')} learnings={d.get('learnings_count')} "
                  f"collective={d.get('collective_memory_count')} knowledge_chunks={d.get('knowledge_count')}")
    finally:
        await rt.close()
    return 0


async def cmd_setup(a, s: Settings) -> int:
    from trailguard.bootstrap import ensure
    from trailguard.engine import Runtime

    rt = await Runtime.create(s)
    try:
        print(f"Datapacks on {rt.backend}: {rt.datapacks}")
        await ensure(rt)
    finally:
        await rt.close()
    return 0


async def cmd_generate(a, s: Settings) -> int:
    from trailguard.sim import attack_instances, generate, save_jsonl

    ev = generate(a.seed, a.epoch, a.events)
    out = Path(a.out or f"data/generated/stream-s{a.seed}-e{a.epoch}-{a.events}.jsonl")
    save_jsonl(ev, out)
    print(f"{len(ev)} events, {len(attack_instances(ev))} planted takeover attempts -> {out}")
    return 0


async def cmd_run(a, s: Settings) -> int:
    from trailguard.engine import RunConfig, Runtime, SimulatedCrash, run
    from trailguard.metrics import compute
    from trailguard.report import audit_markdown
    from trailguard.sim import generate

    run_id = a.resume or a.run_id or f"{a.mode.replace('+', '-')}-s{a.seed}-e{a.epoch}-" \
                                     f"{datetime.now(timezone.utc).strftime('%H%M%S')}"
    cfg = RunConfig(run_id, a.mode, a.seed, a.epoch, a.events, pace=a.pace, crash_at=a.crash_at,
                    resume=bool(a.resume), reset_signals=not a.keep_signals, max_retrievals=a.max_retrievals,
                    max_messages=a.max_messages)
    if a.resume:
        prev = s.runs_dir / run_id / "result.json"
        ck = s.runs_dir / run_id / "checkpoint.json"
        src = ck if ck.exists() else prev
        if src.exists():
            c = json.loads(src.read_text(encoding="utf-8")).get("cfg")
            if c:
                cfg = replace(cfg, seed=c["seed"], epoch=c["epoch"], n_events=c["n_events"], mode=c["mode"])
    events = generate(cfg.seed, cfg.epoch, cfg.n_events)
    rt = await Runtime.create(s, need_meko=cfg.mode in ("meko", "meko+patterns"))

    def progress(kind, p):
        if kind == "decision":
            print(f"  #{p['n']:>3} {p['ts'][5:16]} {p['account']} {p['gate']:<24} risk {p['risk']:>3} -> "
                  f"{p['decision']:<7} ({p['outcome']})")
        elif kind == "takeover_completed":
            print(f"  !!  takeover completed: {p['attack_id']} ({p['ttp']})")

    try:
        res = await run(events, cfg, rt, emit=None if a.quiet else progress)
    except SimulatedCrash as e:
        print(f"\n{e}. Checkpoint saved to Meko. Resume with:\n  trailguard run --resume {run_id}")
        await rt.close()
        return 3
    await rt.close()
    m = compute(events, res)
    (s.runs_dir / run_id / "audit.md").write_text(audit_markdown(s.runs_dir / run_id), encoding="utf-8")
    print(f"\nrun {run_id} [{res.backend} / {res.decider}]{' PARTIAL: ' + res.partial_reason if res.partial else ''}")
    print(f"  stopped before takeover {m['prevented']}/{m['attacks']}  ({m['prevented_early']} early, "
          f"{m['steps_early_mean']} steps on average)  missed {m['missed']}")
    print(f"  genuine customers held/blocked {m['fp_hold_block']}, stepped up {m['fp_stepup']}  "
          f"decisions {m['decisions']}  tokens {m['tokens_in'] + m['tokens_out']:,}"
          f"{' (estimated)' if m['tokens_estimated'] else ''}  Meko calls {m['meko_calls']}")
    print(f"  trace: {s.runs_dir / run_id}  (audit.md, decisions.jsonl, trace.jsonl)")
    return 0


def _load_run(s: Settings, run_id: str):
    from trailguard.engine import RunResult
    from trailguard.sim import generate

    data = json.loads((s.runs_dir / run_id / "result.json").read_text(encoding="utf-8"))
    res = RunResult(**data)
    c = res.cfg
    return res, generate(c["seed"], c["epoch"], c["n_events"])


async def cmd_learn(a, s: Settings) -> int:
    from trailguard.agents.curator import Curator
    from trailguard.engine import Runtime, scope_for

    res, events = _load_run(s, a.run)
    rt = await Runtime.create(s)
    try:
        cur = Curator(scope_for(rt, "curator", a.run))
        pats = await cur.learn(events, res, res.cfg["epoch"])
        for p in pats:
            print(f"  learning {p.memory_id}  {p.pattern_id}: {' > '.join(p.sequence[:4])}  "
                  f"indicators {sum(len(v) for v in p.iocs.values())}")
        if a.approve:
            out = await cur.approve([p.memory_id for p in pats])
            print(f"promoted to collective memory: {len(out.get('inserted_ids', []))}")
        else:
            print("Review with `trailguard pending`, approve with `trailguard approve --all` or in the dashboard.")
    finally:
        await rt.close()
    return 0


async def cmd_pending(a, s: Settings) -> int:
    from trailguard.agents.curator import Curator
    from trailguard.engine import Runtime, scope_for

    rt = await Runtime.create(s)
    try:
        for x in await Curator(scope_for(rt, "curator", "review")).pending():
            p = x["pattern"]
            print(f"  {x['memory_id']}  {p['pattern_id']}  {p['ttp']}: {' > '.join(p['sequence'][:4])}")
    finally:
        await rt.close()
    return 0


async def cmd_approve(a, s: Settings) -> int:
    from trailguard.agents.curator import Curator
    from trailguard.engine import Runtime, scope_for

    rt = await Runtime.create(s)
    try:
        cur = Curator(scope_for(rt, "curator", "review"))
        out = await (cur.approve("all") if a.all else cur.approve(a.ids))
        _print(out)
    finally:
        await rt.close()
    return 0


async def cmd_bench(a, s: Settings) -> int:
    from trailguard.bench import run_bench
    from trailguard.meko.fake import FakeMeko

    factory = (lambda seed: FakeMeko(None)) if s.meko_backend == "fake" else None
    if s.meko_backend == "cloud":
        print("Benchmark against Meko Cloud: retrieval and message budgets per run are enforced "
              f"({a.max_retrievals} / {a.max_messages}).")
    b = await run_bench(s, _seeds(a.seeds), a.events, tuple(a.modes.split(",")) if a.modes else None,
                        meko_factory=factory, max_retrievals=a.max_retrievals, max_messages=a.max_messages,
                        progress=lambda m: print("  " + m))
    print((Path(b["out_dir"]) / "results.md").read_text(encoding="utf-8"))
    return 0


async def cmd_explain(a, s: Settings) -> int:
    from trailguard.explain import card, card_markdown
    from trailguard.trace import read

    for rec in read(s.runs_dir / a.run, "decisions.jsonl"):
        if rec["n"] == a.n:
            print(card_markdown(card(rec)))
            return 0
    print(f"decision {a.n} not found in {a.run}")
    return 1


async def cmd_audit(a, s: Settings) -> int:
    from trailguard.engine import Runtime, scope_for
    from trailguard.memlines import format_artifact
    from trailguard.report import audit_markdown

    md = audit_markdown(s.runs_dir / a.run)
    out = s.runs_dir / a.run / "audit.md"
    out.write_text(md, encoding="utf-8")
    print(f"audit report: {out}")
    if not a.local:
        rt = await Runtime.create(s)
        try:
            sc = scope_for(rt, SENTINEL, a.run)
            h = await sc.put_artifact("signals", f"audit-{a.run}.md", md.encode(), "text/markdown")
            await sc.add_memory("signals", format_artifact("audit report", a.run, h), {"kind": "artifact"})
            print(f"stored in Meko as artifact {h} ({rt.backend})")
        finally:
            await rt.close()
    return 0


async def cmd_reset(a, s: Settings) -> int:
    from trailguard.engine import Runtime, scope_for

    rt = await Runtime.create(s)
    try:
        for agent in [*CHANNEL_AGENTS.values(), SENTINEL]:
            await scope_for(rt, agent, "reset").delete_own_memories("signals")
        print(f"deleted signal memories written by TrailGuard agents in trailguard-signals ({rt.backend}); "
              "patterns and playbooks are untouched")
    finally:
        await rt.close()
    return 0


async def cmd_serve(a, s: Settings) -> int:
    import uvicorn

    from trailguard.web.app import create_app

    config = uvicorn.Config(create_app(s), host=a.host, port=a.port, log_level="warning")
    print(f"TrailGuard dashboard: http://{a.host}:{a.port}  [{s.meko_backend} / {s.decider_label}]")
    await uvicorn.Server(config).serve()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="trailguard", description="Agents that remember the attacker (Meko).")
    p.add_argument("--meko", choices=["cloud", "fake"], help="context layer (default: cloud if MEKO_API_KEY set)")
    p.add_argument("--llm", choices=["claude", "heuristic"], help="decider (default: claude if ANTHROPIC_API_KEY)")
    p.add_argument("--model", help="Claude model id (default claude-opus-5-5)")
    p.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor")
    sub.add_parser("setup")
    g = sub.add_parser("generate")
    g.add_argument("--seed", type=int, default=1)
    g.add_argument("--epoch", type=int, default=1)
    g.add_argument("--events", type=int, default=600)
    g.add_argument("--out")
    r = sub.add_parser("run")
    r.add_argument("--mode", choices=MODES, default="meko")
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--epoch", type=int, default=1)
    r.add_argument("--events", type=int, default=600)
    r.add_argument("--pace", type=float, default=0.0, help="events per second (0 = as fast as possible)")
    r.add_argument("--run-id")
    r.add_argument("--crash-at", type=int, help="simulate a failure at this event index")
    r.add_argument("--resume", metavar="RUN_ID", help="resume a run from its Meko checkpoint")
    r.add_argument("--keep-signals", action="store_true", help="don't clear earlier signal memories first")
    r.add_argument("--max-retrievals", type=int, default=400)
    r.add_argument("--max-messages", type=int, default=120)
    r.add_argument("--quiet", action="store_true")
    le = sub.add_parser("learn")
    le.add_argument("--run", required=True)
    le.add_argument("--approve", action="store_true")
    sub.add_parser("pending")
    ap = sub.add_parser("approve")
    ap.add_argument("ids", nargs="*")
    ap.add_argument("--all", action="store_true")
    b = sub.add_parser("bench")
    b.add_argument("--seeds", default="1-3")
    b.add_argument("--events", type=int, default=2000)
    b.add_argument("--modes", help="comma-separated subset")
    b.add_argument("--max-retrievals", type=int, default=2000)
    b.add_argument("--max-messages", type=int, default=400)
    e = sub.add_parser("explain")
    e.add_argument("--run", required=True)
    e.add_argument("-n", type=int, default=1)
    au = sub.add_parser("audit")
    au.add_argument("--run", required=True)
    au.add_argument("--local", action="store_true", help="don't store the report in Meko")
    rs = sub.add_parser("reset")
    rs.add_argument("--signals", action="store_true", required=True)
    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    return p


COMMANDS = {"doctor": cmd_doctor, "setup": cmd_setup, "generate": cmd_generate, "run": cmd_run, "learn": cmd_learn,
            "pending": cmd_pending, "approve": cmd_approve, "bench": cmd_bench, "explain": cmd_explain,
            "audit": cmd_audit, "reset": cmd_reset, "serve": cmd_serve}


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    a = build_parser().parse_args(argv)
    s = _settings(a)
    return asyncio.run(COMMANDS[a.cmd](a, s))


if __name__ == "__main__":
    raise SystemExit(main())
