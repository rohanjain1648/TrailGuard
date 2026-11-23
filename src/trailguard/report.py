"""Audit report for one run and results table for a benchmark, generated from trace data."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from trailguard.engine import RunResult
from trailguard.explain import card, card_markdown
from trailguard.metrics import compute
from trailguard.sim import generate
from trailguard.trace import read

BACKEND_LABEL = {"meko-cloud": "Meko Cloud", "offline-fake": "OFFLINE stand-in (not Meko)", "none": "no context layer"}


def _load(run_dir: Path) -> tuple[RunResult, list[dict[str, Any]]]:
    data = json.loads((Path(run_dir) / "result.json").read_text(encoding="utf-8"))
    return RunResult(**data), read(run_dir, "decisions.jsonl") or data["decisions"]


def pick_walkthroughs(decisions: list[dict[str, Any]], k: int = 3) -> list[dict[str, Any]]:
    """One stopped attack, one step-up, one allow (when present), then the highest-risk rest."""
    chosen: list[dict[str, Any]] = []
    tests = [lambda d: d["decision"] in ("BLOCK", "HOLD") and d["truth"].get("attack_id"),
             lambda d: d["decision"] == "STEP_UP",
             lambda d: d["decision"] == "ALLOW",
             lambda d: d.get("patterns")]
    for t in tests:
        hit = next((d for d in decisions if t(d) and d not in chosen), None)
        if hit:
            chosen.append(hit)
    for d in sorted(decisions, key=lambda x: -x["risk"]):
        if len(chosen) >= k:
            break
        if d not in chosen:
            chosen.append(d)
    return sorted(chosen, key=lambda d: d["n"])


def audit_markdown(run_dir: Path) -> str:
    res, decisions = _load(run_dir)
    cfg = res.cfg
    events = generate(cfg["seed"], cfg["epoch"], cfg["n_events"])
    m = compute(events, res)
    lines = [
        f"# Audit report: run `{res.run_id}`", "",
        f"- Context layer: **{BACKEND_LABEL.get(res.backend, res.backend)}**",
        f"- Decider: **{res.decider}**", f"- Mode: `{cfg['mode']}` · seed {cfg['seed']} · epoch {cfg['epoch']} · "
                                          f"{len(events)} events",
        f"- Run status: {'PARTIAL (' + res.partial_reason + ')' if res.partial else 'complete'} · {res.seconds}s",
    ]
    if res.patterns_used:
        lines.append(f"- Confirmed patterns loaded from collective memory: {', '.join(res.patterns_used)}")
    lines += ["", "## Outcome", "", "| Metric | Value |", "|---|---|",
              f"| Planted takeover attempts | {m['attacks']} |",
              f"| Stopped before takeover completed | {m['prevented']} ({m['recall']:.0%}) |",
              f"| Stopped at least one step early | {m['prevented_early']} |",
              f"| Average steps before completion | {m['steps_early_mean']} |",
              f"| Genuine customers held or blocked | {m['fp_hold_block']} of {m['benign_accounts']} |",
              f"| Genuine customers asked for extra verification | {m['fp_stepup']} |",
              f"| Decisions | {m['decisions']} |",
              f"| Model tokens{' (estimated)' if m['tokens_estimated'] else ''} | {m['tokens_in'] + m['tokens_out']:,} |",
              f"| Meko calls (retrievals) | {m['meko_calls']} ({m['meko_retrievals']}) |", ""]
    lines += ["## Every decision", "",
              "| # | Time | Account | Action requested | Risk | Decision | Agents | Outcome |", "|---|---|---|---|---|---|---|---|"]
    for d in decisions:
        agents = ", ".join(sorted({s["agent"].replace("-agent", "") for s in d["signals"]}))
        lines.append(f"| {d['n']} | {d['ts'][5:16].replace('T', ' ')} | {d['account']} | {d['gate'].replace('_', ' ')} "
                     f"| {d['risk']} | **{d['decision']}** | {agents} | {d['outcome'].replace('_', ' ')} |")
    if len(decisions) < 10:
        lines += ["", f"_Only {len(decisions)} decisions in this run; run more events for the 10+ decision audit._"]
    lines += ["", "## Walkthroughs", "",
              "Each walkthrough is generated from the decision trace and is meant to be read in under two minutes.", ""]
    for d in pick_walkthroughs(decisions):
        lines += [card_markdown(card(d)), ""]
    lines += ["## Meko references", "",
              "Every decision is a turn in a case conversation in the `trailguard-signals` datapack. Open "
              "**Datapack > Conversations** in the Meko portal and expand **Decision trace**, or **Observe** for "
              "the full Langfuse trace with MCP spans and token usage.", "",
              "| # | Conversation | Message | Signal memories cited |", "|---|---|---|---|"]
    for d in decisions:
        mk = d.get("meko") or {}
        if mk.get("message_id"):
            mem = ", ".join(f"`{s['memory_id'][:8]}`" for s in d["signals"] if s.get("memory_id"))
            lines.append(f"| {d['n']} | `{mk['conversation_id']}` | `{mk['message_id']}` | {mem} |")
    return "\n".join(lines) + "\n"


def _get(agg: list[dict[str, Any]], epoch: int, mode: str) -> dict[str, Any] | None:
    return next((a for a in agg if a["epoch"] == epoch and a["mode"] == mode), None)


def headlines(bench: dict[str, Any]) -> list[str]:
    agg = bench["aggregate"]
    out = []
    iso, mk, st = _get(agg, 1, "isolated"), _get(agg, 1, "meko"), _get(agg, 1, "stuffed")
    if iso and mk:
        out.append(f"Shared memory through Meko stopped {mk['recall']:.0%} of takeovers before completion vs "
                   f"{iso['recall']:.0%} for the same agents in isolation, on average "
                   f"{mk['steps_early_mean']:.2f} vs {iso['steps_early_mean']:.2f} steps earlier "
                   f"(genuine customers held/blocked: {mk['fp_hold_block']:.1f} vs {iso['fp_hold_block']:.1f} per run).")
    if st and mk and st["tokens_per_decision"]:
        cut = 1 - mk["tokens_per_decision"] / st["tokens_per_decision"]
        out.append(f"Retrieving only the relevant slice used {cut:.0%} fewer tokens per decision than passing every "
                   f"agent's signals around ({mk['tokens_per_decision']:,.0f} vs {st['tokens_per_decision']:,.0f}), "
                   f"with recall {mk['recall']:.0%} vs {st['recall']:.0%}.")
    m2, mp = _get(agg, 2, "meko"), _get(agg, 2, "meko+patterns")
    if m2 and mp:
        out.append(f"Learning loop: on new victims, analyst-approved patterns from epoch 1 moved detection from "
                   f"{m2['steps_early_mean']:.2f} to {mp['steps_early_mean']:.2f} steps before completion "
                   f"(recall {m2['recall']:.0%} to {mp['recall']:.0%}; genuine customers held/blocked "
                   f"{m2['fp_hold_block']:.1f} to {mp['fp_hold_block']:.1f}).")
    return out


def results_markdown(bench: dict[str, Any]) -> str:
    est = any(a["tokens_estimated"] for a in bench["aggregate"])
    lines = [f"# TrailGuard benchmark ({bench['created']})", "",
             f"- Context layer for Meko modes: **{BACKEND_LABEL.get(bench['backend'], bench['backend'])}**",
             f"- Decider: **{bench['decider']}**" + (" (tokens are estimated from prompt size)" if est else ""),
             f"- Seeds: {bench['seeds']} · {bench['n_events']} events per stream · mean ± sd across seeds", ""]
    lines += [f"- {h}" for h in headlines(bench)]
    lines += ["", "| Epoch | Mode | Recall | Stopped early | Steps early | Genuine held/blocked | Genuine stepped up "
                  "| Decisions | Tokens/decision | Total input tokens | p50 ms | Meko retrievals | Cost $ |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for a in bench["aggregate"]:
        lines.append(
            f"| {a['epoch']} | `{a['mode']}` | {a['recall']:.0%} ± {a['recall_sd']:.0%} | {a['prevented_early']:.1f} "
            f"| {a['steps_early_mean']:.2f} ± {a['steps_early_mean_sd']:.2f} | {a['fp_hold_block']:.1f} "
            f"| {a['fp_stepup']:.1f} | {a['decisions']:.0f} | {a['tokens_per_decision']:,.0f} | {a['tokens_in']:,.0f} "
            f"| {a['latency_p50_ms']:.0f} | {a['meko_retrievals']:.0f} | {a['cost_usd']:.3f} |")
    lines += ["", "Definitions are in docs/METHODOLOGY.md. Per-run rows are in results.json."]
    return "\n".join(lines) + "\n"
