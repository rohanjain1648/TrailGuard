"""Detection, false-positive, token, latency and cost metrics for one run."""
from __future__ import annotations

import statistics
from typing import Any

from trailguard.config import PRICES
from trailguard.engine import RunResult
from trailguard.models import Event
from trailguard.sim import attack_instances


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return round(s[min(len(s) - 1, int(round(q * (len(s) - 1))))], 1)


def compute(events: list[Event], result: RunResult) -> dict[str, Any]:
    inst = attack_instances(events)
    victims = {steps[0].account_id for steps in inst.values()}
    by_idx = {i: e for i, e in enumerate(events)}
    early: list[int] = []
    per_ttp: dict[str, dict[str, int]] = {}
    for aid, steps in inst.items():
        ttp = steps[0].truth.ttp
        row = per_ttp.setdefault(ttp, {"attacks": 0, "prevented": 0})
        row["attacks"] += 1
        comp = next(e.truth.step for e in steps if e.truth.completes_takeover)
        idx = result.interdicted.get(aid)
        if idx is not None and (by_idx[idx].truth.step or 0) <= comp:
            early.append(comp - (by_idx[idx].truth.step or 0))
            row["prevented"] += 1
    benign = {e.account_id for e in events} - victims
    hb = {d["account"] for d in result.decisions if d["account"] in benign and d["decision"] in ("HOLD", "BLOCK")}
    su = {d["account"] for d in result.decisions if d["account"] in benign and d["decision"] == "STEP_UP"} - hb
    tin = sum(d.get("tokens_in", 0) for d in result.decisions)
    tout = sum(d.get("tokens_out", 0) for d in result.decisions)
    model = result.decider.split(":", 1)[-1]
    pin, pout = PRICES.get(model, PRICES["heuristic"])
    n_dec = len(result.decisions)
    lat = [d.get("decision_ms", 0.0) for d in result.decisions]
    return {
        "run_id": result.run_id, "mode": result.cfg["mode"], "seed": result.cfg["seed"], "epoch": result.cfg["epoch"],
        "backend": result.backend, "decider": result.decider, "partial": result.partial,
        "events": len(events), "attacks": len(inst), "prevented": len(early),
        "prevented_early": sum(1 for x in early if x > 0), "missed": len(inst) - len(early),
        "recall": round(len(early) / len(inst), 3) if inst else 0.0,
        "steps_early_mean": round(statistics.mean(early), 2) if early else 0.0,
        "steps_early_median": statistics.median(early) if early else 0,
        "benign_accounts": len(benign), "fp_hold_block": len(hb), "fp_stepup": len(su),
        "fp_rate": round(len(hb) / len(benign), 4) if benign else 0.0,
        "decisions": n_dec, "escalations": n_dec,
        "fallbacks": sum(1 for d in result.decisions if d.get("fallback")),
        "tokens_in": tin, "tokens_out": tout, "tokens_per_decision": round((tin + tout) / n_dec) if n_dec else 0,
        "tokens_estimated": any(d.get("tokens_estimated") for d in result.decisions),
        "latency_p50_ms": _pct(lat, 0.5), "latency_p95_ms": _pct(lat, 0.95),
        "meko_calls": result.meter.get("total_calls", 0), "meko_retrievals": result.meter.get("retrievals", 0),
        "meko_messages": result.meter.get("messages", 0),
        "cost_usd": round(tin / 1e6 * pin + tout / 1e6 * pout, 4),
        "per_ttp": per_ttp, "patterns_used": len(result.patterns_used), "seconds": result.seconds,
    }


AGG_KEYS = ["recall", "prevented", "prevented_early", "missed", "steps_early_mean", "fp_hold_block", "fp_stepup",
            "decisions", "tokens_in", "tokens_per_decision", "latency_p50_ms", "latency_p95_ms", "meko_calls",
            "meko_retrievals", "cost_usd", "attacks"]


def aggregate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for r in rows:
        groups.setdefault((r["epoch"], r["mode"]), []).append(r)
    out = []
    for (epoch, mode), rs in sorted(groups.items(), key=lambda kv: (kv[0][0], _MODE_ORDER.get(kv[0][1], 9))):
        agg: dict[str, Any] = {"epoch": epoch, "mode": mode, "runs": len(rs),
                               "tokens_estimated": any(r["tokens_estimated"] for r in rs),
                               "partial_runs": sum(1 for r in rs if r["partial"])}
        for k in AGG_KEYS:
            vals = [float(r[k]) for r in rs]
            agg[k] = round(statistics.mean(vals), 3)
            agg[k + "_sd"] = round(statistics.stdev(vals), 3) if len(vals) > 1 else 0.0
        out.append(agg)
    return out


_MODE_ORDER = {"isolated": 0, "stuffed": 1, "meko": 2, "meko+patterns": 3}
