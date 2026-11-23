from datetime import datetime, timedelta, timezone

from trailguard.engine import RunResult
from trailguard.metrics import aggregate, compute
from trailguard.models import Event, Truth

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


def ev(i, acct, attack=None, step=None, done=False):
    t = Truth(attack, "sim_swap" if attack else None, step, done)
    return Event(f"E{i}", T0 + timedelta(minutes=i), "recovery", "x", acct, "1.1.1.1", "IN", None, {}, t)


def test_metrics_on_hand_built_stream():
    events = [ev(0, "C1", "A1", 0), ev(1, "C1", "A1", 1), ev(2, "C1", "A1", 2), ev(3, "C1", "A1", 3, True),
              ev(4, "C2", "A2", 0), ev(5, "C2", "A2", 1, True),
              ev(6, "C3"), ev(7, "C4")]
    decisions = [{"account": "C1", "decision": "HOLD", "tokens_in": 100, "tokens_out": 10, "decision_ms": 5.0},
                 {"account": "C3", "decision": "HOLD", "tokens_in": 100, "tokens_out": 10, "decision_ms": 7.0},
                 {"account": "C4", "decision": "STEP_UP", "tokens_in": 100, "tokens_out": 10, "decision_ms": 9.0}]
    res = RunResult("r", {"mode": "meko", "seed": 1, "epoch": 1}, decisions, {"A1": 1}, ["A2"], False, "", {},
                    "offline-fake", "heuristic", 1.0)
    m = compute(events, res)
    assert m["attacks"] == 2 and m["prevented"] == 1 and m["missed"] == 1
    assert m["steps_early_mean"] == 2 and m["prevented_early"] == 1
    assert m["fp_hold_block"] == 1 and m["fp_stepup"] == 1 and m["benign_accounts"] == 2
    assert m["tokens_in"] == 300 and m["latency_p50_ms"] == 7.0


def test_aggregate_mean_sd():
    rows = [{"epoch": 1, "mode": "meko", "tokens_estimated": True, "partial": False,
             **{k: v for k, v in zip(["recall", "prevented", "prevented_early", "missed", "steps_early_mean",
                                      "fp_hold_block", "fp_stepup", "decisions", "tokens_in", "tokens_per_decision",
                                      "latency_p50_ms", "latency_p95_ms", "meko_calls", "meko_retrievals",
                                      "cost_usd", "attacks"], [x] * 16)}} for x in (1, 3)]
    a = aggregate(rows)[0]
    assert a["recall"] == 2 and a["recall_sd"] > 1.4 and a["runs"] == 2
