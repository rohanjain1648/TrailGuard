"""Deterministic synthetic event stream with planted account takeovers."""
from __future__ import annotations

import json
import random
from datetime import timedelta
from pathlib import Path

from trailguard.models import Event
from trailguard.sim import attacks
from trailguard.sim.benign import BAITS, bait, session
from trailguard.sim.world import SPAN_DAYS, Timeline, build_customers, build_infra, epoch_start


def generate(seed: int, epoch: int = 1, n_events: int = 600) -> list[Event]:
    rng = random.Random(f"{seed}:{epoch}")
    scale = n_events / 600
    customers = build_customers(rng, epoch, max(60, n_events // 7))
    infra = build_infra(seed, epoch)
    start = epoch_start(epoch)
    tl = Timeline()

    pool = customers.copy()
    rng.shuffle(pool)
    reserved: set[str] = set()

    def take(k: int):
        out = [pool.pop() for _ in range(k)]
        reserved.update(c.account_id for c in out)
        return out

    def at(lo_days: float = 0.3, hi_days: float = SPAN_DAYS - 0.6):
        return start + timedelta(hours=rng.uniform(lo_days * 24, hi_days * 24))

    def k(base: float) -> int:
        return max(1, round(base * scale))

    # Planted attacks (assign victims first so baits never overlap them).
    cs_campaigns = [(f"A{epoch}-CS{i}", take(2)) for i in range(1, k(1) + 1)]
    swaps = [(f"A{epoch}-SS{i}", take(1)[0]) for i in range(1, k(2) + 1)]
    hijacks = [(f"A{epoch}-SH{i}", take(1)[0]) for i in range(1, k(2) + 1)]
    rings = [(f"A{epoch}-MR{i}", take(4)) for i in range(1, k(1) + 1)]
    slows = [(f"A{epoch}-LS{i}", take(1)[0]) for i in range(1, k(1) + 1)]
    baits = [(kind, take(2 if kind == "family_device" else 1)) for kind in BAITS for _ in range(k(2))]

    for camp, victims in cs_campaigns:
        bystanders = rng.sample([c for c in customers if c.account_id not in reserved], 18)
        attacks.credential_stuffing(tl, rng, victims, bystanders, infra, at(), camp)
    for camp, c in swaps:
        attacks.sim_swap(tl, rng, c, infra, at(), camp)
    for camp, c in hijacks:
        attacks.session_hijack(tl, rng, c, infra, at(), camp)
    for camp, accts in rings:
        attacks.mule_ring(tl, rng, accts, infra, at(), camp)
    for camp, c in slows:
        attacks.low_and_slow(tl, rng, c, infra, at(0.3, 3.0), camp)
    for kind, cs in baits:
        bait(tl, rng, kind, cs, at())

    # Ordinary traffic fills the stream up to the target size.
    while len(tl) < n_events:
        session(tl, rng, rng.choice(customers), at(0.0, SPAN_DAYS))

    rows = sorted(tl.rows, key=lambda r: (r["ts"], r["order"]))
    events = []
    for i, r in enumerate(rows, 1):
        r = dict(r)
        r.pop("order")
        events.append(Event(event_id=f"E{epoch}-{i:05d}", **r))
    return events


def attack_instances(events: list[Event]) -> dict[str, list[Event]]:
    out: dict[str, list[Event]] = {}
    for e in events:
        if e.truth.attack_id:
            out.setdefault(e.truth.attack_id, []).append(e)
    return out


def save_jsonl(events: list[Event], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e.to_dict()) + "\n")


def load_jsonl(path: str | Path) -> list[Event]:
    with Path(path).open(encoding="utf-8") as f:
        return [Event.from_dict(json.loads(line)) for line in f if line.strip()]
