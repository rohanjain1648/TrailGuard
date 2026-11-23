"""Building and scoring a case at a gate.

A *gate* is a risky action (new-device login, credential change, payee add, card test,
transfer) that produced at least one local signal. At a gate the agent gathers related
signals (the ones it is allowed to see in the current mode) and scores them.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from trailguard.config import INFRA_SIGNALS, LINKED_CASE_SOURCES, SIGNAL_WEIGHTS
from trailguard.models import Event, Pattern, Signal

GATE_TYPES = {"login_success", "phone_change", "email_change", "password_reset_complete", "mfa_device_added",
              "payee_add", "card_test", "transfer"}
MONEY_GATES = {"payee_add", "card_test", "transfer"}
CREDENTIAL_GATES = {"phone_change", "email_change", "password_reset_complete", "mfa_device_added"}
DEVICE_SPECIFIC = {"new_device", "emulator", "device_multi_account", "new_device_login"}
WINDOW = timedelta(hours=72)
DECAY_AFTER = timedelta(hours=24)


@dataclass
class Case:
    gate: Event
    signals: list[Signal]
    risk: int
    patterns: list[tuple[Pattern, str]] = field(default_factory=list)
    playbook: list[dict] = field(default_factory=list)  # [{id, text, score}]
    query: str = ""
    retrieved: int = 0

    @property
    def agents(self) -> list[str]:
        return sorted({s.agent for s in self.signals})


def gate_payee(e: Event) -> str | None:
    return e.attrs.get("payee_id")


def is_gate(e: Event, local_signals: list[Signal]) -> bool:
    return e.type in GATE_TYPES and bool(local_signals)


def _shares_entity(s: Signal, g: Event) -> str | None:
    if g.device_id and s.device_id == g.device_id:
        return f"device:{g.device_id}"
    if s.ip and s.ip == g.ip:
        return f"ip:{g.ip}"
    p = gate_payee(g)
    if p and s.payee_id == p:
        return f"payee:{p}"
    return None


def case_signals(candidates: list[Signal], g: Event) -> list[Signal]:
    """Signals that count toward this gate's case, de-duplicated by (type, entity)."""
    best: dict[tuple[str, str], Signal] = {}
    for s in candidates:
        if s.ts > g.ts or g.ts - s.ts > WINDOW:
            continue
        if s.account_id == g.account_id:
            if s.type in DEVICE_SPECIFIC and g.device_id and s.device_id and s.device_id != g.device_id:
                continue  # about another device on this account, not the one in front of us
            c, key = s, s.entity_key
        else:
            ent = _shares_entity(s, g)
            if ent is None:
                continue
            if s.type in INFRA_SIGNALS:
                c, key = s, s.entity_key
            elif s.type in LINKED_CASE_SOURCES:
                c = dataclasses.replace(s, type="linked_case", weight=SIGNAL_WEIGHTS["linked_case"],
                                        note=f"{ent} was in a blocked/failed case on {s.account_id}")
                key = ("linked_case", ent)
            else:
                continue
        prev = best.get(key)
        if prev is None or c.weight > prev.weight or (c.weight == prev.weight and c.ts > prev.ts):
            best[key] = c
    return sorted(best.values(), key=lambda x: x.ts)


def score(signals: list[Signal], now: datetime) -> int:
    best: dict[tuple[str, str], float] = {}
    for s in signals:
        w = s.weight / 2 if now - s.ts > DECAY_AFTER else s.weight
        k = s.entity_key
        best[k] = max(best.get(k, 0.0), w)
    return int(min(100, round(sum(best.values()))))


def _subsequence(needle: list[str], hay: list[str]) -> bool:
    it = iter(hay)
    return all(any(x == y for y in it) for x in needle)


def pattern_bonus(patterns: list[Pattern], g: Event, signals: list[Signal]) -> list[Signal]:
    """Signals contributed by confirmed attacker patterns (meko+patterns mode)."""
    devices = {s.device_id for s in signals if s.device_id and s.account_id == g.account_id} | {g.device_id}
    ips = {s.ip for s in signals if s.ip and s.account_id == g.account_id} | {g.ip}
    payees = {s.payee_id for s in signals if s.payee_id} | {gate_payee(g)}
    prefixes = {ip.rsplit(".", 1)[0] for ip in ips if ip}
    seq = [s.type for s in signals if s.account_id == g.account_id and s.weight >= SIGNAL_WEIGHTS.get(s.type, 0)]
    out: list[Signal] = []
    ioc_hit = ttp_hit = None
    for p in patterns:
        if ioc_hit is None:
            hit = (devices & set(p.iocs.get("device", [])) or payees & set(p.iocs.get("payee", []))
                   or prefixes & set(p.iocs.get("ip_subnet", [])))
            if hit:
                ioc_hit = (p, sorted(x for x in hit if x)[0])
        if ttp_hit is None and len(p.sequence) >= 2 and _subsequence(p.sequence[:2], seq):
            ttp_hit = p
    if ioc_hit:
        p, ioc = ioc_hit
        out.append(Signal("known_attacker_ioc", "high", SIGNAL_WEIGHTS["known_attacker_ioc"], g.account_id,
                          "patterns", g.ts, g.event_id, "", g.device_id, g.ip, gate_payee(g),
                          note=f"{ioc} is an indicator in confirmed pattern {p.pattern_id}", memory_id=p.memory_id))
    if ttp_hit:
        out.append(Signal("ttp_match", "high", SIGNAL_WEIGHTS["ttp_match"], g.account_id, "patterns", g.ts,
                          g.event_id, "", g.device_id, g.ip, gate_payee(g),
                          note=f"sequence matches the start of {ttp_hit.ttp} pattern {ttp_hit.pattern_id}",
                          memory_id=ttp_hit.memory_id))
    return out
