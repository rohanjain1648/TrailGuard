"""The Curator: turns confirmed attacks into attacker patterns, an analyst approves them.

Confirmation stands in for what confirms fraud in real life (disputes, chargebacks,
customer reports): after a run the ground-truth labels say which accounts were attacked.
For each TTP the Curator writes one ``TG-PATTERN`` memory to the patterns datapack: the
observed signal sequence, the attacker's indicators (proxy /24 subnets, device
fingerprints, mule payees), the earliest useful signal and the recommended action.

Those memories are Meko *learnings*: candidates nobody else's agents trust yet. Only after
an analyst approves them (``memory_promote``) do they enter collective memory, where the
channel agents load them in ``meko+patterns`` mode.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict

from trailguard.agents.detectors import for_channel
from trailguard.config import SIGNAL_WEIGHTS
from trailguard.engine import RunResult
from trailguard.memlines import format_pattern, parse_pattern
from trailguard.meko.scope import AgentScope
from trailguard.models import Event, Pattern
from trailguard.sim import attack_instances

ACTIONS = {
    "credential_stuffing": "STEP_UP the new-device login after failed logins; BLOCK payees and transfers on matching "
                           "infrastructure",
    "sim_swap": "HOLD the phone change when support contact came from an unfamiliar network; never trust SMS step-up "
                "for 72 h after a phone change",
    "session_hijack": "BLOCK sessions after impossible travel; HOLD email and password changes that follow",
    "mule_ring": "BLOCK any account on the ring device or adding the mule payee",
    "low_and_slow": "HOLD the MFA device change when an abandoned reset and failed logins came first",
}


BENIGN_MAX_RATE = 0.01  # a signal genuine customers show this often is not an attacker signature


def _signal_sequences(events: list[Event]) -> tuple[dict[str, list[str]], dict[str, float]]:
    """Full-strength signals per attack instance (in order), and how common each signal type is
    among genuine customers. Confirmed fraud labels make 'everyone else' the genuine baseline."""
    dets = {ch: for_channel(ch) for ch in ("login", "device", "recovery", "payments")}
    seq: dict[str, list[str]] = defaultdict(list)
    victims = {e.account_id for e in events if e.truth.attack_id}
    benign_types: dict[str, set[str]] = defaultdict(set)
    for e in events:
        for s in dets[e.channel].observe(e, "curation"):
            if s.weight < SIGNAL_WEIGHTS.get(s.type, 0):
                continue  # a softened signal (known device / network) is not distinctive
            if e.truth.attack_id:
                if s.type not in seq[e.truth.attack_id]:
                    seq[e.truth.attack_id].append(s.type)
            elif e.account_id not in victims:
                benign_types[s.type].add(e.account_id)
    n_benign = max(1, len({e.account_id for e in events} - victims))
    rates = {t: len(a) / n_benign for t, a in benign_types.items()}
    return seq, rates


def build_patterns(events: list[Event], epoch: int) -> list[Pattern]:
    inst = attack_instances(events)
    seqs, benign_rate = _signal_sequences(events)
    by_ttp: dict[str, list[str]] = defaultdict(list)
    for aid, steps in inst.items():
        by_ttp[steps[0].truth.ttp].append(aid)
    out = []
    for ttp, aids in sorted(by_ttp.items()):
        subnets, devices, payees = set(), set(), set()
        for aid in aids:
            for e in inst[aid]:
                if e.ip:
                    subnets.add(e.ip.rsplit(".", 1)[0])
                if e.device_id and e.type in ("device_seen", "login_success"):
                    devices.add(e.device_id)
                if e.attrs.get("payee_id"):
                    payees.add(e.attrs["payee_id"])
        iocs = {"ip_subnet": sorted(subnets), "device": sorted(devices), "payee": sorted(payees)}
        longest = max((seqs[a] for a in aids), key=len, default=[])
        seq = [t for t in longest if benign_rate.get(t, 0.0) <= BENIGN_MAX_RATE]
        digest = hashlib.sha1(repr(sorted(iocs.items())).encode()).hexdigest()[:6]
        out.append(Pattern(pattern_id=f"PAT-{ttp}-e{epoch}-{digest}", ttp=ttp, sequence=seq, iocs=iocs,
                           earliest_signal=seq[0] if seq else "", action=ACTIONS.get(ttp, "HOLD for review"),
                           epoch=epoch, source_cases=sorted(aids)[:6]))
    return out


class Curator:
    agent = "curator"

    def __init__(self, scope: AgentScope) -> None:
        self.scope = scope

    async def learn(self, events: list[Event], result: RunResult | None, epoch: int) -> list[Pattern]:
        patterns = build_patterns(events, epoch)
        caught = set(result.interdicted) if result else set()
        for p in patterns:
            stopped = sum(1 for c in p.source_cases if c in caught)
            p.memory_id = await self.scope.add_memory(
                "patterns", format_pattern(p),
                {"kind": "pattern", "ttp": p.ttp, "epoch": epoch, "cases": len(p.source_cases),
                 "stopped_in_run": stopped, "source_run": result.run_id if result else None})
        return patterns

    async def pending(self) -> list[dict]:
        """Candidate patterns waiting for an analyst (Meko learnings)."""
        dp = self.scope.datapacks["patterns"]
        out = []
        for m in await self.scope.meko.list_learnings(dp):
            p = parse_pattern(m.get("memory", ""))
            if p:
                p.memory_id = m["id"]
                out.append({"memory_id": m["id"], "pattern": p.to_dict(), "text": m.get("memory", "")})
        return out

    async def approve(self, memory_ids: list[str] | str = "all") -> dict:
        if memory_ids == "all":
            memory_ids = [x["memory_id"] for x in await self.pending()]
        if not memory_ids:
            return {"inserted_ids": [], "updated_ids": [], "not_found_ids": []}
        return await self.scope.promote("patterns", list(memory_ids))

    async def reject(self, memory_ids: list[str]) -> dict:
        return await self.scope.meko.keep_private(self.scope.datapacks["patterns"], memory_ids)
