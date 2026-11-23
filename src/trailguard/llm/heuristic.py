"""Deterministic decider implementing knowledge/step-up-policy.md exactly.

Used offline (no Anthropic key) and as the fallback when Claude's reply can't be used.
"""
from __future__ import annotations

from datetime import timedelta

from trailguard.agents.case import CREDENTIAL_GATES, Case
from trailguard.models import Decision, Signal

SECOND_FACTOR = {"phone_change", "mfa_change"}
WINDOW_2FA = timedelta(hours=72)

POLICY_1 = "Step-up policy §1 (risk thresholds)"
POLICY_2 = "Step-up policy §2 (second factor recently changed)"
POLICY_3 = "Step-up policy §3 (known attacker indicator)"

_HYPOTHESES = [
    ("mule_ring", {"device_multi_account", "emulator"}),
    ("sim_swap", {"risky_support_contact", "phone_change"}),
    ("session_hijack", {"impossible_travel", "email_change"}),
    ("credential_stuffing", {"ip_spray", "spray_ip_login", "failed_logins"}),
    ("low_and_slow", {"mfa_change", "reset_unknown_device"}),
]


def hypothesis(signals: list[Signal]) -> str:
    types = {s.type for s in signals}
    for name, keys in _HYPOTHESES:
        if types & keys:
            return name
    return "unknown"


def second_factor_changed(case: Case) -> bool:
    g = case.gate
    return any(s.type in SECOND_FACTOR and s.account_id == g.account_id and g.ts - s.ts <= WINDOW_2FA
               for s in case.signals)


def evidence(case: Case) -> list[dict]:
    return [{"memory_id": s.memory_id, "agent": s.agent, "type": s.type, "weight": s.weight, "note": s.note,
             "account": s.account_id, "ts": s.ts.isoformat(), "score": s.score} for s in case.signals]


def decide(case: Case) -> Decision:
    g, risk = case.gate, case.risk
    credential = g.type in CREDENTIAL_GATES
    refs = [POLICY_1]
    if any(s.type == "known_attacker_ioc" for s in case.signals):
        action, refs = "BLOCK", [POLICY_3, POLICY_1]
    elif risk >= 80:
        action = "HOLD" if credential else "BLOCK"
    elif risk >= 50:
        if second_factor_changed(case):
            action, refs = "HOLD", [POLICY_2, POLICY_1]
        else:
            action = "STEP_UP"
    else:
        action = "ALLOW"
    pattern = next((p.pattern_id for p, _ in case.patterns), None)
    reasons = [f"{s.agent}: {s.note or s.type} (+{s.weight})" for s in case.signals]
    hyp = hypothesis(case.signals)
    verb = {"ALLOW": "Allowed", "STEP_UP": "Asked for extra verification", "HOLD": "Paused for an analyst",
            "BLOCK": "Blocked"}[action]
    teams = ", ".join(a.replace("-agent", "") for a in case.agents if a != "patterns") or "one"
    why = {"BLOCK": "together the warning signs crossed the block threshold",
           "HOLD": ("the phone number or two-factor device changed recently, so extra verification could reach "
                    "the attacker") if refs[0] == POLICY_2 else "the risk was high on an account change",
           "STEP_UP": "the warning signs were serious but not conclusive",
           "ALLOW": "the warning signs were too weak to act on"}[action]
    if refs[0] == POLICY_3:
        why = "it involves infrastructure already confirmed as used by attackers"
    plain = (f"{verb} because {why}. The {teams} agents together saw {len(case.signals)} warning signs "
             f"(risk {risk} out of 100).")
    return Decision(decision=action, risk=risk, hypothesis=hyp, reasons=reasons, evidence=evidence(case),
                    policy_refs=refs, pattern_id=pattern, plain_english=plain, decider="heuristic")
