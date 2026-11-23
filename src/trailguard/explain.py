"""Plain-English decision cards built from the decision trace.

Target reader: someone with no engineering background who should be able to answer
"why did the agents do that?" in under two minutes.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

AGENT_NAMES = {"login-agent": "Login agent", "device-agent": "Device agent", "recovery-agent": "Account-recovery agent",
               "payments-agent": "Payments agent", "sentinel": "Sentinel (decision agent)",
               "patterns": "Confirmed-pattern library"}

SIGNAL_PLAIN = {
    "failed_logins": "several wrong passwords in a short time",
    "ip_spray": "a network trying passwords on many accounts",
    "spray_ip_login": "a successful login from a network caught trying passwords on many accounts",
    "new_device_login": "a first login from a device never used on this account",
    "geo_anomaly": "a login from outside the customer's home country",
    "impossible_travel": "logins from two countries too close together to be one person",
    "step_up_failed": "a failed extra-verification check",
    "new_device": "a device never seen on this account",
    "emulator": "a device that looks like software pretending to be a phone",
    "device_multi_account": "one device being used on several different customers' accounts",
    "risky_support_contact": "a call to support asking to move the phone number",
    "phone_change": "the account's phone number being changed",
    "email_change": "the account's email address being changed",
    "reset_unknown_device": "a password reset from an unrecognised device",
    "mfa_change": "a new two-factor device being added",
    "new_payee": "a new payee being added",
    "card_test": "a tiny test charge, typical of someone checking stolen card details",
    "large_transfer": "a transfer far larger than this customer usually makes",
    "fresh_payee_transfer": "money going to a payee added less than a day ago",
    "known_attacker_ioc": "a device, network or payee already confirmed as used by attackers",
    "ttp_match": "the same sequence of moves as a confirmed attack",
    "under_watch": "the account was already asked for extra verification recently",
    "case_blocked": "the account was already paused or blocked recently",
    "linked_case": "a device, network or payee linked to another account's stopped attack",
}

GATE_PLAIN = {
    "transfer": "a transfer", "payee_add": "adding a new payee", "login_success": "a login from a new device",
    "phone_change": "a phone-number change", "email_change": "an email change",
    "password_reset_complete": "a password reset", "mfa_device_added": "adding a two-factor device",
    "card_test": "a small card charge",
}

ACTION_HEAD = {"ALLOW": "Allowed", "STEP_UP": "Asked for extra verification on", "HOLD": "Paused for review:",
               "BLOCK": "Blocked"}

OUTCOME_PLAIN = {
    "stopped": "The attempt was stopped here, so the attacker's later steps never happened.",
    "step_up_failed": "The person could not pass the extra check, so the attempt stopped here.",
    "step_up_passed": "The person passed the extra check and carried on.",
    "allowed": "The action went ahead and the agents kept watching the account.",
    "held_benign": "This was the genuine customer: an analyst would release the hold (a false alarm).",
}

POLICY_PLAIN = {
    "§1": "Risk thresholds: 80 or more blocks money movement and pauses account changes; 50 to 79 asks for extra "
          "verification.",
    "§2": "If the phone number or two-factor device changed in the last 72 hours, extra verification would go to "
          "whoever changed it, so the action is paused instead.",
    "§3": "Anything already confirmed as attacker infrastructure is blocked on sight.",
}


def _ago(then: str, now: str) -> str:
    secs = (datetime.fromisoformat(now) - datetime.fromisoformat(then)).total_seconds()
    if secs < 60:
        return "moments earlier"
    mins = int(secs // 60)
    if mins < 60:
        return f"{mins} min earlier"
    hours, mins = divmod(mins, 60)
    if hours < 48:
        return f"{hours} h {mins} min earlier" if mins else f"{hours} h earlier"
    return f"{hours // 24} days earlier"


def _span(rec: dict[str, Any]) -> str:
    ts = [s["ts"] for s in rec["signals"]] + [rec["ts"]]
    secs = (max(datetime.fromisoformat(t) for t in ts) - min(datetime.fromisoformat(t) for t in ts)).total_seconds()
    if secs < 120:
        return "a minute"
    if secs < 3600:
        return f"{int(secs // 60)} minutes"
    if secs < 48 * 3600:
        return f"{round(secs / 3600)} hours"
    return f"{round(secs / 86400)} days"


def _gate_phrase(rec: dict[str, Any]) -> str:
    base = GATE_PLAIN.get(rec["gate"], rec["gate"].replace("_", " "))
    amount = (rec.get("event") or {}).get("attrs", {}).get("amount")
    return f"{base} of {amount:,}" if rec["gate"] == "transfer" and amount else base


def _policy(rec: dict[str, Any]) -> list[str]:
    out = []
    for ref in rec.get("policy_refs", []):
        for k, v in POLICY_PLAIN.items():
            if k in ref and v not in out:
                out.append(v)
    return out or [POLICY_PLAIN["§1"]]


def card(rec: dict[str, Any]) -> dict[str, Any]:
    agents = sorted({s["agent"] for s in rec["signals"] if s["agent"] != "patterns"})
    n_agents = len(agents)
    head = (f"{ACTION_HEAD.get(rec['decision'], rec['decision'])} {_gate_phrase(rec)} on account {rec['account']}. "
            f"{n_agents} agent{'s' if n_agents != 1 else ''} saw {len(rec['signals'])} warning "
            f"sign{'s' if len(rec['signals']) != 1 else ''} within {_span(rec)}.")
    ev = rec.get("event") or {}
    when = datetime.fromisoformat(rec["ts"]).strftime("%d %b %H:%M UTC")
    knew = []
    for s in sorted(rec["signals"], key=lambda x: x["ts"]):
        other = s["account"] != rec["account"]
        knew.append({
            "agent": AGENT_NAMES.get(s["agent"], s["agent"]),
            "when": _ago(s["ts"], rec["ts"]),
            "what": SIGNAL_PLAIN.get(s["type"], s["type"].replace("_", " "))
                    + (f" (seen on another account, {s['account']})" if other else ""),
            "detail": s.get("note", ""), "points": s["weight"], "memory_id": s.get("memory_id"),
            "match_score": s.get("score"),
        })
    patterns = rec.get("patterns") or []
    pattern = (f"This matches a confirmed attacker pattern ({patterns[0]['ttp'].replace('_', ' ')}) that an analyst "
               f"approved after earlier attacks.") if patterns else None
    truth = rec.get("truth") or {}
    if truth.get("attack_id"):
        reality = f"Simulation ground truth: an attack ({truth['ttp'].replace('_', ' ')}), step {truth['step'] + 1}."
    else:
        reality = "Simulation ground truth: the genuine customer."
    return {
        "n": rec["n"], "decision": rec["decision"], "risk": rec["risk"], "headline": head,
        "what_happened": f"At {when}, {_gate_phrase(rec)} was requested on account {rec['account']} from "
                         f"{ev.get('country', '?')} (network {ev.get('ip', '?')}"
                         + (f", device {ev['device']}" if ev.get("device") else "") + ").",
        "what_agents_knew": knew,
        "rule": _policy(rec),
        "pattern": pattern,
        "model_explanation": rec.get("plain_english", ""),
        "what_next": OUTCOME_PLAIN.get(rec.get("outcome", ""), ""),
        "reality": reality,
        "decider": rec.get("decider"), "fallback": rec.get("fallback", False),
        "meko_refs": {**(rec.get("meko") or {}),
                      "signal_memory_ids": [s.get("memory_id") for s in rec["signals"] if s.get("memory_id")],
                      "playbook_passages": [p.get("id") for p in rec.get("playbook", [])]},
    }


def card_markdown(c: dict[str, Any]) -> str:
    lines = [f"#### Decision {c['n']}: {c['decision']} (risk {c['risk']}/100)", "", f"**{c['headline']}**", "",
             f"**What happened.** {c['what_happened']}", "", "**What the agents knew.**", ""]
    for k in c["what_agents_knew"]:
        mid = f" · memory `{k['memory_id']}`" if k["memory_id"] else ""
        lines.append(f"- {k['when']}, the **{k['agent']}** saw {k['what']} (+{k['points']}){mid}")
    lines += ["", "**Rule applied.** " + " ".join(c["rule"])]
    if c["pattern"]:
        lines += ["", f"**Pattern recognised.** {c['pattern']}"]
    if c["model_explanation"]:
        lines += ["", f"**Sentinel's explanation.** {c['model_explanation']}"]
    lines += ["", f"**What happened next.** {c['what_next']}", "", f"_{c['reality']}_"]
    refs = c["meko_refs"]
    if refs.get("message_id"):
        lines += ["", f"Meko trace: conversation `{refs.get('conversation_id')}`, message `{refs['message_id']}`"
                      " (open Datapack > Conversations > Decision trace in the Meko portal)."]
    return "\n".join(lines)
