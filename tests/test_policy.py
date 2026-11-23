from datetime import datetime, timedelta, timezone

from trailguard.agents.case import Case
from trailguard.llm.heuristic import decide, hypothesis
from trailguard.models import Event, Signal

T0 = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def case(risk, gate_type="transfer", signals=()):
    g = Event("G", T0, "payments", gate_type, "C1001", "5.5.5.5", "IN", "d-aaaa", {"payee_id": "P-9001"})
    return Case(gate=g, signals=list(signals), risk=risk)


def s(type, w=20, ts=T0 - timedelta(minutes=30)):
    return Signal(type, "medium", w, "C1001", "recovery-agent", ts, "E", "r1")


def test_policy_thresholds():
    assert decide(case(39)).decision == "ALLOW"
    assert decide(case(55)).decision == "STEP_UP"
    assert decide(case(85, "transfer")).decision == "BLOCK"
    assert decide(case(85, "email_change")).decision == "HOLD"


def test_sms_exception():
    d = decide(case(55, "password_reset_complete", [s("phone_change")]))
    assert d.decision == "HOLD"
    assert any("§2" in r for r in d.policy_refs)


def test_known_ioc_blocks():
    d = decide(case(30, "payee_add", [s("known_attacker_ioc", 60)]))
    assert d.decision == "BLOCK" and any("§3" in r for r in d.policy_refs)


def test_hypothesis():
    assert hypothesis([s("risky_support_contact"), s("phone_change")]) == "sim_swap"
    assert hypothesis([s("device_multi_account")]) == "mule_ring"
    assert hypothesis([s("new_payee")]) == "unknown"


def test_decision_evidence_lists_signals():
    d = decide(case(55, signals=[s("phone_change"), s("email_change")]))
    assert [e["type"] for e in d.evidence] == ["phone_change", "email_change"]
    assert d.decider == "heuristic"
