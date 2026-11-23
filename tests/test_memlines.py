from datetime import datetime, timezone

from trailguard.memlines import (
    format_decision,
    format_pattern,
    format_signal,
    parse_decision,
    parse_pattern,
    parse_signal,
)
from trailguard.models import Decision, Pattern, Signal

TS = datetime(2026, 10, 1, tzinfo=timezone.utc)


def sig(**kw):
    base = dict(type="phone_change", severity="medium", weight=20, account_id="C1001", agent="recovery-agent",
                ts=TS, event_id="E1-00001", run_id="r1", ip="1.2.3.4", note="number moved | via support")
    base.update(kw)
    return Signal(**base)


def test_signal_roundtrip():
    s = sig(device_id="d-ab12", payee_id="P-9001")
    back = parse_signal(format_signal(s))
    assert back.type == s.type and back.account_id == s.account_id and back.weight == 20
    assert back.device_id == "d-ab12" and back.payee_id == "P-9001" and back.ip == "1.2.3.4"
    assert back.ts == TS and back.run_id == "r1"
    assert "|" not in back.note


def test_parse_signal_tolerates_prose():
    text = ("Note: TG-SIGNAL v1 | type=phone_change | account=C0001 | sev=medium | w=20 | agent=recovery-agent "
            "| ts=2026-10-01T00:00:00+00:00 | event=E1 | run=r1 (extracted)")
    s = parse_signal(text)
    assert s is not None and s.type == "phone_change" and s.run_id == "r1"


def test_parse_signal_ignores_other_text():
    assert parse_signal("user likes tea") is None


def test_pattern_roundtrip():
    p = Pattern("PAT-sim_swap-abc123", "sim_swap", ["risky_support_contact", "phone_change"],
                {"ip_subnet": ["185.220.33"], "device": [], "payee": ["P-9123"]}, "risky_support_contact",
                "HOLD at phone_change", 1, ["A1-SS1-C1003"])
    back = parse_pattern(format_pattern(p))
    assert back.pattern_id == p.pattern_id and back.sequence == p.sequence
    assert back.iocs["payee"] == ["P-9123"] and back.iocs["device"] == [] and back.epoch == 1


def test_decision_line():
    d = Decision("HOLD", 72, "sim_swap", [], [], [], None, "", "heuristic")
    rec = parse_decision(format_decision("C1001", d, "E1-00009", "r1", TS))
    assert rec["decision"] == "HOLD" and rec["account"] == "C1001" and rec["risk"] == 72
