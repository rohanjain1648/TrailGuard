from datetime import datetime, timedelta, timezone

from trailguard.agents.detectors import DeviceDetector, LoginDetector, PaymentsDetector
from trailguard.models import Event

T0 = datetime(2026, 10, 1, 9, tzinfo=timezone.utc)


def ev(type, channel, account="C1001", ts=T0, ip="1.1.1.1", country="IN", device="d-0001", **attrs):
    return Event(f"E-{type}-{ts.timestamp()}-{account}", ts, channel, type, account, ip, country, device, attrs)


def types(signals):
    return [s.type for s in signals]


def test_two_failed_logins_emit_failed_logins():
    d = LoginDetector()
    assert d.observe(ev("login_failed", "login"), "r") == []
    out = d.observe(ev("login_failed", "login", ts=T0 + timedelta(minutes=5)), "r")
    assert "failed_logins" in types(out)


def test_device_on_three_accounts_emits_multi_account():
    d = DeviceDetector()
    for i, acct in enumerate(["C1001", "C1002", "C1003"]):
        out = d.observe(ev("device_seen", "device", account=acct, ts=T0 + timedelta(minutes=i),
                           device="d-f111", new_to_account=True, emulator=False), "r")
    assert "device_multi_account" in types(out)


def test_impossible_travel():
    d = LoginDetector()
    d.observe(ev("login_success", "login", new_device=False, home_country="IN"), "r")
    out = d.observe(ev("login_success", "login", ts=T0 + timedelta(minutes=50), country="BR", ip="9.9.9.9",
                       device="d-9999", new_device=True, home_country="IN"), "r")
    assert {"impossible_travel", "new_device_login", "geo_anomaly"} <= set(types(out))


def test_known_device_abroad_is_low_geo():
    d = LoginDetector()
    out = d.observe(ev("login_success", "login", country="BR", new_device=False, home_country="IN"), "r")
    geo = [s for s in out if s.type == "geo_anomaly"]
    assert geo and geo[0].weight == 5


def test_large_transfer_to_fresh_payee():
    d = PaymentsDetector()
    d.observe(ev("payee_add", "payments", payee_id="P-9001", payee_country="NL"), "r")
    out = d.observe(ev("transfer", "payments", ts=T0 + timedelta(minutes=10), amount=2000, payee_id="P-9001",
                       typical_amount=100, payee_known=False), "r")
    assert {"large_transfer", "fresh_payee_transfer"} <= set(types(out))
    assert all(s.payee_id == "P-9001" for s in out)
