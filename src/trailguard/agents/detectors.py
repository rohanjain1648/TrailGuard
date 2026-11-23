"""Deterministic per-channel detectors.

Each detector holds only its own channel's history, exactly what that team's system
would know. The detectors are identical in every benchmark mode; only what the agents
can *share* differs.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from trailguard.config import CHANNEL_AGENTS, SIGNAL_WEIGHTS
from trailguard.models import Event, Signal

RISKY_TOPICS = {"lost_phone_move_number", "change_email", "disable_mfa"}
SEVERITY = {range(0, 15): "low", range(15, 30): "medium"}


def _sev(w: int) -> str:
    for r, s in SEVERITY.items():
        if w in r:
            return s
    return "high"


class Detector:
    channel = ""

    def __init__(self) -> None:
        self.agent = CHANNEL_AGENTS[self.channel]

    def sig(self, e: Event, run_id: str, type: str, note: str, weight: int | None = None,
            payee_id: str | None = None) -> Signal:
        w = SIGNAL_WEIGHTS[type] if weight is None else weight
        return Signal(type=type, severity=_sev(w), weight=w, account_id=e.account_id, agent=self.agent,
                      ts=e.ts, event_id=e.event_id, run_id=run_id, device_id=e.device_id, ip=e.ip,
                      payee_id=payee_id, note=note)

    def observe(self, e: Event, run_id: str) -> list[Signal]:  # pragma: no cover - abstract
        raise NotImplementedError


class LoginDetector(Detector):
    channel = "login"

    def __init__(self) -> None:
        super().__init__()
        self.fails: dict[str, list[datetime]] = defaultdict(list)
        self.fail_flagged: dict[str, datetime] = {}
        self.ip_accounts: dict[str, dict[str, datetime]] = defaultdict(dict)
        self.spray_ips: set[str] = set()
        self.last_ok: dict[str, tuple[datetime, str]] = {}

    def observe(self, e: Event, run_id: str) -> list[Signal]:
        out: list[Signal] = []
        if e.type == "login_failed":
            hist = [t for t in self.fails[e.account_id] if e.ts - t <= timedelta(hours=1)] + [e.ts]
            self.fails[e.account_id] = hist
            last = self.fail_flagged.get(e.account_id)
            if len(hist) >= 2 and (last is None or e.ts - last > timedelta(hours=1)):
                self.fail_flagged[e.account_id] = e.ts
                out.append(self.sig(e, run_id, "failed_logins", f"{len(hist)} failed logins within 60 min"))
            seen = {a: t for a, t in self.ip_accounts[e.ip].items() if e.ts - t <= timedelta(hours=1)}
            seen[e.account_id] = e.ts
            self.ip_accounts[e.ip] = seen
            if len(seen) >= 5 and e.ip not in self.spray_ips:
                self.spray_ips.add(e.ip)
                out.append(self.sig(e, run_id, "ip_spray", f"IP failed on {len(seen)} accounts within 60 min"))
        elif e.type == "login_success":
            new = bool(e.attrs.get("new_device"))
            home = e.attrs.get("home_country")
            if new:
                home_net = bool(e.attrs.get("known_network"))
                out.append(self.sig(e, run_id, "new_device_login",
                                    "first login from this device" + (" (on the customer's home network)"
                                                                      if home_net else ""),
                                    weight=10 if home_net else None))
            if home and e.country != home:
                out.append(self.sig(e, run_id, "geo_anomaly", f"login from {e.country}, home is {home}",
                                    weight=None if new else 5))
            prev = self.last_ok.get(e.account_id)
            if prev and prev[1] != e.country and e.ts - prev[0] <= timedelta(hours=2):
                mins = int((e.ts - prev[0]).total_seconds() // 60)
                out.append(self.sig(e, run_id, "impossible_travel", f"{prev[1]} to {e.country} in {mins} min"))
            if e.ip in self.spray_ips:
                out.append(self.sig(e, run_id, "spray_ip_login", "success from an IP seen spraying passwords"))
            self.last_ok[e.account_id] = (e.ts, e.country)
        elif e.type == "step_up_failed":
            out.append(self.sig(e, run_id, "step_up_failed", "failed the step-up challenge"))
        return out


class DeviceDetector(Detector):
    channel = "device"

    def __init__(self) -> None:
        super().__init__()
        self.dev_accounts: dict[str, dict[str, datetime]] = defaultdict(dict)

    def observe(self, e: Event, run_id: str) -> list[Signal]:
        out: list[Signal] = []
        if e.type != "device_seen" or not e.device_id:
            return out
        if e.attrs.get("new_to_account"):
            out.append(self.sig(e, run_id, "new_device", "device not seen on this account before"))
        if e.attrs.get("emulator"):
            out.append(self.sig(e, run_id, "emulator", "fingerprint looks like an emulator"))
        seen = {a: t for a, t in self.dev_accounts[e.device_id].items() if e.ts - t <= timedelta(hours=24)}
        seen[e.account_id] = e.ts
        self.dev_accounts[e.device_id] = seen
        if len(seen) >= 3:
            out.append(self.sig(e, run_id, "device_multi_account", f"device used on {len(seen)} accounts in 24 h"))
        return out


class RecoveryDetector(Detector):
    channel = "recovery"

    def observe(self, e: Event, run_id: str) -> list[Signal]:
        a, known_dev = e.attrs, bool(e.attrs.get("known_device"))
        if e.type == "support_contact" and a.get("topic") in RISKY_TOPICS:
            return [self.sig(e, run_id, "risky_support_contact", f"support asked to {a['topic'].replace('_', ' ')}",
                             weight=None if not a.get("known_ip") else 5)]
        if e.type == "phone_change":
            return [self.sig(e, run_id, "phone_change", f"phone number changed via {a.get('via', '?')}")]
        if e.type == "email_change":
            return [self.sig(e, run_id, "email_change", "account email changed",
                             weight=None if not known_dev else 10)]
        if e.type in ("password_reset_request", "password_reset_complete") and not known_dev:
            step = "requested" if e.type.endswith("request") else "completed"
            return [self.sig(e, run_id, "reset_unknown_device", f"password reset {step} via {a.get('via')} "
                                                                 "from an unrecognised device")]
        if e.type == "mfa_device_added":
            return [self.sig(e, run_id, "mfa_change", "new MFA device added", weight=None if not known_dev else 10)]
        return []


class PaymentsDetector(Detector):
    channel = "payments"

    def __init__(self) -> None:
        super().__init__()
        self.added: dict[tuple[str, str], datetime] = {}

    def observe(self, e: Event, run_id: str) -> list[Signal]:
        a = e.attrs
        if e.type == "payee_add":
            self.added[(e.account_id, a["payee_id"])] = e.ts
            return [self.sig(e, run_id, "new_payee", f"new payee in {a.get('payee_country', '?')}",
                             payee_id=a["payee_id"])]
        if e.type == "card_test":
            return [self.sig(e, run_id, "card_test", f"micro-charge of {a.get('amount')}")]
        if e.type == "transfer":
            out = []
            payee = a.get("payee_id")
            typical = max(1, int(a.get("typical_amount") or 1))
            if a.get("amount", 0) > 5 * typical:
                out.append(self.sig(e, run_id, "large_transfer", f"{a['amount']} is {a['amount'] // typical}x typical",
                                    payee_id=payee))
            added = self.added.get((e.account_id, payee))
            if (added and e.ts - added <= timedelta(hours=24)) or (not added and not a.get("payee_known", True)):
                out.append(self.sig(e, run_id, "fresh_payee_transfer", "payee added in the last 24 h",
                                    payee_id=payee))
            return out
        return []


_DETECTORS = {d.channel: d for d in (LoginDetector, DeviceDetector, RecoveryDetector, PaymentsDetector)}


def for_channel(channel: str) -> Detector:
    return _DETECTORS[channel]()
