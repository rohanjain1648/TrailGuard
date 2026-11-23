"""Ordinary customer traffic plus seven benign 'bait' cases that look risky to one channel."""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from trailguard.models import Truth
from trailguard.sim.world import FOREIGN_COUNTRIES, Customer, Timeline, rand_device, rand_ip

BAITS = ("traveller", "phone_upgrade", "forgetful", "family_device", "big_purchase", "new_landlord", "lost_phone")


def session(tl: Timeline, rng: random.Random, c: Customer, ts: datetime) -> None:
    """A normal visit: maybe a typo, a login on a known device, 0-2 payments to known payees."""
    ip = c.home_ip(rng)
    dev = rng.choice(c.devices)
    if rng.random() < 0.05:
        tl.add(ts - timedelta(seconds=40), "login", "login_failed", c.account_id, ip, c.home_country, dev,
               {"reason": "bad_password"})
    if rng.random() < 0.02:  # a genuinely new device at home; nobody flags it as bait
        dev = rand_device(rng)
    tl.login(ts, c, dev, ip, c.home_country)
    for _ in range(rng.choice([0, 0, 1, 1, 2])):
        ts += timedelta(minutes=rng.randint(1, 20))
        amount = max(5, int(c.typical_amount * rng.uniform(0.3, 1.6)))
        tl.add(ts, "payments", "transfer", c.account_id, ip, c.home_country, dev,
               {"amount": amount, "payee_id": rng.choice(c.payees), "typical_amount": c.typical_amount,
                "payee_known": True})


def bait(tl: Timeline, rng: random.Random, kind: str, cs: list[Customer], ts: datetime) -> None:
    c = cs[0]
    t = Truth(benign_case=kind)
    home_ip = c.home_ip(rng)
    if kind == "traveller":
        country = rng.choice(FOREIGN_COUNTRIES)
        ip = rand_ip(rng)
        tl.login(ts, c, c.devices[0], ip, country, t)
        tl.add(ts + timedelta(minutes=30), "payments", "transfer", c.account_id, ip, country, c.devices[0],
               {"amount": int(c.typical_amount * 2.5), "payee_id": c.payees[0], "typical_amount": c.typical_amount,
                "payee_known": True}, t)
    elif kind == "phone_upgrade":
        dev = rand_device(rng)
        tl.login(ts, c, dev, home_ip, c.home_country, t)
        tl.add(ts + timedelta(minutes=10), "payments", "transfer", c.account_id, home_ip, c.home_country, dev,
               {"amount": c.typical_amount, "payee_id": c.payees[0], "typical_amount": c.typical_amount,
                "payee_known": True}, t)
    elif kind == "forgetful":
        for i in range(3):
            tl.add(ts + timedelta(seconds=30 * i), "login", "login_failed", c.account_id, home_ip, c.home_country,
                   c.devices[0], {"reason": "bad_password"}, t)
        tl.add(ts + timedelta(minutes=3), "recovery", "password_reset_request", c.account_id, home_ip,
               c.home_country, c.devices[0], {"via": "email", "known_device": True}, t)
        tl.add(ts + timedelta(minutes=6), "recovery", "password_reset_complete", c.account_id, home_ip,
               c.home_country, c.devices[0], {"via": "email", "known_device": True}, t)
        tl.login(ts + timedelta(minutes=7), c, c.devices[0], home_ip, c.home_country, t)
    elif kind == "family_device":
        a, b = cs[0], cs[1]
        shared = a.devices[0]
        if shared not in b.devices:
            b.devices.append(shared)
        tl.login(ts, a, shared, home_ip, a.home_country, t)
        tl.login(ts + timedelta(minutes=45), b, shared, home_ip, b.home_country, t)
    elif kind == "big_purchase":
        tl.login(ts, c, c.devices[0], home_ip, c.home_country, t)
        tl.add(ts + timedelta(minutes=8), "payments", "transfer", c.account_id, home_ip, c.home_country,
               c.devices[0], {"amount": c.typical_amount * 9, "payee_id": c.payees[0],
                              "typical_amount": c.typical_amount, "payee_known": True}, t)
    elif kind == "new_landlord":
        payee = f"P-{rng.randint(1000, 7999)}"
        tl.login(ts, c, c.devices[0], home_ip, c.home_country, t)
        tl.add(ts + timedelta(minutes=5), "payments", "payee_add", c.account_id, home_ip, c.home_country,
               c.devices[0], {"payee_id": payee, "payee_country": c.home_country}, t)
        tl.add(ts + timedelta(minutes=12), "payments", "transfer", c.account_id, home_ip, c.home_country,
               c.devices[0], {"amount": c.typical_amount * 6, "payee_id": payee,
                              "typical_amount": c.typical_amount, "payee_known": False}, t)
    elif kind == "lost_phone":
        tl.add(ts, "recovery", "support_contact", c.account_id, home_ip, c.home_country, None,
               {"topic": "lost_phone_move_number", "known_ip": True}, t)
        tl.add(ts + timedelta(minutes=40), "recovery", "phone_change", c.account_id, home_ip, c.home_country,
               None, {"via": "support", "known_device": False}, t)
        dev = rand_device(rng)
        tl.login(ts + timedelta(hours=3), c, dev, home_ip, c.home_country, t)
    else:  # pragma: no cover
        raise ValueError(kind)
