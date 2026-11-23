"""The five planted account-takeover TTPs.

Each builder appends one or more attack *instances* to the timeline. An instance is one
victim account's takeover attempt: an ordered list of steps with exactly one completion
step (the first irreversible harm: money out, or the owner locked out).
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from trailguard.models import Truth
from trailguard.sim.world import FOREIGN_COUNTRIES, Customer, Infra, Timeline, rand_device, rand_ip


def _t(aid: str, ttp: str, step: int, completion: int) -> Truth:
    return Truth(attack_id=aid, ttp=ttp, step=step, completes_takeover=step == completion)


def _mins(rng: random.Random, lo: int, hi: int) -> timedelta:
    return timedelta(minutes=rng.randint(lo, hi))


def _money_out(tl: Timeline, rng, c: Customer, ts: datetime, ip, country, device, mule, aid, ttp, step_payee, completion):
    """payee_add (mule) then a large transfer to it."""
    tl.add(ts, "payments", "payee_add", c.account_id, ip, country, device,
           {"payee_id": mule, "payee_country": rng.choice(FOREIGN_COUNTRIES)}, _t(aid, ttp, step_payee, completion))
    ts += _mins(rng, 4, 30)
    amount = c.typical_amount * rng.randint(8, 25)
    tl.add(ts, "payments", "transfer", c.account_id, ip, country, device,
           {"amount": amount, "payee_id": mule, "typical_amount": c.typical_amount, "payee_known": False},
           _t(aid, ttp, step_payee + 1, completion))


def credential_stuffing(tl: Timeline, rng, victims: list[Customer], bystanders: list[Customer],
                        infra: Infra, t0: datetime, campaign: str) -> None:
    """Spray 1-2 failures over many accounts through a rotating residential proxy pool
    (no single IP touches more than 4 accounts), then take over the few that succeed."""
    pool = [rand_ip(rng, rng.choice(infra.proxy_prefixes)) for _ in range(12)]
    targets = bystanders + victims
    rng.shuffle(targets)
    ts = t0
    for i, c in enumerate(targets):
        ip = pool[i % len(pool)]
        is_victim = c in victims
        aid = f"{campaign}-{c.account_id}" if is_victim else None
        truth = _t(aid, "credential_stuffing", 0, 3) if is_victim else Truth(ttp="credential_stuffing")
        for _ in range(rng.randint(1, 2)):
            tl.add(ts, "login", "login_failed", c.account_id, ip, c.home_country, rand_device(rng),
                   {"reason": "bad_password"}, truth)
            ts += timedelta(seconds=rng.randint(20, 90))
    for c in victims:
        aid = f"{campaign}-{c.account_id}"
        dev, ip = rand_device(rng), rand_ip(rng, rng.choice(infra.proxy_prefixes))
        ts = t0 + _mins(rng, 40, 120)
        tl.login(ts, c, dev, ip, c.home_country, _t(aid, "credential_stuffing", 1, 3))
        _money_out(tl, rng, c, ts + _mins(rng, 5, 40), ip, c.home_country, dev,
                   rng.choice(infra.mule_payees), aid, "credential_stuffing", 2, 3)


def sim_swap(tl: Timeline, rng, c: Customer, infra: Infra, t0: datetime, campaign: str) -> None:
    """Social-engineer support into moving the number, reset by SMS, then drain."""
    aid, ttp, done = f"{campaign}-{c.account_id}", "sim_swap", 3
    ip = rand_ip(rng, rng.choice(infra.proxy_prefixes))
    ts = t0
    tl.add(ts, "recovery", "support_contact", c.account_id, ip, c.home_country, None,
           {"topic": "lost_phone_move_number", "known_ip": False}, _t(aid, ttp, 0, done))
    ts += _mins(rng, 20, 90)
    tl.add(ts, "recovery", "phone_change", c.account_id, ip, c.home_country, None,
           {"via": "support", "known_device": False}, _t(aid, ttp, 1, done))
    ts += _mins(rng, 10, 60)
    tl.add(ts, "recovery", "password_reset_request", c.account_id, ip, c.home_country, None,
           {"via": "sms", "known_device": False}, _t(aid, ttp, 2, done))
    ts += _mins(rng, 2, 10)
    tl.add(ts, "recovery", "password_reset_complete", c.account_id, ip, c.home_country, None,
           {"via": "sms", "known_device": False}, _t(aid, ttp, 3, done))
    dev = rand_device(rng)
    ts += _mins(rng, 5, 30)
    tl.login(ts, c, dev, ip, c.home_country, _t(aid, ttp, 4, done))
    _money_out(tl, rng, c, ts + _mins(rng, 5, 30), ip, c.home_country, dev,
               rng.choice(infra.mule_payees), aid, ttp, 5, done)


def session_hijack(tl: Timeline, rng, c: Customer, infra: Infra, t0: datetime, campaign: str) -> None:
    """Phished session used from abroad shortly after a genuine home login."""
    aid, ttp, done = f"{campaign}-{c.account_id}", "session_hijack", 2
    tl.login(t0, c, c.devices[0], c.home_ip(rng), c.home_country)  # the genuine user
    country = rng.choice(FOREIGN_COUNTRIES)
    ip, dev = rand_ip(rng), rand_device(rng)
    ts = t0 + _mins(rng, 30, 90)
    tl.login(ts, c, dev, ip, country, _t(aid, ttp, 0, done))
    ts += _mins(rng, 3, 20)
    tl.add(ts, "recovery", "email_change", c.account_id, ip, country, dev,
           {"via": "app", "known_device": False}, _t(aid, ttp, 1, done))
    ts += _mins(rng, 3, 20)
    tl.add(ts, "recovery", "password_reset_complete", c.account_id, ip, country, dev,
           {"via": "email", "known_device": False}, _t(aid, ttp, 2, done))
    tl.add(ts + _mins(rng, 5, 20), "payments", "payee_add", c.account_id, ip, country, dev,
           {"payee_id": rng.choice(infra.mule_payees), "payee_country": country}, _t(aid, ttp, 3, done))


def mule_ring(tl: Timeline, rng, accounts: list[Customer], infra: Infra, t0: datetime, campaign: str) -> None:
    """One emulator fingerprint works through several accounts, interleaved."""
    ttp, done = "mule_ring", 3
    dev = infra.ring_devices[0]
    mule = rng.choice(infra.mule_payees)
    for i, c in enumerate(accounts):
        aid = f"{campaign}-{c.account_id}"
        ip = rand_ip(rng, rng.choice(infra.proxy_prefixes))
        ts = t0 + timedelta(minutes=25 * i)
        tl.login(ts, c, dev, ip, c.home_country, _t(aid, ttp, 0, done), emulator=True)
        ts += _mins(rng, 30, 50)
        tl.add(ts, "payments", "card_test", c.account_id, ip, c.home_country, dev,
               {"amount": round(rng.uniform(0.5, 1.99), 2)}, _t(aid, ttp, 1, done))
        _money_out(tl, rng, c, ts + _mins(rng, 20, 60), ip, c.home_country, dev, mule, aid, ttp, 2, done)


def low_and_slow(tl: Timeline, rng, c: Customer, infra: Infra, t0: datetime, campaign: str) -> None:
    """Patient takeover over three days, each step below any single-channel alarm."""
    aid, ttp, done = f"{campaign}-{c.account_id}", "low_and_slow", 6
    ip = rand_ip(rng, rng.choice(infra.proxy_prefixes))
    ts = t0
    tl.add(ts, "recovery", "password_reset_request", c.account_id, ip, c.home_country, None,
           {"via": "email", "known_device": False}, _t(aid, ttp, 0, done))
    ts += timedelta(hours=rng.randint(18, 30))
    for _ in range(2):
        tl.add(ts, "login", "login_failed", c.account_id, ip, c.home_country, rand_device(rng),
               {"reason": "bad_password"}, _t(aid, ttp, 1, done))
        ts += _mins(rng, 2, 15)
    ts += timedelta(hours=rng.randint(18, 30))
    dev = rand_device(rng)
    tl.add(ts, "recovery", "mfa_device_added", c.account_id, ip, c.home_country, dev,
           {"via": "email", "known_device": False}, _t(aid, ttp, 2, done))
    ts += _mins(rng, 10, 60)
    tl.login(ts, c, dev, ip, c.home_country, _t(aid, ttp, 3, done))
    ts += _mins(rng, 10, 60)
    tl.add(ts, "payments", "card_test", c.account_id, ip, c.home_country, dev,
           {"amount": round(rng.uniform(0.5, 1.99), 2)}, _t(aid, ttp, 4, done))
    _money_out(tl, rng, c, ts + _mins(rng, 30, 120), ip, c.home_country, dev,
               rng.choice(infra.mule_payees), aid, ttp, 5, done)
