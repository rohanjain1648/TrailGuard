"""Customers, attacker infrastructure and an event timeline builder."""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from trailguard.models import Truth

HOME_COUNTRIES = ["IN", "IN", "IN", "US", "US", "GB", "DE", "SG", "AE", "AU"]
FOREIGN_COUNTRIES = ["NL", "BR", "VN", "RO", "NG", "UA", "MX"]
EPOCH_START = datetime(2026, 10, 1, tzinfo=timezone.utc)
SPAN_DAYS = 7


def epoch_start(epoch: int) -> datetime:
    return EPOCH_START + timedelta(days=14 * (epoch - 1))


def rand_ip(rng: random.Random, prefix: str | None = None) -> str:
    if prefix:
        return f"{prefix}.{rng.randint(2, 254)}"
    return f"{rng.randint(11, 99)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"


def rand_device(rng: random.Random, head: str = "") -> str:
    return "d-" + head + "".join(rng.choice("0123456789abcdef") for _ in range(4 - len(head)))


@dataclass
class Customer:
    account_id: str
    home_country: str
    home_prefix: str  # first three octets of the home /24
    devices: list[str]
    typical_amount: int
    payees: list[str]

    def home_ip(self, rng: random.Random) -> str:
        return rand_ip(rng, self.home_prefix)


@dataclass
class Infra:
    """Attacker infrastructure. Derived from the seed only, so later epochs can reuse it."""

    proxy_prefixes: list[str]
    mule_payees: list[str]
    ring_devices: list[str]


def build_infra(seed: int, epoch: int) -> Infra:
    base = random.Random(f"infra:{seed}")
    prefixes = [f"185.220.{base.randint(10, 250)}", f"45.83.{base.randint(10, 250)}", f"193.32.{base.randint(10, 250)}"]
    mules1 = [f"P-9{base.randint(100, 999)}" for _ in range(6)]
    rings = [rand_device(base, "f") for _ in range(2)]
    if epoch == 1:
        return Infra(prefixes, mules1, rings)
    rng = random.Random(f"infra:{seed}:{epoch}")
    kept = mules1[: round(len(mules1) * 0.6)]
    fresh = [f"P-8{rng.randint(100, 999)}" for _ in range(len(mules1) - len(kept))]
    return Infra(prefixes, kept + fresh, rings)


def build_customers(rng: random.Random, epoch: int, n: int) -> list[Customer]:
    out = []
    for i in range(1, n + 1):
        devices = [rand_device(rng) for _ in range(rng.choice([1, 1, 2]))]
        out.append(
            Customer(
                account_id=f"C{epoch}{i:03d}",
                home_country=rng.choice(HOME_COUNTRIES),
                home_prefix=f"{rng.randint(11, 99)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}",
                devices=devices,
                typical_amount=rng.randint(20, 300),
                payees=[f"P-{rng.randint(1000, 7999)}" for _ in range(rng.randint(1, 4))],
            )
        )
    return out


@dataclass
class Timeline:
    """Collects raw events; ids are assigned after sorting."""

    rows: list[dict[str, Any]] = field(default_factory=list)

    def add(
        self,
        ts: datetime,
        channel: str,
        type: str,
        account_id: str,
        ip: str,
        country: str,
        device_id: str | None,
        attrs: dict[str, Any] | None = None,
        truth: Truth | None = None,
    ) -> None:
        self.rows.append(
            dict(
                ts=ts,
                channel=channel,
                type=type,
                account_id=account_id,
                ip=ip,
                country=country,
                device_id=device_id,
                attrs=attrs or {},
                truth=truth or Truth(),
                order=len(self.rows),
            )
        )

    def login(
        self,
        ts: datetime,
        c: Customer,
        device: str,
        ip: str,
        country: str,
        truth: Truth | None = None,
        emulator: bool = False,
    ) -> None:
        """A successful login: device fingerprint is collected 1 s before the session opens."""
        new = device not in c.devices
        self.add(ts - timedelta(seconds=1), "device", "device_seen", c.account_id, ip, country, device,
                 {"new_to_account": new, "emulator": emulator}, truth)
        self.add(ts, "login", "login_success", c.account_id, ip, country, device,
                 {"new_device": new, "home_country": c.home_country,
                  "known_network": ip.startswith(c.home_prefix + ".")}, truth)

    def __len__(self) -> int:
        return len(self.rows)
