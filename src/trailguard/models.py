"""Core data types shared by the simulator, agents, engine and reports."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Truth:
    """Ground truth attached to every simulated event. Agents never see it."""

    attack_id: str | None = None
    ttp: str | None = None
    step: int | None = None
    completes_takeover: bool = False
    benign_case: str | None = None


@dataclass(frozen=True)
class Event:
    event_id: str
    ts: datetime
    channel: str  # login | device | recovery | payments
    type: str
    account_id: str
    ip: str
    country: str
    device_id: str | None
    attrs: dict[str, Any] = field(default_factory=dict)
    truth: Truth = field(default_factory=Truth)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        d = dict(d)
        d["ts"] = datetime.fromisoformat(d["ts"])
        d["truth"] = Truth(**d.get("truth") or {})
        return cls(**d)

    @property
    def is_attack(self) -> bool:
        return self.truth.attack_id is not None


@dataclass
class Signal:
    """A risk signal one agent observed. Shared through Meko as a TG-SIGNAL memory."""

    type: str
    severity: str  # low | medium | high
    weight: int
    account_id: str
    agent: str
    ts: datetime
    event_id: str
    run_id: str
    device_id: str | None = None
    ip: str | None = None
    payee_id: str | None = None
    note: str = ""
    memory_id: str | None = None  # set once stored in / read back from Meko
    score: float | None = None  # Meko retrieval score when read back

    @property
    def entity_key(self) -> tuple[str, str]:
        """(type, entity) used to de-duplicate signals when scoring a case."""
        ent = self.account_id
        if self.type in ("ip_spray",):
            ent = f"ip:{self.ip}"
        elif self.type in ("device_multi_account",):
            ent = f"device:{self.device_id}"
        return (self.type, ent)


@dataclass
class Decision:
    decision: str  # ALLOW | STEP_UP | HOLD | BLOCK
    risk: int
    hypothesis: str
    reasons: list[str]
    evidence: list[dict[str, Any]]
    policy_refs: list[str]
    pattern_id: str | None
    plain_english: str
    decider: str
    tokens_in: int = 0
    tokens_out: int = 0
    tokens_estimated: bool = False
    latency_ms: float = 0.0
    fallback: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Pattern:
    """A confirmed attacker pattern distilled by the Curator."""

    pattern_id: str
    ttp: str
    sequence: list[str]
    iocs: dict[str, list[str]]  # ip_subnet / device / payee -> values
    earliest_signal: str
    action: str
    epoch: int
    source_cases: list[str] = field(default_factory=list)
    memory_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
