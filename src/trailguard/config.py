"""Settings, signal weights and prices."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

MCP_URL = "https://mcp.mekodata.ai/mcp"
API_URL = "https://api.mekodata.ai/api/v1"
USER_AGENT = "trailguard/0.1"

SIGNALS_DATAPACK = "trailguard-signals"
PATTERNS_DATAPACK = "trailguard-patterns"

CHANNEL_AGENTS = {
    "login": "login-agent",
    "device": "device-agent",
    "recovery": "recovery-agent",
    "payments": "payments-agent",
}
SENTINEL = "sentinel"
CURATOR = "curator"
EXPLAINER = "explainer"

MODES = ("isolated", "stuffed", "meko", "meko+patterns")

ESCALATE_AT = 40

# Risk points per signal type. Mirrors knowledge/risk-rules.md (the copy agents read).
SIGNAL_WEIGHTS: dict[str, int] = {
    # login
    "failed_logins": 10,
    "ip_spray": 25,
    "spray_ip_login": 35,
    "new_device_login": 20,
    "geo_anomaly": 15,
    "impossible_travel": 35,
    "step_up_failed": 50,
    # device
    "new_device": 10,
    "device_multi_account": 40,
    "emulator": 20,
    # recovery
    "risky_support_contact": 15,
    "phone_change": 20,
    "email_change": 25,
    "reset_unknown_device": 15,
    "mfa_change": 25,
    # payments
    "new_payee": 10,
    "card_test": 20,
    "large_transfer": 25,
    "fresh_payee_transfer": 20,
    # learned / decisions
    "known_attacker_ioc": 60,
    "ttp_match": 30,
    "under_watch": 15,  # Sentinel stepped this account up recently
    "case_blocked": 15,  # Sentinel held/blocked this account recently
    "linked_case": 30,  # this device/IP/payee was in another account's blocked or failed case
}

# Signal types that describe shared infrastructure, so they count for any account
# that shares the device / IP / payee, not just the account they were seen on.
INFRA_SIGNALS = {"ip_spray", "device_multi_account"}
LINKED_CASE_SOURCES = {"case_blocked", "step_up_failed"}

# USD per 1M tokens (input, output). Anthropic first-party list prices.
PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "heuristic": (4.00, 20.00),  # estimated tokens priced as the default model
}
DEFAULT_MODEL = "claude-opus-5-5"


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


@dataclass
class Settings:
    meko_api_key: str
    anthropic_api_key: str
    meko_backend: str  # cloud | fake
    llm: str  # claude | heuristic
    model: str
    effort: str
    mcp_url: str
    api_url: str
    runs_dir: Path

    @classmethod
    def load(cls, env_file: str | Path | None = ROOT / ".env") -> "Settings":
        if env_file is not None and Path(env_file).exists():
            from dotenv import load_dotenv

            load_dotenv(env_file, override=False)
        meko_key = _env("MEKO_API_KEY")
        anth_key = _env("ANTHROPIC_API_KEY")
        backend = _env("TRAILGUARD_MEKO") or ("cloud" if meko_key else "fake")
        llm = _env("TRAILGUARD_LLM") or ("claude" if anth_key else "heuristic")
        return cls(
            meko_api_key=meko_key,
            anthropic_api_key=anth_key,
            meko_backend=backend,
            llm=llm,
            model=_env("TRAILGUARD_MODEL") or DEFAULT_MODEL,
            effort=_env("TRAILGUARD_EFFORT") or "medium",
            mcp_url=_env("MEKO_MCP_URL") or MCP_URL,
            api_url=_env("MEKO_API_URL") or API_URL,
            runs_dir=Path(_env("TRAILGUARD_RUNS") or ROOT / "runs"),
        )

    @property
    def decider_label(self) -> str:
        return f"claude:{self.model}" if self.llm == "claude" else "heuristic"
