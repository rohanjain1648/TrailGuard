from datetime import datetime, timezone

from trailguard.config import Settings
from trailguard.models import Event, Truth


def test_event_roundtrip():
    e = Event(
        event_id="E00001",
        ts=datetime(2026, 10, 1, 8, 30, tzinfo=timezone.utc),
        channel="login",
        type="login_success",
        account_id="C0001",
        ip="10.1.2.3",
        country="IN",
        device_id="d-1a2b",
        attrs={"new_device": True},
        truth=Truth(attack_id="A1", ttp="sim_swap", step=3, completes_takeover=False, benign_case=None),
    )
    assert Event.from_dict(e.to_dict()) == e


def test_settings_defaults_offline(monkeypatch):
    for k in ("MEKO_API_KEY", "ANTHROPIC_API_KEY", "TRAILGUARD_MEKO", "TRAILGUARD_LLM"):
        monkeypatch.setenv(k, "")
    s = Settings.load(env_file=None)
    assert s.meko_backend == "fake"
    assert s.llm == "heuristic"
