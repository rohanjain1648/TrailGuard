import json

import pytest
from fastapi.testclient import TestClient

from trailguard.config import Settings
from trailguard.web.app import create_app


@pytest.fixture
def client(tmp_path):
    s = Settings("", "", "fake", "heuristic", "claude-opus-5-5", "medium", "", "", tmp_path)
    with TestClient(create_app(s)) as c:
        yield c


def stream_until_closed(client, run_id):
    kinds = []
    with client.stream("GET", f"/api/runs/{run_id}/stream") as r:
        for line in r.iter_lines():
            if line.startswith("event: "):
                kinds.append(line[7:])
                if kinds[-1] == "closed":
                    break
    return kinds


def test_status(client):
    s = client.get("/api/status").json()
    assert s["backend"] == "offline-fake" and "not Meko" in s["backend_label"] and s["decider"] == "heuristic"
    assert set(s["datapacks"]) == {"signals", "patterns"}


def test_index_served(client):
    assert "TrailGuard" in client.get("/").text


def test_run_stream_explain_learn_audit(client):
    run_id = client.post("/api/runs", json={"mode": "meko", "seed": 1, "events": 500, "pace": 0}).json()["run_id"]
    kinds = stream_until_closed(client, run_id)
    assert {"start", "event", "signal_written", "signal_read", "decision", "done", "metrics"} <= set(kinds)
    decs = client.get(f"/api/runs/{run_id}/decisions").json()
    assert decs
    d = client.get(f"/api/runs/{run_id}/decisions/{decs[0]['n']}").json()
    assert d["card"]["headline"] and d["record"]["signals"]
    assert "Audit report" in client.get(f"/api/runs/{run_id}/audit").text
    learned = client.post("/api/learn", json={"run_id": run_id}).json()["learned"]
    pending = client.get("/api/learnings").json()["pending"]
    assert len(pending) == len(learned)
    out = client.post("/api/learnings/approve", json={"ids": [pending[0]["memory_id"]]}).json()
    assert out["inserted_ids"] == [pending[0]["memory_id"]]
    assert len(client.get("/api/learnings").json()["approved"]) == 1


def test_bad_mode_rejected(client):
    assert client.post("/api/runs", json={"mode": "nope"}).status_code == 400
