import pytest

from trailguard import cli


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    monkeypatch.setenv("TRAILGUARD_MEKO", "fake")
    monkeypatch.setenv("TRAILGUARD_LLM", "heuristic")
    monkeypatch.setenv("TRAILGUARD_RUNS", str(tmp_path / "runs"))
    monkeypatch.setattr("trailguard.bootstrap.STATE_FILE", tmp_path / ".trailguard.json")
    return tmp_path


def test_cli_run_learn_audit_offline(offline, capsys):
    assert cli.main(["run", "--mode", "meko", "--seed", "1", "--events", "500", "--run-id", "t1", "--quiet"]) == 0
    run_dir = offline / "runs" / "t1"
    assert (run_dir / "trace.jsonl").exists() and (run_dir / "audit.md").exists()
    assert cli.main(["learn", "--run", "t1", "--approve"]) == 0
    assert "promoted to collective memory: 5" in capsys.readouterr().out
    assert cli.main(["explain", "--run", "t1", "-n", "1"]) == 0
    assert cli.main(["audit", "--run", "t1"]) == 0


def test_cli_crash_and_resume(offline):
    assert cli.main(["run", "--seed", "2", "--events", "500", "--run-id", "c1", "--crash-at", "200", "--quiet"]) == 3
    assert cli.main(["run", "--resume", "c1", "--quiet"]) == 0


def test_cli_generate(offline):
    out = offline / "s.jsonl"
    assert cli.main(["generate", "--seed", "3", "--events", "300", "--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8").count("\n") >= 280


def test_cli_doctor_and_setup_offline(offline, capsys):
    assert cli.main(["setup"]) == 0
    assert cli.main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "offline stand-in" in out and "knowledge_chunks=" in out
