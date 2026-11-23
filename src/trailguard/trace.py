"""Append-only JSONL trace of a run, kept next to what Meko records."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _default(o: Any) -> Any:
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if hasattr(o, "to_dict"):
        return o.to_dict()
    return str(o)


class TraceWriter:
    def __init__(self, run_dir: Path, append: bool = False) -> None:
        self.dir = Path(run_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        self._trace = (self.dir / "trace.jsonl").open(mode, encoding="utf-8")
        self._decisions = (self.dir / "decisions.jsonl").open(mode, encoding="utf-8")
        self.seq = 0

    def write(self, kind: str, **data: Any) -> None:
        self.seq += 1
        rec = {"seq": self.seq, "at": datetime.now(timezone.utc).isoformat(), "kind": kind, **data}
        self._trace.write(json.dumps(rec, default=_default) + "\n")
        if kind == "decision":
            self._decisions.write(json.dumps(data["record"], default=_default) + "\n")

    def write_json(self, name: str, obj: Any) -> Path:
        p = self.dir / name
        p.write_text(json.dumps(obj, default=_default, indent=2), encoding="utf-8")
        return p

    def close(self) -> None:
        self._trace.close()
        self._decisions.close()


def dumps(obj: Any) -> str:
    return json.dumps(obj, default=_default)


def read(run_dir: Path, name: str = "trace.jsonl") -> list[dict[str, Any]]:
    p = Path(run_dir) / name
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
