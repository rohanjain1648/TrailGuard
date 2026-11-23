"""One-line memory formats that TrailGuard stores in Meko.

Every memory is a single self-contained line, for example:

    TG-SIGNAL v1 | type=phone_change | account=C1003 | sev=medium | w=20 | ...

Exact identifiers in the text get Meko's keyword and entity boost at search time, and the
parser recovers fields from ``key=value`` pairs wherever the marker appears, so extra
prose around the line does not break it.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from trailguard.models import Decision, Pattern, Signal

_MARK = re.compile(r"TG-(SIGNAL|DECISION|PATTERN|CHECKPOINT|ARTIFACT) v1")
_FREE_TEXT_KEYS = {"note", "action", "summary"}


def _clean(v: Any) -> str:
    return re.sub(r"\s+", " ", str(v).replace("|", "/")).strip() or "-"


def _line(kind: str, fields: dict[str, Any]) -> str:
    return f"TG-{kind} v1 | " + " | ".join(f"{k}={_clean(v)}" for k, v in fields.items())


def parse_fields(text: str, kind: str) -> dict[str, str] | None:
    m = None
    for m in _MARK.finditer(text or ""):
        if m.group(1) == kind:
            break
    else:
        return None
    if m is None or m.group(1) != kind:
        return None
    out: dict[str, str] = {}
    for part in text[m.end():].split("|"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        if not re.fullmatch(r"\w+", k):
            continue
        v = v.strip()
        if k not in _FREE_TEXT_KEYS:
            v = v.split()[0] if v.split() else ""
        out[k] = v
    return out


def _opt(v: str | None) -> str | None:
    return None if v in (None, "", "-") else v


# --- signals -----------------------------------------------------------------------------

def format_signal(s: Signal) -> str:
    return _line("SIGNAL", {
        "type": s.type, "account": s.account_id, "sev": s.severity, "w": s.weight,
        "device": s.device_id or "-", "ip": s.ip or "-", "payee": s.payee_id or "-",
        "ts": s.ts.isoformat(), "agent": s.agent, "event": s.event_id, "run": s.run_id, "note": s.note,
    })


def parse_signal(text: str) -> Signal | None:
    f = parse_fields(text, "SIGNAL")
    if not f or not {"type", "account", "ts"} <= f.keys():
        return None
    try:
        return Signal(
            type=f["type"], severity=f.get("sev", "medium"), weight=int(f.get("w", 0)),
            account_id=f["account"], agent=f.get("agent", "?"), ts=datetime.fromisoformat(f["ts"]),
            event_id=f.get("event", "?"), run_id=f.get("run", "?"), device_id=_opt(f.get("device")),
            ip=_opt(f.get("ip")), payee_id=_opt(f.get("payee")), note=_opt(f.get("note")) or "",
        )
    except (ValueError, TypeError):
        return None


# --- decisions ---------------------------------------------------------------------------

def format_decision(account_id: str, d: Decision, event_id: str, run_id: str, ts: datetime) -> str:
    return _line("DECISION", {
        "account": account_id, "decision": d.decision, "risk": d.risk, "hypothesis": d.hypothesis,
        "event": event_id, "run": run_id, "ts": ts.isoformat(), "agent": "sentinel",
        "summary": d.plain_english[:240],
    })


def parse_decision(text: str) -> dict[str, Any] | None:
    f = parse_fields(text, "DECISION")
    if not f or "decision" not in f:
        return None
    rec: dict[str, Any] = dict(f)
    try:
        rec["risk"] = int(f.get("risk", 0))
        rec["ts"] = datetime.fromisoformat(f["ts"]) if "ts" in f else None
    except ValueError:
        return None
    return rec


# --- patterns ----------------------------------------------------------------------------

def _csv(vals: list[str]) -> str:
    return ",".join(vals) if vals else "-"


def _uncsv(v: str | None) -> list[str]:
    return [] if v in (None, "", "-") else [x for x in v.split(",") if x]


def format_pattern(p: Pattern) -> str:
    return _line("PATTERN", {
        "id": p.pattern_id, "ttp": p.ttp, "sequence": ">".join(p.sequence),
        "ioc_subnet": _csv(p.iocs.get("ip_subnet", [])), "ioc_device": _csv(p.iocs.get("device", [])),
        "ioc_payee": _csv(p.iocs.get("payee", [])), "earliest": p.earliest_signal, "epoch": p.epoch,
        "cases": _csv(p.source_cases), "action": p.action,
    })


def parse_pattern(text: str) -> Pattern | None:
    f = parse_fields(text, "PATTERN")
    if not f or not {"id", "ttp"} <= f.keys():
        return None
    try:
        return Pattern(
            pattern_id=f["id"], ttp=f["ttp"], sequence=[x for x in f.get("sequence", "").split(">") if x],
            iocs={"ip_subnet": _uncsv(f.get("ioc_subnet")), "device": _uncsv(f.get("ioc_device")),
                  "payee": _uncsv(f.get("ioc_payee"))},
            earliest_signal=f.get("earliest", ""), action=f.get("action", ""), epoch=int(f.get("epoch", 0)),
            source_cases=_uncsv(f.get("cases")),
        )
    except ValueError:
        return None


# --- checkpoints and artifacts -----------------------------------------------------------

def format_checkpoint(run_id: str, offset: int, content_hash: str) -> str:
    return _line("CHECKPOINT", {"run": run_id, "offset": offset, "hash": content_hash})


def format_artifact(name: str, run_id: str, content_hash: str) -> str:
    return _line("ARTIFACT", {"name": name, "run": run_id, "hash": content_hash})
