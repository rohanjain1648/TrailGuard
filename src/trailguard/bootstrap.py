"""One-time setup: datapacks exist, the fraud playbooks are in the patterns knowledge base."""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable

from trailguard.config import ROOT
from trailguard.engine import Runtime

KNOWLEDGE_DIR = ROOT / "knowledge"
STATE_FILE = ROOT / ".trailguard.json"


def _state() -> dict[str, Any]:
    return json.loads(STATE_FILE.read_text(encoding="utf-8")) if STATE_FILE.exists() else {}


async def ensure(rt: Runtime, say: Callable[[str], None] = print, wait_s: float = 300) -> dict[str, Any]:
    assert rt.meko is not None
    state = _state()
    key = rt.backend
    uploaded: dict[str, Any] = state.get(key, {}).get("knowledge", {})
    pending: dict[str, str] = {}
    for path in sorted(KNOWLEDGE_DIR.glob("*.md")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if uploaded.get(path.name, {}).get("sha256") == digest and uploaded[path.name].get("ready"):
            say(f"  knowledge {path.name}: already indexed")
            continue
        doc_key = await rt.meko.upload_knowledge(rt.datapacks["patterns"], path)
        uploaded[path.name] = {"sha256": digest, "key": doc_key, "ready": False}
        pending[path.name] = doc_key
        say(f"  knowledge {path.name}: uploaded")
    deadline = time.monotonic() + wait_s
    while pending and time.monotonic() < deadline:
        for name, doc_key in list(pending.items()):
            if await rt.meko.knowledge_ready(rt.datapacks["patterns"], doc_key):
                uploaded[name]["ready"] = True
                pending.pop(name)
                say(f"  knowledge {name}: indexed")
        if pending:
            await asyncio.sleep(3)
    for name in pending:
        say(f"  knowledge {name}: still indexing (check again with `trailguard setup`)")
    state[key] = {"datapacks": rt.datapacks, "knowledge": uploaded}
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return state[key]
