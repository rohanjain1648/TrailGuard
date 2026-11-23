"""Offline stand-in for Meko, for tests and keyless development.

It mirrors the semantics TrailGuard relies on (datapacks, memories shared by every agent on
the account, hybrid-ish search with an exact-identifier boost, knowledge chunks, learnings
and one-way promotion, artifacts by content hash). It is not Meko and is always labelled
``offline-fake``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trailguard.meko.base import ContextResult, KnowledgeHit, Meko, MekoError, MemoryHit
from trailguard.meko.meter import Meter

_TOKEN = re.compile(r"[a-z0-9][a-z0-9.\-]*")
_IDENT = re.compile(r"\b(?:c\d{3,}|d-[0-9a-f]{4}|p-\d{4}|\d{1,3}(?:\.\d{1,3}){2,3}|pat-[\w-]+|a\d-[a-z]{2}\d+)\b")


def _tokens(text: str) -> set[str]:
    return set(_TOKEN.findall(text.lower()))


def _idents(text: str) -> set[str]:
    return set(_IDENT.findall(text.lower()))


def _score(query: str, text: str) -> float:
    q, t = _tokens(query), _tokens(text)
    if not q or not t:
        return 0.0
    jac = len(q & t) / len(q | t)
    cover = len(q & t) / len(q)
    qi = _idents(query)
    ident = len(qi & _idents(text)) / len(qi) if qi else 0.0
    return round(0.4 * cover + 0.2 * jac + 0.4 * ident, 4)


class FakeMeko(Meko):
    backend = "offline-fake"

    def __init__(self, path: Path | None = None, meter: Meter | None = None) -> None:
        self.path = Path(path) if path else None
        self.meter = meter or Meter()
        self.state: dict[str, Any] = {
            "datapacks": {}, "memories": {}, "conversations": {}, "knowledge": {}, "artifacts": {},
            "token_usage": [],
        }
        if self.path and self.path.exists():
            self.state = json.loads(self.path.read_text(encoding="utf-8"))

    # -- helpers ---------------------------------------------------------------------------
    def _rec(self, tool: str, t0: float, ok: bool = True) -> None:
        self.meter.record(tool, (time.perf_counter() - t0) * 1000, ok)

    def _dp(self, datapack_id: str) -> None:
        if datapack_id not in self.state["datapacks"]:
            raise MekoError("datapack_access_denied", datapack_id)

    def save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.state), encoding="utf-8")

    async def close(self) -> None:
        self.save()

    # -- datapacks -------------------------------------------------------------------------
    async def ensure_datapack(self, name: str, description: str) -> str:
        t0 = time.perf_counter()
        for dp_id, dp in self.state["datapacks"].items():
            if dp["name"] == name:
                self._rec("datapack_search", t0)
                return dp_id
        dp_id = str(uuid.uuid4())
        self.state["datapacks"][dp_id] = {"name": name, "description": description}
        for k in ("memories", "knowledge"):
            self.state[k][dp_id] = []
        self.state["artifacts"][dp_id] = {}
        self._rec("datapack_create", t0)
        return dp_id

    async def describe(self, datapack_id: str) -> dict[str, Any]:
        self._dp(datapack_id)
        mems = self.state["memories"][datapack_id]
        return {
            "datapack_id": datapack_id, "datapack_name": self.state["datapacks"][datapack_id]["name"],
            "memory_count": sum(1 for m in mems if not m["promoted"]),
            "learnings_count": sum(1 for m in mems if not m["promoted"] and not m["kept"]),
            "collective_memory_count": sum(1 for m in mems if m["promoted"]),
            "knowledge_count": len(self.state["knowledge"][datapack_id]),
            "conversation_count": sum(1 for c in self.state["conversations"].values()
                                      if c["datapack_id"] == datapack_id),
        }

    # -- conversations ---------------------------------------------------------------------
    async def open_conversation(self, datapack_id, agent_id, session_id, title, metadata=None) -> str:
        t0 = time.perf_counter()
        self._dp(datapack_id)
        for cid, c in self.state["conversations"].items():
            if c["session_id"] == session_id and c["agent_id"] == agent_id and c["datapack_id"] == datapack_id:
                self._rec("conversation_create", t0)
                return cid
        cid = uuid.uuid4().hex
        self.state["conversations"][cid] = {"datapack_id": datapack_id, "agent_id": agent_id,
                                            "session_id": session_id, "title": title,
                                            "metadata": metadata or {}, "messages": []}
        self._rec("conversation_create", t0)
        return cid

    async def add_message(self, datapack_id, conversation_id, agent_id, input, output, reasoning, plan, metadata):
        self.meter.check("conversation_add_message")
        t0 = time.perf_counter()
        conv = self.state["conversations"].get(conversation_id)
        if conv is None:
            raise MekoError("not_found", conversation_id)
        mid = uuid.uuid4().hex
        conv["messages"].append({"message_id": mid, "input": input, "output": output, "reasoning": reasoning,
                                 "plan": plan, "metadata": metadata})
        self._rec("conversation_add_message", t0)
        return mid

    async def track_tokens(self, datapack_id, conversation_id, name, input_tokens, output_tokens, model,
                           message_id=None) -> None:
        t0 = time.perf_counter()
        self.state["token_usage"].append({"conversation_id": conversation_id, "name": name, "model": model,
                                          "input_tokens": input_tokens, "output_tokens": output_tokens,
                                          "message_id": message_id})
        self._rec("track_token_usage", t0)

    # -- memory ----------------------------------------------------------------------------
    async def add_memory(self, datapack_id, conversation_id, agent_id, text, metadata=None) -> str:
        t0 = time.perf_counter()
        self._dp(datapack_id)
        mid = str(uuid.uuid4())
        self.state["memories"][datapack_id].append({
            "id": mid, "text": text, "agent_id": agent_id, "conversation_id": conversation_id,
            "metadata": metadata or {}, "created_at": datetime.now(timezone.utc).isoformat(),
            "promoted": False, "kept": False,
        })
        self._rec("memory_add", t0)
        return mid

    def _search(self, datapack_id: str, query: str, limit: int, promoted_only: bool = False) -> list[MemoryHit]:
        hits = []
        for m in self.state["memories"].get(datapack_id, []):
            if promoted_only and not m["promoted"]:
                continue
            s = _score(query, m["text"])
            if s > 0.05:
                hits.append(MemoryHit(m["id"], m["text"], s, m["agent_id"], m["metadata"]))
        hits.sort(key=lambda h: -(h.score or 0))
        return hits[:limit]

    async def search_memory(self, datapack_id, conversation_id, agent_id, query, limit=25) -> list[MemoryHit]:
        self.meter.check("memory_search")
        t0 = time.perf_counter()
        self._dp(datapack_id)
        out = self._search(datapack_id, query, limit)
        self._rec("memory_search", t0)
        return out

    async def context_search(self, datapack_id, conversation_id, agent_id, query, limit=10) -> ContextResult:
        self.meter.check("context_search")
        t0 = time.perf_counter()
        self._dp(datapack_id)
        memory = self._search(datapack_id, query, limit)
        knowledge = [KnowledgeHit(h.id, h.text, h.score, h.metadata.get("conversation_id"))
                     for h in self._search(datapack_id, query, limit, promoted_only=True)]
        chunks = self.state["knowledge"][datapack_id]
        scored = sorted(((_score(query, c["text"]), c) for c in chunks), key=lambda x: -x[0])
        knowledge += [KnowledgeHit(c["id"], c["text"], s, c["document_id"]) for s, c in scored[:3] if s > 0.03]
        baseline = 1000 * len(chunks) if chunks else 10000
        sent = 1000 * len(knowledge) + 200 * len(memory)
        self._rec("context_search", t0)
        return ContextResult(memory, knowledge, [], {"sent": sent, "baseline": baseline,
                                                     "saved": max(0, baseline - sent)})

    async def delete_agent_memories(self, datapack_id, conversation_id, agent_id) -> None:
        t0 = time.perf_counter()
        mems = self.state["memories"].get(datapack_id, [])
        self.state["memories"][datapack_id] = [m for m in mems if m["agent_id"] != agent_id or m["promoted"]]
        self._rec("memory_delete_all", t0)

    async def list_promoted(self, datapack_id, conversation_id, agent_id) -> list[dict[str, Any]]:
        t0 = time.perf_counter()
        out = [{"id": m["id"], "memory": m["text"]} for m in self.state["memories"].get(datapack_id, [])
               if m["promoted"]]
        self._rec("memory_get_all", t0)
        return out

    async def list_learnings(self, datapack_id) -> list[dict[str, Any]]:
        return [{"id": m["id"], "memory": m["text"], "agent_id": m["agent_id"]}
                for m in self.state["memories"].get(datapack_id, []) if not m["promoted"] and not m["kept"]]

    async def promote(self, datapack_id, conversation_id, agent_id, memory_ids) -> dict[str, Any]:
        t0 = time.perf_counter()
        inserted, missing = [], []
        by_id = {m["id"]: m for m in self.state["memories"].get(datapack_id, [])}
        for mid in memory_ids:
            m = by_id.get(mid)
            if m is None or m["promoted"] or m["kept"]:
                missing.append(mid)
            else:
                m["promoted"] = True
                inserted.append(mid)
        self._rec("memory_promote", t0)
        return {"inserted_ids": inserted, "updated_ids": [], "not_found_ids": missing}

    async def keep_private(self, datapack_id, memory_ids) -> dict[str, Any]:
        n = 0
        for m in self.state["memories"].get(datapack_id, []):
            if m["id"] in memory_ids and not m["kept"] and not m["promoted"]:
                m["kept"] = True
                n += 1
        return {"updated": n}

    # -- knowledge -------------------------------------------------------------------------
    async def upload_knowledge(self, datapack_id, path: Path) -> str:
        self._dp(datapack_id)
        text = Path(path).read_text(encoding="utf-8")
        doc_id = hashlib.sha256(text.encode()).hexdigest()
        chunks = self.state["knowledge"][datapack_id]
        if any(c["document_id"] == doc_id for c in chunks):
            return doc_id
        title = next((ln.lstrip("# ").strip() for ln in text.splitlines() if ln.startswith("# ")), Path(path).name)
        for section in re.split(r"\n(?=## )", text):
            body = section.strip()
            if body and not body.startswith("# ") or "\n" in body:
                chunks.append({"id": str(uuid.uuid4()), "document_id": doc_id,
                               "text": f"[{title}] {body}" if not body.startswith("# ") else body})
        return doc_id

    async def knowledge_ready(self, datapack_id, key) -> bool:
        return True

    # -- artifacts -------------------------------------------------------------------------
    async def put_artifact(self, datapack_id, conversation_id, agent_id, filename, content, content_type) -> str:
        t0 = time.perf_counter()
        h = hashlib.sha256(content).hexdigest()
        self.state["artifacts"][datapack_id][h] = {"filename": filename, "content_type": content_type,
                                                   "b64": base64.b64encode(content).decode()}
        self._rec("artifact_put", t0)
        return h

    async def get_artifact(self, datapack_id, conversation_id, agent_id, content_hash) -> bytes:
        t0 = time.perf_counter()
        a = self.state["artifacts"].get(datapack_id, {}).get(content_hash)
        if a is None:
            raise MekoError("ARTIFACT_NOT_FOUND", content_hash)
        self._rec("artifact_get", t0)
        return base64.b64decode(a["b64"])
