"""Meko Cloud client: MCP tools over Streamable HTTP plus the Datapack REST API.

Rules learned from Meko's docs and source, which this client enforces:
  * every request carries ``Authorization: Bearer mko_tkn_...`` and a ``User-Agent``;
  * Meko Cloud refuses arguments a tool doesn't declare, so arguments are filtered
    against each tool's ``inputSchema`` from ``tools/list``;
  * most tools need a ``conversation_id``;
  * actionable errors come back *in band* as ``{"error": code, "detail": ...}`` with
    ``isError: false``, so every reply is checked for that shape;
  * ``metadata`` is sent as a JSON string.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import httpx

from trailguard.config import USER_AGENT, Settings
from trailguard.meko.base import ContextResult, KnowledgeHit, Meko, MekoError, MemoryHit
from trailguard.meko.meter import Meter

RETRYABLE = ("RATE_LIMIT", "rate_limit", "cloud_unreachable", "TIMEOUT", "LANGFUSE_UNAVAILABLE")


def _get(obj: Any, *names: str, default: Any = None) -> Any:
    for n in names:
        if isinstance(obj, dict) and n in obj:
            return obj[n]
        if hasattr(obj, n):
            return getattr(obj, n)
    return default


def parse_tool_result(result: Any) -> Any:
    """Turn an MCP CallToolResult into Python data, raising MekoError on any error shape."""
    content = _get(result, "content", default=[]) or []
    text = "".join(_get(c, "text", default="") or "" for c in content if _get(c, "type") == "text")
    if _get(result, "is_error", "isError", default=False):
        raise MekoError("tool_error", text[:500])
    structured = _get(result, "structured_content", "structuredContent")
    payload: Any = None
    if isinstance(structured, dict) and "result" in structured:
        payload = structured["result"]
    elif structured is not None:
        payload = structured
    else:
        payload = text
    if isinstance(payload, str):
        s = payload.strip()
        if s.startswith("Error:"):
            raise MekoError("tool_error", s)
        try:
            payload = json.loads(s) if s else {}
        except json.JSONDecodeError:
            return s
    if isinstance(payload, dict) and isinstance(payload.get("error"), str):
        raise MekoError(payload["error"], str(payload.get("detail") or payload.get("message") or ""))
    return payload


def _results(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("results", "hits", "memories", "items"):
            v = payload.get(key)
            if isinstance(v, list):
                return v
    return []


class MekoCloud(Meko):
    backend = "meko-cloud"

    def __init__(self, settings: Settings, meter: Meter | None = None, http: httpx.AsyncClient | None = None,
                 concurrency: int = 4) -> None:
        if not settings.meko_api_key:
            raise MekoError("no_api_key", "set MEKO_API_KEY in .env")
        self.settings = settings
        self.meter = meter or Meter()
        self.headers = {"Authorization": f"Bearer {settings.meko_api_key}", "User-Agent": USER_AGENT}
        self.http = http or httpx.AsyncClient(base_url=settings.api_url, headers=self.headers, timeout=60)
        self.tools: dict[str, dict[str, Any]] = {}
        self._session: Any = None
        self._stack: contextlib.AsyncExitStack | None = None
        self._sem = asyncio.Semaphore(concurrency)

    # -- connection ------------------------------------------------------------------------
    async def connect(self) -> "MekoCloud":
        from mcp import ClientSession
        from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

        stack = contextlib.AsyncExitStack()
        client = await stack.enter_async_context(create_mcp_http_client(headers=self.headers))
        streams = await stack.enter_async_context(streamable_http_client(self.settings.mcp_url, http_client=client))
        session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
        await session.initialize()
        listed = await session.list_tools()
        self.tools = {t.name: (_get(t, "input_schema", "inputSchema") or {}) for t in listed.tools}
        self._session, self._stack = session, stack
        return self

    async def close(self) -> None:
        if self._stack:
            with contextlib.suppress(Exception):
                await self._stack.aclose()
        self._stack = self._session = None
        await self.http.aclose()

    def _filter(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        args = {k: v for k, v in args.items() if v is not None}
        schema = self.tools.get(tool)
        props = (schema or {}).get("properties")
        if props is None:
            return args
        return {k: v for k, v in args.items() if k in props}

    async def call(self, tool: str, **args: Any) -> Any:
        if self._session is None:
            await self.connect()
        self.meter.check(tool)
        sent = self._filter(tool, args)
        delay = 0.5
        for attempt in range(4):
            t0 = time.perf_counter()
            try:
                async with self._sem:
                    result = await self._session.call_tool(tool, sent)
                out = parse_tool_result(result)
                self.meter.record(tool, (time.perf_counter() - t0) * 1000, True)
                return out
            except MekoError as e:
                self.meter.record(tool, (time.perf_counter() - t0) * 1000, False)
                if attempt == 3 or not any(r in e.code or r in e.detail for r in RETRYABLE):
                    raise
            except Exception as e:  # transport failure: the call may not have run
                self.meter.record(tool, (time.perf_counter() - t0) * 1000, False)
                if attempt == 3:
                    raise MekoError("transport_error", f"{type(e).__name__}: {e}") from e
            await asyncio.sleep(delay)
            delay *= 2
        raise MekoError("unreachable")  # pragma: no cover

    async def rest(self, method: str, path: str, **kw: Any) -> Any:
        for attempt in range(3):
            r = await self.http.request(method, path, headers=self.headers, **kw)
            if r.status_code == 429 and attempt < 2:
                await asyncio.sleep(min(float(r.headers.get("Retry-After", "2")), 5.0))
                continue
            break
        try:
            body = r.json()
        except ValueError:
            raise MekoError(f"HTTP_{r.status_code}", r.text[:300]) from None
        err = body.get("error") if isinstance(body, dict) else None
        if r.status_code >= 400 or (err and body.get("data") is None):
            if isinstance(err, dict):
                raise MekoError(err.get("code", f"HTTP_{r.status_code}"), err.get("message", ""))
            raise MekoError(str(body.get("code") or f"HTTP_{r.status_code}"), str(err or body)[:300])
        return body.get("data") if isinstance(body, dict) and "data" in body else body

    # -- datapacks (REST: needs no conversation) -------------------------------------------
    async def ensure_datapack(self, name: str, description: str) -> str:
        data = await self.rest("GET", "/datapacks", params={"limit": 100, "name": name})
        items = data.get("items", []) if isinstance(data, dict) else data
        for it in items or []:
            if it.get("datapack_name") == name:
                return it["datapack_id"]
        try:
            made = await self.rest("POST", "/datapacks", json={"name": name, "description": description})
        except MekoError as e:
            if e.code != "CONFLICT":
                raise
            data = await self.rest("GET", "/datapacks", params={"limit": 100, "q": name})
            items = data.get("items", []) if isinstance(data, dict) else data
            return next(it["datapack_id"] for it in items if it.get("datapack_name") == name)
        return made["datapack_id"]

    async def describe(self, datapack_id: str) -> dict[str, Any]:
        return await self.rest("GET", f"/datapacks/{datapack_id}")

    # -- conversations ---------------------------------------------------------------------
    async def open_conversation(self, datapack_id, agent_id, session_id, title, metadata=None) -> str:
        out = await self.call("conversation_create", agent_id=agent_id, session_id=session_id,
                              datapack_id=datapack_id, title=title[:200],
                              metadata=json.dumps(metadata or {}))
        return str(_get(out, "id", "conversation_id"))

    async def add_message(self, datapack_id, conversation_id, agent_id, input, output, reasoning, plan, metadata):
        out = await self.call("conversation_add_message", conversation_id=conversation_id, input=input,
                              output=output, agent_id=agent_id, reasoning=reasoning, plan=plan,
                              metadata=json.dumps(metadata), datapack_id=datapack_id)
        return str(_get(out, "message_id", default=""))

    async def track_tokens(self, datapack_id, conversation_id, name, input_tokens, output_tokens, model,
                           message_id=None) -> None:
        await self.call("track_token_usage", conversation_id=conversation_id, name=name, input_tokens=input_tokens,
                        output_tokens=output_tokens, total_tokens=input_tokens + output_tokens, model=model,
                        message_id=message_id, datapack_id=datapack_id)

    # -- memory ----------------------------------------------------------------------------
    async def add_memory(self, datapack_id, conversation_id, agent_id, text, metadata=None) -> str:
        out = await self.call("memory_add", text=text, conversation_id=conversation_id, agent_id=agent_id,
                              metadata=json.dumps(metadata or {}), datapack_id=datapack_id)
        res = _results(out)
        return str(_get(res[0], "id", default="")) if res else ""

    @staticmethod
    def _memory_hits(items: list[dict[str, Any]]) -> list[MemoryHit]:
        out = []
        for it in items:
            text = _get(it, "memory", "text", "data", default="") or ""
            meta = it.get("metadata") or {}
            if isinstance(meta, str):
                with contextlib.suppress(ValueError):
                    meta = json.loads(meta)
            out.append(MemoryHit(str(it.get("id", "")), text, it.get("score"), it.get("agent_id"),
                                 meta if isinstance(meta, dict) else {}))
        return out

    async def search_memory(self, datapack_id, conversation_id, agent_id, query, limit=25) -> list[MemoryHit]:
        out = await self.call("memory_search", query=query, conversation_id=conversation_id, agent_id=agent_id,
                              limit=limit, datapack_id=datapack_id)
        return self._memory_hits(_results(out))

    async def context_search(self, datapack_id, conversation_id, agent_id, query, limit=10) -> ContextResult:
        out = await self.call("context_search", query=query, conversation_id=conversation_id, agent_id=agent_id,
                              datapack_id=datapack_id, limit=limit)
        buckets = _get(out, "results", default={}) or {}
        memory = self._memory_hits(_results(buckets.get("memory")))
        knowledge = []
        for it in _results(buckets.get("knowledge_base")):
            dist = it.get("distance")
            score = it.get("rerank_score") if it.get("rerank_score") is not None else (
                round(1 - dist, 4) if isinstance(dist, (int, float)) else None)
            knowledge.append(KnowledgeHit(str(it.get("id", "")), it.get("chunk_text") or it.get("text") or "",
                                          score, it.get("document_id")))
        conv = buckets.get("conversation") or {}
        hits = conv.get("hits", []) if isinstance(conv, dict) else (conv if isinstance(conv, list) else [])
        return ContextResult(memory, knowledge, hits, _get(out, "token_savings", default={}) or {})

    async def delete_agent_memories(self, datapack_id, conversation_id, agent_id) -> None:
        await self.call("memory_delete_all", conversation_id=conversation_id, agent_id=agent_id,
                        datapack_id=datapack_id)

    async def list_promoted(self, datapack_id, conversation_id, agent_id) -> list[dict[str, Any]]:
        out = await self.call("memory_get_all", conversation_id=conversation_id, agent_id=agent_id,
                              datapack_id=datapack_id, promoted=True)
        items = out.get("promoted_memories", []) if isinstance(out, dict) else []
        return [{"id": str(it.get("id")), "memory": _get(it, "data", "memory", "text", default="")} for it in items]

    async def list_learnings(self, datapack_id) -> list[dict[str, Any]]:
        data = await self.rest("GET", "/memories", params={"datapack_id": datapack_id, "scope": "learnings",
                                                           "page_size": 100})
        items = data.get("memories", []) if isinstance(data, dict) else (data or [])
        return [{"id": str(it.get("id")), "memory": _get(it, "memory", "text", "data", default=""),
                 "agent_id": it.get("agent_id")} for it in items]

    async def promote(self, datapack_id, conversation_id, agent_id, memory_ids) -> dict[str, Any]:
        try:
            return await self.call("memory_promote", conversation_id=conversation_id, memory_ids=memory_ids,
                                   agent_id=agent_id, datapack_id=datapack_id)
        except MekoError:
            return await self.rest("POST", "/promote-memories",
                                   json={"datapack_id": datapack_id, "memory_ids": memory_ids})

    async def keep_private(self, datapack_id, memory_ids) -> dict[str, Any]:
        return await self.rest("POST", "/keep-as-memory", json={"datapack_id": datapack_id, "memory_ids": memory_ids})

    # -- knowledge -------------------------------------------------------------------------
    async def upload_knowledge(self, datapack_id, path: Path) -> str:
        p = Path(path)
        ctype = "text/markdown" if p.suffix == ".md" else "text/plain"
        data = await self.rest("POST", f"/datapacks/{datapack_id}/knowledge-bases/upload",
                               files={"file": (p.name, p.read_bytes(), ctype)})
        return data.get("document_key", "")

    async def knowledge_ready(self, datapack_id, key) -> bool:
        try:
            data = await self.rest("GET", f"/datapacks/{datapack_id}/knowledge-bases/document-status",
                                   params={"document_key": key})
        except MekoError as e:
            if e.code == "NOT_FOUND":
                return False
            raise
        status = (data or {}).get("document_status")
        if status == "FAILED":
            raise MekoError("knowledge_index_failed", key)
        return status == "COMPLETED"

    # -- artifacts -------------------------------------------------------------------------
    async def put_artifact(self, datapack_id, conversation_id, agent_id, filename, content, content_type) -> str:
        out = await self.call("artifact_put", filename=filename, content_base64=base64.b64encode(content).decode(),
                              content_type=content_type, conversation_id=conversation_id, datapack_id=datapack_id,
                              agent_id=agent_id)
        return str(_get(out, "content_hash", default=hashlib.sha256(content).hexdigest()))

    async def get_artifact(self, datapack_id, conversation_id, agent_id, content_hash) -> bytes:
        out = await self.call("artifact_get", content_hash=content_hash, conversation_id=conversation_id,
                              datapack_id=datapack_id, agent_id=agent_id)
        b64 = _get(out, "content_base64", "content_base64_large")
        if b64:
            return base64.b64decode(b64)
        local = _get(out, "local_path", "path")
        if local:
            return Path(local).read_bytes()
        raise MekoError("ARTIFACT_NOT_FOUND", content_hash)
