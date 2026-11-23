"""MekoCloud: argument filtering, reply parsing, REST envelopes, and a real MCP round trip."""
import json
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from trailguard.config import Settings
from trailguard.meko.base import MekoError
from trailguard.meko.cloud import MekoCloud, parse_tool_result


def settings(**kw):
    base = dict(meko_api_key="mko_tkn_test", anthropic_api_key="", meko_backend="cloud", llm="heuristic",
                model="claude-opus-5-5", effort="medium", mcp_url="http://127.0.0.1:1/mcp",
                api_url="https://api.example/api/v1", runs_dir=Path("runs"))
    base.update(kw)
    return Settings(**base)


def text_result(payload, structured=True, is_error=False):
    s = payload if isinstance(payload, str) else json.dumps(payload)
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=s)],
                           structured_content={"result": s} if structured else None, is_error=is_error)


class FakeSession:
    def __init__(self, reply):
        self.reply = reply
        self.sent = []

    async def call_tool(self, name, arguments):
        self.sent.append((name, arguments))
        return self.reply(name, arguments) if callable(self.reply) else self.reply


def client_with(session, tools):
    c = MekoCloud(settings())
    c._session = session
    c.tools = tools
    return c


async def test_unknown_args_dropped():
    s = FakeSession(text_result({"results": []}))
    c = client_with(s, {"memory_search": {"properties": {"query": {}, "datapack_id": {}}}})
    await c.call("memory_search", query="q", datapack_id="dp", foo=1, limit=None)
    assert s.sent == [("memory_search", {"query": "q", "datapack_id": "dp"})]


async def test_inband_error_raises():
    s = FakeSession(text_result({"error": "datapack_access_denied", "detail": "x"}))
    c = client_with(s, {})
    with pytest.raises(MekoError) as e:
        await c.call("memory_search", query="q")
    assert e.value.code == "datapack_access_denied"


def test_parses_structured_result():
    assert parse_tool_result(text_result({"results": []})) == {"results": []}
    assert parse_tool_result(text_result({"a": 1}, structured=False)) == {"a": 1}


def test_plain_text_error_raises():
    with pytest.raises(MekoError):
        parse_tool_result(text_result("Error: metadata must be a valid JSON string.", structured=False))


def test_is_error_raises():
    with pytest.raises(MekoError):
        parse_tool_result(text_result("boom", is_error=True))


async def test_memory_add_returns_id_and_sends_json_metadata():
    s = FakeSession(text_result({"results": [{"id": "m1", "memory": "x", "event": "ADD"}]}))
    c = client_with(s, {})
    assert await c.add_memory("dp", "conv", "login-agent", "TG-SIGNAL v1 | x", {"k": 1}) == "m1"
    assert json.loads(s.sent[0][1]["metadata"]) == {"k": 1}


async def test_context_search_normalises_buckets():
    reply = {"results": {"memory": [{"id": "m1", "memory": "TG-SIGNAL v1 | type=x", "score": 0.8}],
                         "knowledge_base": {"results": [{"id": "k1", "chunk_text": "policy", "distance": 0.25}]},
                         "conversation": {"hits": [], "thread": None}},
             "token_savings": {"sent": 1200}}
    c = client_with(FakeSession(text_result(reply)), {})
    res = await c.context_search("dp", "conv", "sentinel", "q")
    assert res.memory[0].id == "m1" and res.knowledge[0].score == 0.75 and res.token_savings["sent"] == 1200


def rest_client(handler):
    s = settings()
    http = httpx.AsyncClient(base_url=s.api_url, transport=httpx.MockTransport(handler))
    return MekoCloud(s, http=http)


async def test_rest_promote_envelope():
    def handler(req):
        assert req.headers["authorization"] == "Bearer mko_tkn_test" and req.headers["user-agent"]
        return httpx.Response(200, json={"data": {"inserted_ids": ["m1"], "updated_ids": [], "not_found_ids": []}})

    c = rest_client(handler)
    out = await c.rest("POST", "/promote-memories", json={"datapack_id": "d", "memory_ids": ["m1"]})
    assert out["inserted_ids"] == ["m1"]


async def test_rest_error_envelope_raises():
    c = rest_client(lambda req: httpx.Response(409, json={"data": None, "error": {"code": "CONFLICT",
                                                                                  "message": "exists"}}))
    with pytest.raises(MekoError) as e:
        await c.rest("POST", "/datapacks", json={"name": "x"})
    assert e.value.code == "CONFLICT"


async def test_ensure_datapack_finds_existing():
    def handler(req):
        return httpx.Response(200, json={"data": {"items": [{"datapack_id": "dp-1", "datapack_name": "trailguard-signals"}],
                                                  "has_more": False}})

    assert await rest_client(handler).ensure_datapack("trailguard-signals", "") == "dp-1"


# -- real transport: a local MCP server that answers like Meko -------------------------------

def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def local_mcp():
    import uvicorn
    from mcp.server.mcpserver import MCPServer

    seen = {}
    srv = MCPServer("fake-meko")

    @srv.tool()
    def memory_add(text: str, conversation_id: str, agent_id: str = "", metadata: str = "{}",
                   datapack_id: str = "") -> str:
        seen["memory_add"] = dict(text=text, conversation_id=conversation_id, metadata=metadata)
        return json.dumps({"results": [{"id": "mem-1", "memory": text, "event": "ADD"}]})

    @srv.tool()
    def memory_search(query: str, conversation_id: str = "", agent_id: str = "", limit: int = 10,
                      datapack_id: str = "") -> str:
        if datapack_id == "denied":
            return json.dumps({"error": "datapack_access_denied", "detail": "no"})
        return json.dumps({"results": [{"id": "mem-1", "memory": f"hit for {query}", "score": 0.9}]})

    port = _free_port()
    app = srv.streamable_http_app()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp", seen
    server.should_exit = True
    th.join(timeout=5)


async def test_real_streamable_http_roundtrip(local_mcp):
    url, seen = local_mcp
    c = MekoCloud(settings(mcp_url=url))
    await c.connect()
    try:
        assert {"memory_add", "memory_search"} <= set(c.tools)
        mid = await c.add_memory("dp", "conv1", "login-agent", "TG-SIGNAL v1 | type=x | account=C1001", {"a": 1})
        assert mid == "mem-1" and seen["memory_add"]["conversation_id"] == "conv1"
        hits = await c.search_memory("dp", "conv1", "payments-agent", "C1001", limit=5)
        assert hits[0].text == "hit for C1001"
        with pytest.raises(MekoError):
            await c.search_memory("denied", "conv1", "x", "q")
        assert c.meter.calls["memory_search"] == 2
    finally:
        await c.close()
