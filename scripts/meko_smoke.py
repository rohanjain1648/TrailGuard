"""Live check of the Meko Cloud behaviour TrailGuard depends on. Run before any benchmark:

    uv run python scripts/meko_smoke.py

It uses the trailguard-signals datapack (creating it if needed; no extra datapack slot),
writes as agent ``smoke-test`` only, and deletes that agent's memories at the end.
Costs roughly: 6 retrievals, 1 conversation message.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid

from trailguard.config import SIGNALS_DATAPACK, Settings
from trailguard.meko.cloud import MekoCloud

EXPECTED_TOOLS = {"context_search", "memory_add", "memory_search", "memory_get_all", "memory_promote",
                  "memory_delete_all", "conversation_create", "conversation_add_message", "track_token_usage",
                  "knowledgebase_search", "knowledgebase_upload_document", "datapack_search", "artifact_put",
                  "artifact_get"}
AGENT = "smoke-test"


def check(results: list, name: str, ok: bool, detail: str = "") -> None:
    results.append({"check": name, "ok": ok, "detail": detail})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))


async def main() -> int:
    s = Settings.load()
    if not s.meko_api_key:
        print("MEKO_API_KEY is not set. Put it in .env (see .env.example).")
        return 2
    out: list = []
    m = await MekoCloud(s).connect()
    try:
        missing = EXPECTED_TOOLS - set(m.tools)
        check(out, "tools/list", not missing, f"{len(m.tools)} tools" + (f", missing {sorted(missing)}" if missing else ""))
        for t in ("memory_add", "memory_search", "context_search", "conversation_add_message", "memory_get_all"):
            props = sorted((m.tools.get(t) or {}).get("properties", {}))
            print(f"      {t}({', '.join(props)})")
        dp = await m.ensure_datapack(SIGNALS_DATAPACK, "TrailGuard: raw risk signals and decision traces")
        check(out, "datapack", bool(dp), dp)
        conv = await m.open_conversation(dp, AGENT, f"smoke-{uuid.uuid4().hex[:8]}", "TrailGuard smoke test")
        check(out, "conversation_create", bool(conv), conv)
        marker = f"C9{uuid.uuid4().int % 1000:03d}"
        text = (f"TG-SIGNAL v1 | type=phone_change | account={marker} | sev=medium | w=20 | device=- | ip=45.83.1.9 "
                f"| payee=- | ts=2026-10-01T00:00:00+00:00 | agent={AGENT} | event=SMOKE | run=smoke | note=smoke test")
        t0 = time.perf_counter()
        mid = await m.add_memory(dp, conv, AGENT, text, {"kind": "smoke"})
        check(out, "memory_add returns id", bool(mid), f"{mid} in {1000 * (time.perf_counter() - t0):.0f} ms")
        found, waited = None, 0.0
        t0 = time.perf_counter()
        while waited < 30:
            hits = await m.search_memory(dp, conv, "payments-agent", f"TG-SIGNAL account={marker}", limit=5)
            found = next((h for h in hits if marker in h.text), None)
            if found:
                break
            await asyncio.sleep(2)
            waited = time.perf_counter() - t0
        check(out, "read-after-write by another agent", found is not None, f"{waited:.1f}s")
        if found:
            check(out, "memory text kept verbatim", found.text.strip() == text,
                  "" if found.text.strip() == text else f"came back as: {found.text[:160]}")
        res = await m.context_search(dp, conv, "sentinel", f"risk signals for account {marker}")
        check(out, "context_search buckets", True, f"memory={len(res.memory)} knowledge={len(res.knowledge)} "
                                                   f"conversation={len(res.conversation)} savings={res.token_savings}")
        msg = await m.add_message(dp, conv, AGENT, "smoke input", '{"decision":"ALLOW"}', "smoke reasoning",
                                  ["step one", "step two"], {"kind": "smoke"})
        check(out, "conversation_add_message (decision trace)", bool(msg), msg)
        await m.track_tokens(dp, conv, "smoke", 10, 2, "claude-opus-5-5", msg)
        check(out, "track_token_usage", True)
        h = await m.put_artifact(dp, conv, AGENT, "smoke.txt", b"trailguard smoke", "text/plain")
        back = await m.get_artifact(dp, conv, AGENT, h)
        check(out, "artifact round trip", back == b"trailguard smoke", h[:16])
        promoted = await m.list_promoted(dp, conv, AGENT)
        check(out, "memory_get_all(promoted)", isinstance(promoted, list), f"{len(promoted)} promoted")
        await m.delete_agent_memories(dp, conv, AGENT)
        check(out, "cleanup (memory_delete_all for smoke-test)", True)
    except Exception as e:  # report, don't hide
        check(out, "unexpected error", False, f"{type(e).__name__}: {e}")
    finally:
        print(f"\nMeko calls: {json.dumps(m.meter.summary()['by_tool'])}")
        await m.close()
    s.runs_dir.mkdir(parents=True, exist_ok=True)
    (s.runs_dir / "smoke.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    failed = [r for r in out if not r["ok"]]
    print(f"\n{len(out) - len(failed)}/{len(out)} checks passed. Details: {s.runs_dir / 'smoke.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
