"""Dashboard: FastAPI + Server-Sent Events over the same engine the CLI uses."""
from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from trailguard.agents.curator import Curator
from trailguard.config import MODES, Settings
from trailguard.engine import RunConfig, Runtime, RunResult, load_patterns, run, scope_for
from trailguard.explain import card
from trailguard.metrics import compute
from trailguard.report import BACKEND_LABEL, audit_markdown, headlines
from trailguard.sim import attack_instances, generate
from trailguard.trace import read

STATIC = Path(__file__).parent / "static"


class RunRequest(BaseModel):
    mode: str = "meko"
    seed: int = 1
    epoch: int = 1
    events: int = 600
    pace: float = 25.0


class Ids(BaseModel):
    ids: list[str] | None = None
    all: bool = False


class LearnRequest(BaseModel):
    run_id: str
    approve: bool = False


class LiveRun:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.backlog: list[tuple[str, dict]] = []
        self.subscribers: list[asyncio.Queue] = []
        self.task: asyncio.Task | None = None
        self.done = False
        self.error: str | None = None

    def publish(self, kind: str, payload: dict) -> None:
        self.backlog.append((kind, payload))
        for q in self.subscribers:
            q.put_nowait((kind, payload))


def create_app(settings: Settings | None = None) -> FastAPI:
    from contextlib import asynccontextmanager

    s = settings or Settings.load()
    state: dict[str, Any] = {"rt": None, "lock": asyncio.Lock(), "runs": {}, "active": None}

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        if state["rt"]:
            await state["rt"].close()

    app = FastAPI(title="TrailGuard", lifespan=lifespan)

    async def runtime() -> Runtime:
        if state["rt"] is None:
            state["rt"] = await Runtime.create(s)
        return state["rt"]

    def run_dir(run_id: str) -> Path:
        d = s.runs_dir / run_id
        if not (d / "result.json").exists() and run_id not in state["runs"]:
            raise HTTPException(404, f"run {run_id} not found")
        return d

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        rt = await runtime()
        counts = {}
        for k, dp in rt.datapacks.items():
            try:
                d = await rt.meko.describe(dp)
                counts[k] = {x: d.get(x) for x in ("memory_count", "learnings_count", "collective_memory_count",
                                                     "knowledge_count", "conversation_count")}
            except Exception as e:  # noqa: BLE001 - status must not fail
                counts[k] = {"error": str(e)}
        runs = sorted((p.parent.name for p in s.runs_dir.glob("*/result.json")
                       if not p.parent.name.startswith("bench")), key=lambda n: (s.runs_dir / n).stat().st_mtime,
                      reverse=True)[:20]
        return {"backend": rt.backend, "backend_label": BACKEND_LABEL.get(rt.backend, rt.backend),
                "decider": rt.decider.label, "datapacks": rt.datapacks, "counts": counts, "modes": list(MODES),
                "active": state["active"], "runs": runs}

    @app.post("/api/runs")
    async def start(req: RunRequest) -> dict[str, str]:
        if req.mode not in MODES:
            raise HTTPException(400, f"mode must be one of {MODES}")
        if state["active"] and not state["runs"][state["active"]].done:
            raise HTTPException(409, f"run {state['active']} is still running")
        rt = await runtime()
        run_id = f"{req.mode.replace('+', '-')}-s{req.seed}-e{req.epoch}-{datetime.now(timezone.utc):%H%M%S}"
        live = LiveRun(run_id)
        state["runs"][run_id] = live
        state["active"] = run_id
        events = generate(req.seed, req.epoch, req.events)
        n_attacks = len(attack_instances(events))
        cfg = RunConfig(run_id, req.mode, req.seed, req.epoch, req.events, pace=req.pace)

        async def go() -> None:
            async with state["lock"]:
                try:
                    live.publish("meta", {"attacks": n_attacks, "events": len(events)})
                    res = await run(events, cfg, rt, emit=live.publish)
                    live.publish("metrics", compute(events, res))
                    (s.runs_dir / run_id / "audit.md").write_text(audit_markdown(s.runs_dir / run_id),
                                                                  encoding="utf-8")
                except Exception as e:  # noqa: BLE001 - surface to the UI
                    live.error = f"{type(e).__name__}: {e}"
                    live.publish("error", {"detail": live.error})
                finally:
                    live.done = True
                    live.publish("closed", {})

        live.task = asyncio.create_task(go())
        return {"run_id": run_id}

    @app.get("/api/runs/{run_id}/stream")
    async def stream(run_id: str) -> StreamingResponse:
        live = state["runs"].get(run_id)
        if live is None:
            raise HTTPException(404, "not a live run")
        q: asyncio.Queue = asyncio.Queue()
        backlog = list(live.backlog)
        live.subscribers.append(q)

        async def gen():
            try:
                for kind, payload in backlog:
                    yield f"event: {kind}\ndata: {json.dumps(payload, default=str)}\n\n"
                    if kind == "closed":
                        return
                while True:
                    kind, payload = await q.get()
                    yield f"event: {kind}\ndata: {json.dumps(payload, default=str)}\n\n"
                    if kind == "closed":
                        return
            finally:
                live.subscribers.remove(q)

        return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    def load(run_id: str) -> tuple[RunResult, list]:
        d = run_dir(run_id)
        data = json.loads((d / "result.json").read_text(encoding="utf-8"))
        res = RunResult(**data)
        c = res.cfg
        return res, generate(c["seed"], c["epoch"], c["n_events"])

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str) -> dict[str, Any]:
        res, events = load(run_id)
        return {"result": {k: v for k, v in res.to_dict().items() if k != "decisions"},
                "metrics": compute(events, res)}

    @app.get("/api/runs/{run_id}/decisions")
    async def decisions(run_id: str) -> list[dict[str, Any]]:
        return [{"n": d["n"], "ts": d["ts"], "account": d["account"], "gate": d["gate"], "risk": d["risk"],
                 "decision": d["decision"], "outcome": d["outcome"], "attack": bool(d["truth"].get("attack_id"))}
                for d in read(run_dir(run_id), "decisions.jsonl")]

    @app.get("/api/runs/{run_id}/decisions/{n}")
    async def decision(run_id: str, n: int) -> dict[str, Any]:
        for d in read(run_dir(run_id), "decisions.jsonl"):
            if d["n"] == n:
                return {"card": card(d), "record": d}
        raise HTTPException(404, "decision not found")

    @app.get("/api/runs/{run_id}/audit", response_class=PlainTextResponse)
    async def audit(run_id: str) -> str:
        return audit_markdown(run_dir(run_id))

    @app.get("/api/learnings")
    async def learnings() -> dict[str, Any]:
        rt = await runtime()
        pending = await Curator(scope_for(rt, "curator", "review")).pending()
        approved = [p.to_dict() for p in await load_patterns(scope_for(rt, "sentinel", "review"))]
        return {"pending": pending, "approved": approved}

    @app.post("/api/learn")
    async def learn(req: LearnRequest) -> dict[str, Any]:
        rt = await runtime()
        res, events = load(req.run_id)
        cur = Curator(scope_for(rt, "curator", req.run_id))
        pats = await cur.learn(events, res, res.cfg["epoch"])
        out: dict[str, Any] = {"learned": [p.to_dict() for p in pats]}
        if req.approve:
            out["promoted"] = await cur.approve([p.memory_id for p in pats])
        return out

    @app.post("/api/learnings/approve")
    async def approve(req: Ids) -> dict[str, Any]:
        rt = await runtime()
        cur = Curator(scope_for(rt, "curator", "review"))
        return await (cur.approve("all") if req.all else cur.approve(req.ids or []))

    @app.post("/api/learnings/reject")
    async def reject(req: Ids) -> dict[str, Any]:
        rt = await runtime()
        return await Curator(scope_for(rt, "curator", "review")).reject(req.ids or [])

    @app.get("/api/bench")
    async def bench() -> dict[str, Any]:
        files = sorted(s.runs_dir.glob("bench-*/results.json"), key=lambda p: p.stat().st_mtime)
        if not files:
            return {"available": False}
        b = json.loads(files[-1].read_text(encoding="utf-8"))
        return {"available": True, "headlines": headlines(b), **b}

    @app.post("/api/bench")
    async def bench_run(seeds: str = "1-2", events: int = 1000) -> dict[str, Any]:
        from trailguard.bench import run_bench
        from trailguard.cli import _seeds
        from trailguard.meko.fake import FakeMeko

        if s.meko_backend != "fake":
            raise HTTPException(400, "run the Meko Cloud benchmark from the CLI: trailguard bench")
        b = await run_bench(replace(s), _seeds(seeds), events, meko_factory=lambda _seed: FakeMeko(None))
        return {"available": True, "headlines": headlines(b), **b}

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app
