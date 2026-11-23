"""Per-agent view of Meko: fixed agent_id, its own conversations, and a datapack allowlist.

Meko keys are account-scoped, so with one key every agent could reach every datapack.
TrailGuard enforces least privilege here: e.g. channel agents may write signals but only
read confirmed patterns; only the Curator writes patterns.
"""
from __future__ import annotations

from typing import Any

from trailguard.meko.base import ContextResult, Meko, MemoryHit


class AgentScope:
    def __init__(self, meko: Meko, agent_id: str, datapacks: dict[str, str], read: set[str], write: set[str],
                 session: str) -> None:
        self.meko = meko
        self.agent_id = agent_id
        self.datapacks = datapacks
        self.read = set(read) | set(write)
        self.write = set(write)
        self.session = session
        self._convs: dict[tuple[str, str], str] = {}

    def _id(self, key: str, need: set[str]) -> str:
        if key not in need or key not in self.datapacks:
            verb = "write" if need is self.write else "read"
            raise PermissionError(f"{self.agent_id} may not {verb} datapack '{key}'")
        return self.datapacks[key]

    async def conversation(self, key: str, thread: str = "main") -> str:
        dp = self._id(key, self.read)
        k = (key, thread)
        if k not in self._convs:
            title = f"{self.agent_id} · {thread}" if thread != "main" else f"{self.agent_id} · run {self.session}"
            self._convs[k] = await self.meko.open_conversation(
                dp, self.agent_id, f"{self.session}:{self.agent_id}:{thread}", title,
                {"run_id": self.session, "agent": self.agent_id, "thread": thread})
        return self._convs[k]

    async def add_memory(self, key: str, text: str, metadata: dict | None = None) -> str:
        dp = self._id(key, self.write)
        return await self.meko.add_memory(dp, await self.conversation(key), self.agent_id, text, metadata)

    async def search_memory(self, key: str, query: str, limit: int = 25) -> list[MemoryHit]:
        dp = self._id(key, self.read)
        return await self.meko.search_memory(dp, await self.conversation(key), self.agent_id, query, limit)

    async def context_search(self, key: str, query: str, limit: int = 10) -> ContextResult:
        dp = self._id(key, self.read)
        return await self.meko.context_search(dp, await self.conversation(key), self.agent_id, query, limit)

    async def add_message(self, key: str, thread: str, input: str, output: str, reasoning: str, plan: list[str],
                          metadata: dict[str, Any]) -> tuple[str, str]:
        dp = self._id(key, self.write)
        conv = await self.conversation(key, thread)
        mid = await self.meko.add_message(dp, conv, self.agent_id, input, output, reasoning, plan, metadata)
        return conv, mid

    async def track_tokens(self, key: str, thread: str, name: str, tokens_in: int, tokens_out: int, model: str,
                           message_id: str | None = None) -> None:
        dp = self._id(key, self.write)
        await self.meko.track_tokens(dp, await self.conversation(key, thread), name, tokens_in, tokens_out, model,
                                     message_id)

    async def put_artifact(self, key: str, filename: str, content: bytes, content_type: str) -> str:
        dp = self._id(key, self.write)
        return await self.meko.put_artifact(dp, await self.conversation(key), self.agent_id, filename, content,
                                            content_type)

    async def get_artifact(self, key: str, content_hash: str) -> bytes:
        dp = self._id(key, self.read)
        return await self.meko.get_artifact(dp, await self.conversation(key), self.agent_id, content_hash)

    async def list_promoted(self, key: str) -> list[dict[str, Any]]:
        dp = self._id(key, self.read)
        return await self.meko.list_promoted(dp, await self.conversation(key), self.agent_id)

    async def promote(self, key: str, memory_ids: list[str]) -> dict[str, Any]:
        dp = self._id(key, self.write)
        return await self.meko.promote(dp, await self.conversation(key), self.agent_id, memory_ids)

    async def delete_own_memories(self, key: str) -> None:
        dp = self._id(key, self.write)
        await self.meko.delete_agent_memories(dp, await self.conversation(key), self.agent_id)
