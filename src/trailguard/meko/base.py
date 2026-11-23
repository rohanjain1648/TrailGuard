"""The Meko surface TrailGuard uses, as one async interface.

`MekoCloud` implements it over Meko Cloud's MCP server and Datapack API. `FakeMeko` is an
offline stand-in with the same behaviour for tests and keyless development. It is never
reported as Meko.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from trailguard.meko.meter import Meter


class MekoError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class BudgetExceeded(Exception):
    """The run's Meko call budget is spent; the engine stops cleanly."""


@dataclass
class MemoryHit:
    id: str
    text: str
    score: float | None = None
    agent_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class KnowledgeHit:
    id: str
    text: str
    score: float | None = None
    document_id: str | None = None


@dataclass
class ContextResult:
    memory: list[MemoryHit] = field(default_factory=list)
    knowledge: list[KnowledgeHit] = field(default_factory=list)
    conversation: list[dict[str, Any]] = field(default_factory=list)
    token_savings: dict[str, Any] = field(default_factory=dict)

    def texts(self) -> list[tuple[str, str, float | None]]:
        """(id, text, score) for memory and knowledge hits, memory first."""
        return [(h.id, h.text, h.score) for h in self.memory] + [(h.id, h.text, h.score) for h in self.knowledge]


class Meko(abc.ABC):
    backend: str = "?"
    meter: Meter

    @abc.abstractmethod
    async def ensure_datapack(self, name: str, description: str) -> str: ...

    @abc.abstractmethod
    async def open_conversation(self, datapack_id: str, agent_id: str, session_id: str, title: str,
                                metadata: dict | None = None) -> str: ...

    @abc.abstractmethod
    async def add_memory(self, datapack_id: str, conversation_id: str, agent_id: str, text: str,
                         metadata: dict | None = None) -> str: ...

    @abc.abstractmethod
    async def search_memory(self, datapack_id: str, conversation_id: str, agent_id: str, query: str,
                            limit: int = 25) -> list[MemoryHit]: ...

    @abc.abstractmethod
    async def context_search(self, datapack_id: str, conversation_id: str, agent_id: str, query: str,
                             limit: int = 10) -> ContextResult: ...

    @abc.abstractmethod
    async def add_message(self, datapack_id: str, conversation_id: str, agent_id: str, input: str, output: str,
                          reasoning: str, plan: list[str], metadata: dict) -> str: ...

    @abc.abstractmethod
    async def track_tokens(self, datapack_id: str, conversation_id: str, name: str, input_tokens: int,
                           output_tokens: int, model: str, message_id: str | None = None) -> None: ...

    @abc.abstractmethod
    async def delete_agent_memories(self, datapack_id: str, conversation_id: str, agent_id: str) -> None: ...

    @abc.abstractmethod
    async def list_learnings(self, datapack_id: str) -> list[dict[str, Any]]: ...

    @abc.abstractmethod
    async def list_promoted(self, datapack_id: str, conversation_id: str, agent_id: str) -> list[dict[str, Any]]:
        """Collective memory: memories promoted into the datapack's shared knowledge. [{id, memory}]"""

    @abc.abstractmethod
    async def promote(self, datapack_id: str, conversation_id: str, agent_id: str,
                      memory_ids: list[str]) -> dict[str, Any]: ...

    @abc.abstractmethod
    async def keep_private(self, datapack_id: str, memory_ids: list[str]) -> dict[str, Any]: ...

    @abc.abstractmethod
    async def put_artifact(self, datapack_id: str, conversation_id: str, agent_id: str, filename: str,
                           content: bytes, content_type: str) -> str: ...

    @abc.abstractmethod
    async def get_artifact(self, datapack_id: str, conversation_id: str, agent_id: str,
                           content_hash: str) -> bytes: ...

    @abc.abstractmethod
    async def upload_knowledge(self, datapack_id: str, path: Path) -> str: ...

    @abc.abstractmethod
    async def knowledge_ready(self, datapack_id: str, key: str) -> bool: ...

    @abc.abstractmethod
    async def describe(self, datapack_id: str) -> dict[str, Any]: ...

    async def close(self) -> None:
        return None
