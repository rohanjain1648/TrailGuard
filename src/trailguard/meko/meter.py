"""Per-run accounting of Meko calls, with a budget that protects the free-tier quota."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

RETRIEVAL_TOOLS = {"context_search", "memory_search", "knowledgebase_search"}
MESSAGE_TOOLS = {"conversation_add_message"}


class Meter:
    def __init__(self, max_retrievals: int = 400, max_messages: int = 120) -> None:
        self.max_retrievals = max_retrievals
        self.max_messages = max_messages
        self.calls: dict[str, int] = defaultdict(int)
        self.errors: dict[str, int] = defaultdict(int)
        self.ms: dict[str, float] = defaultdict(float)

    def _count(self, tools: set[str]) -> int:
        return sum(self.calls[t] for t in tools)

    def check(self, tool: str) -> None:
        from trailguard.meko.base import BudgetExceeded

        if tool in RETRIEVAL_TOOLS and self._count(RETRIEVAL_TOOLS) >= self.max_retrievals:
            raise BudgetExceeded(f"retrieval budget of {self.max_retrievals} spent")
        if tool in MESSAGE_TOOLS and self._count(MESSAGE_TOOLS) >= self.max_messages:
            raise BudgetExceeded(f"conversation message budget of {self.max_messages} spent")

    def record(self, tool: str, ms: float, ok: bool) -> None:
        self.calls[tool] += 1
        self.ms[tool] += ms
        if not ok:
            self.errors[tool] += 1

    def reset(self) -> None:
        self.calls.clear()
        self.errors.clear()
        self.ms.clear()

    def summary(self) -> dict[str, Any]:
        total = sum(self.calls.values())
        return {
            "total_calls": total,
            "retrievals": self._count(RETRIEVAL_TOOLS),
            "messages": self._count(MESSAGE_TOOLS),
            "by_tool": dict(sorted(self.calls.items())),
            "errors": dict(self.errors),
            "avg_ms": {t: round(self.ms[t] / n, 1) for t, n in self.calls.items() if n},
        }
