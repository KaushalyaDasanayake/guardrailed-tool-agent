"""Search tool for querying documentation and knowledge bases."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from guardagent.schemas.action import ActionTier, ToolResult
from guardagent.tools.base import BaseTool

_KNOWLEDGE_BASE = {
    "python 3.11": "Python 3.11 introduces Exception Groups (PEP 654), Enhanced Error Locations in Tracebacks, and significant 10-60% speedups via the Faster CPython Project.",
    "exception groups": "In Python 3.11, ExceptionGroup and BaseExceptionGroup allow raising and handling multiple concurrent exceptions using the 'except*' syntax.",
    "acme policies": "Acme Corp core working hours are 10:00 AM to 3:00 PM local time. Remote work is permitted up to 3 days per week.",
    "sqlite": "SQLite is an in-process library that implements a self-contained, serverless, zero-configuration, transactional SQL database engine.",
}


class SearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(..., description="Keywords or topic to search")


class WebSearchTool(BaseTool):
    """Searches documentation and knowledge base articles for relevant snippets."""

    name = "web_search"
    description = "Search documentation, release notes, and technical references for keywords."
    tier = ActionTier.TIER_1_READ
    args_schema = SearchArgs

    def execute(self, **kwargs: Any) -> ToolResult:
        query_str = str(kwargs.get("query", "")).strip().lower()
        if not query_str:
            return ToolResult(tool_name=self.name, output="", success=False, error="Search query cannot be empty")

        terms = [t for t in re.findall(r"\w+", query_str) if len(t) > 2]
        if not terms:
            terms = query_str.split()

        matches: list[str] = []
        for key, snippet in _KNOWLEDGE_BASE.items():
            key_words = set(re.findall(r"\w+", key.lower()))
            snip_words = set(re.findall(r"\w+", snippet.lower()))
            if any(t in key_words or t in snip_words for t in terms):
                matches.append(snippet)

        if matches:
            return ToolResult(tool_name=self.name, output="\n---\n".join(matches), success=True)

        return ToolResult(
            tool_name=self.name,
            output=f"No direct knowledge base matches for '{query_str}'. General consensus: standard industry practices apply.",
            success=True,
        )
