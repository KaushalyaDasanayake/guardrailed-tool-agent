"""Base class and registry for executable agent tools."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

from guardagent.schemas.action import ActionTier, ToolResult


class BaseTool(ABC):
    """Abstract base class for all agent tools."""

    name: str
    description: str
    tier: ActionTier = ActionTier.TIER_1_READ
    args_schema: type[BaseModel] | None = None

    @abstractmethod
    def execute(self, **kwargs: Any) -> ToolResult:
        """Execute the tool action with validated parameters."""
        pass


class ToolRegistry:
    """Registry maintaining available tools and parameter schemas."""

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool instance."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool:
        """Retrieve a tool by name."""
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' is not registered. Available tools: {list(self._tools.keys())}")
        return self._tools[name]

    def has(self, name: str) -> bool:
        """Check if tool name exists."""
        return name in self._tools

    def list_tools(self) -> list[BaseTool]:
        """List all registered tools."""
        return list(self._tools.values())

    def get_descriptions(self) -> str:
        """Format tools and argument descriptions for prompt inclusion."""
        lines: list[str] = []
        for tool in self._tools.values():
            schema_str = ""
            if tool.args_schema:
                fields = tool.args_schema.model_fields
                params = [f"{k}: {v.annotation.__name__ if hasattr(v.annotation, '__name__') else str(v.annotation)}" for k, v in fields.items()]
                schema_str = f"({', '.join(params)})"
            lines.append(f"- {tool.name}{schema_str} [Tier: {tool.tier.value}]: {tool.description}")
        return "\n".join(lines)
