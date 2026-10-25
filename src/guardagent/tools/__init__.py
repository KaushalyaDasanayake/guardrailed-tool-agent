"""Tool definitions and registry initialization."""

from __future__ import annotations

from pathlib import Path

from guardagent.tools.base import BaseTool, ToolRegistry
from guardagent.tools.calculator import CalculatorTool
from guardagent.tools.database import DatabaseTool
from guardagent.tools.file_io import ReadFileTool, WriteFileTool
from guardagent.tools.search import WebSearchTool


def get_default_registry(
    db_path: str | Path = "data/company.db",
    sandbox_dir: str | Path = "data/sandbox",
) -> ToolRegistry:
    """Create and return registry populated with all standard built-in tools."""
    registry = ToolRegistry()
    registry.register(CalculatorTool())
    registry.register(DatabaseTool(db_path=db_path))
    registry.register(ReadFileTool(sandbox_dir=sandbox_dir))
    registry.register(WriteFileTool(sandbox_dir=sandbox_dir))
    registry.register(WebSearchTool())
    return registry


__all__ = [
    "BaseTool",
    "ToolRegistry",
    "CalculatorTool",
    "DatabaseTool",
    "ReadFileTool",
    "WriteFileTool",
    "WebSearchTool",
    "get_default_registry",
]
