"""Sandboxed file read and write tools preventing directory traversal."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from guardagent.schemas.action import ActionTier, ToolResult
from guardagent.tools.base import BaseTool


def _resolve_sandbox_path(sandbox_dir: Path, requested_path: str) -> Path:
    """Resolve and verify that the target path strictly resides within the sandbox directory."""
    clean_req = requested_path.strip().lstrip("/\\")
    resolved_sandbox = sandbox_dir.resolve()
    target = (resolved_sandbox / clean_req).resolve()

    if not target.is_relative_to(resolved_sandbox):
        raise PermissionError(f"Access denied: path traversal outside sandbox detected for '{requested_path}'")

    return target


class ReadFileArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Relative file path inside the sandbox directory")


class ReadFileTool(BaseTool):
    """Reads file contents from within the sandboxed storage directory."""

    name = "read_file"
    description = "Read contents of a text file located inside the sandbox directory."
    tier = ActionTier.TIER_1_READ
    args_schema = ReadFileArgs

    def __init__(self, sandbox_dir: str | Path = "data/sandbox") -> None:
        self.sandbox_dir = Path(sandbox_dir)
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

    def execute(self, **kwargs: Any) -> ToolResult:
        rel_path = str(kwargs.get("path", "")).strip()
        if not rel_path:
            return ToolResult(tool_name=self.name, output="", success=False, error="File path cannot be empty")

        try:
            target = _resolve_sandbox_path(self.sandbox_dir, rel_path)
            if not target.exists():
                return ToolResult(
                    tool_name=self.name,
                    output="",
                    success=False,
                    error=f"File not found: {rel_path}",
                )

            content = target.read_text(encoding="utf-8")
            return ToolResult(tool_name=self.name, output=content, success=True)
        except Exception as err:
            return ToolResult(tool_name=self.name, output="", success=False, error=str(err))


class WriteFileArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(..., description="Relative destination file path inside sandbox")
    content: str = Field(..., description="Text content to write")
    append: bool = Field(default=False, description="Whether to append rather than overwrite")


class WriteFileTool(BaseTool):
    """Writes or appends text to a sandboxed file."""

    name = "write_file"
    description = "Write or append text content to a file inside the sandbox directory."
    tier = ActionTier.TIER_2_MUTATION
    args_schema = WriteFileArgs

    def __init__(self, sandbox_dir: str | Path = "data/sandbox") -> None:
        self.sandbox_dir = Path(sandbox_dir)
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

    def execute(self, **kwargs: Any) -> ToolResult:
        rel_path = str(kwargs.get("path", "")).strip()
        content = str(kwargs.get("content", ""))
        append_mode = bool(kwargs.get("append", False))

        if not rel_path:
            return ToolResult(tool_name=self.name, output="", success=False, error="File path cannot be empty")

        try:
            target = _resolve_sandbox_path(self.sandbox_dir, rel_path)
            target.parent.mkdir(parents=True, exist_ok=True)

            mode = "a" if append_mode else "w"
            with target.open(mode, encoding="utf-8") as f:
                f.write(content)

            action = "Appended to" if append_mode else "Wrote"
            return ToolResult(
                tool_name=self.name,
                output=f"Successfully {action.lower()} {len(content)} characters to {rel_path}.",
                success=True,
            )
        except Exception as err:
            return ToolResult(tool_name=self.name, output="", success=False, error=str(err))
