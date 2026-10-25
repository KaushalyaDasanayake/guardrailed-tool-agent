"""SQLite database query execution tool."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from guardagent.schemas.action import ActionTier, ToolResult
from guardagent.tools.base import BaseTool


class DatabaseQueryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(..., description="SQL statement to execute against company database")


class DatabaseTool(BaseTool):
    """Executes SQL queries against the company SQLite database."""

    name = "query_database"
    description = "Execute SQL queries on the company database (tables: employees)."
    tier = ActionTier.TIER_1_READ  # Default tier; specific statements are evaluated by guardrails
    args_schema = DatabaseQueryArgs

    def __init__(self, db_path: str | Path = "data/company.db") -> None:
        self.db_path = Path(db_path)

    def execute(self, **kwargs: Any) -> ToolResult:
        query_str = str(kwargs.get("query", "")).strip()
        if not query_str:
            return ToolResult(tool_name=self.name, output="", success=False, error="Empty SQL query provided")

        if not self.db_path.exists():
            return ToolResult(
                tool_name=self.name,
                output="",
                success=False,
                error=f"Database file not found at: {self.db_path}",
            )

        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(query_str)

            if cur.description:
                rows = [dict(row) for row in cur.fetchall()]
                return ToolResult(tool_name=self.name, output=json.dumps(rows, default=str), success=True)

            conn.commit()
            affected = cur.rowcount
            return ToolResult(
                tool_name=self.name,
                output=f"Statement executed successfully. Rows affected: {affected}",
                success=True,
            )
        except Exception as err:
            return ToolResult(tool_name=self.name, output="", success=False, error=f"Database error: {err}")
        finally:
            conn.close()
