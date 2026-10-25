"""Safe mathematical calculation tool using AST parsing."""

from __future__ import annotations

import ast
import operator
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from guardagent.schemas.action import ActionTier, ToolResult
from guardagent.tools.base import BaseTool

_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _safe_eval(node: ast.AST) -> float | int:
    """Recursively evaluate only math operator nodes."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp):
        left = _safe_eval(node.left)
        right = _safe_eval(node.right)
        op_type = type(node.op)
        if op_type in _OPERATORS:
            if op_type in (ast.Div, ast.FloorDiv, ast.Mod) and right == 0:
                raise ZeroDivisionError("Division by zero")
            if op_type is ast.Pow and (right > 100 or left > 1000):
                raise ValueError("Exponentiation values too large")
            return _OPERATORS[op_type](left, right)
    if isinstance(node, ast.UnaryOp):
        operand = _safe_eval(node.operand)
        op_type = type(node.op)
        if op_type in _OPERATORS:
            return _OPERATORS[op_type](operand)

    raise ValueError(f"Unsupported AST node or expression element: {type(node).__name__}")


class CalculateArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expression: str = Field(..., description="Math expression to evaluate, e.g. '45 * 12 + 180'")


class CalculatorTool(BaseTool):
    """Evaluates mathematical expressions safely without arbitrary code execution."""

    name = "calculate"
    description = "Perform arithmetic calculations safely. Input must be a valid math string."
    tier = ActionTier.TIER_1_READ
    args_schema = CalculateArgs

    def execute(self, **kwargs: Any) -> ToolResult:
        raw_expr = str(kwargs.get("expression", "")).strip()
        if not raw_expr:
            return ToolResult(tool_name=self.name, output="", success=False, error="Empty expression provided")

        try:
            parsed = ast.parse(raw_expr, mode="eval")
            res = _safe_eval(parsed.body)
            # Format clean representation (e.g. 540 instead of 540.0 if integer)
            out_str = str(int(res)) if isinstance(res, float) and res.is_integer() else str(res)
            return ToolResult(tool_name=self.name, output=out_str, success=True)
        except Exception as err:
            return ToolResult(tool_name=self.name, output="", success=False, error=str(err))
