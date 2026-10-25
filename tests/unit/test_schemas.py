"""Unit tests for action, tool, and agent schemas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from guardagent.schemas.action import (
    ActionTier,
    AgentResponse,
    AgentStep,
    ApprovalStatus,
    ToolCall,
    ToolResult,
)


def test_tool_call_valid():
    call = ToolCall(
        tool_name="calculate",
        arguments={"expression": "12 * 8"},
        tier=ActionTier.TIER_1_READ,
        justification="User asked for calculation",
    )
    assert call.tool_name == "calculate"
    assert call.tier == ActionTier.TIER_1_READ


def test_tool_call_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        ToolCall(
            tool_name="calculate",
            arguments={},
            unknown_arg="extra",
        )


def test_agent_step_and_response():
    step = AgentStep(
        step_number=1,
        thought="Need to compute numbers",
        tool_call=ToolCall(tool_name="calculate", arguments={"expression": "5+5"}),
        approval_status=ApprovalStatus.AUTO_APPROVED,
        tool_result=ToolResult(tool_name="calculate", output="10"),
        latency_ms=12.5,
    )
    assert step.step_number == 1
    assert step.tool_result.output == "10"

    resp = AgentResponse(
        query="What is 5+5?",
        final_answer="The answer is 10.",
        steps=[step],
        completed=True,
        iterations=1,
        total_latency_ms=15.0,
    )
    assert resp.completed is True
    assert len(resp.steps) == 1
