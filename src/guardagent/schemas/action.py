"""Core schemas for actions, tool invocations, tiered guardrails, and audit entries."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ActionTier(str, Enum):
    """Classification tier of tool execution danger and permission requirements."""

    TIER_1_READ = "tier_1_read"  # Read-only, safe, auto-approved (SELECT, math, search)
    TIER_2_MUTATION = "tier_2_mutation"  # Mutation, write, human approval required (INSERT, write_file)
    TIER_3_FORBIDDEN = "tier_3_forbidden"  # Destructive, blocked by policy (DROP, DELETE, traversal)


class ApprovalStatus(str, Enum):
    """Status of human-in-the-loop or automated permission evaluation."""

    AUTO_APPROVED = "auto_approved"
    APPROVED = "approved"
    DENIED = "denied"
    BLOCKED = "blocked"
    PENDING = "pending"


class ToolCall(BaseModel):
    """Structured proposal to invoke a specific tool."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(..., description="Name of the tool to invoke")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Typed keyword arguments")
    tier: ActionTier = Field(default=ActionTier.TIER_1_READ, description="Evaluated action tier")
    justification: str = Field(default="", description="Reasoning for invoking this tool")


class ToolResult(BaseModel):
    """Output received from executing a tool."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    output: str = Field(..., description="Stringified output or error message")
    success: bool = Field(default=True, description="Whether tool execution succeeded")
    error: str | None = Field(default=None, description="Error detail if execution failed")


class AgentStep(BaseModel):
    """A single ReAct reasoning cycle step."""

    model_config = ConfigDict(extra="forbid")

    step_number: int = Field(..., ge=1)
    thought: str = Field(..., description="Internal reasoning leading to proposed action")
    tool_call: ToolCall | None = Field(default=None, description="Action proposed in this step")
    approval_status: ApprovalStatus = Field(default=ApprovalStatus.AUTO_APPROVED)
    approval_reason: str | None = Field(default=None, description="Human or policy approval comment")
    tool_result: ToolResult | None = Field(default=None, description="Observation from tool")
    latency_ms: float = Field(default=0.0, ge=0.0, description="Step execution latency")


class AgentResponse(BaseModel):
    """Final answer returned to user including complete traceable step sequence."""

    model_config = ConfigDict(extra="forbid")

    query: str
    final_answer: str = Field(..., description="Direct final response to user query")
    steps: list[AgentStep] = Field(default_factory=list, description="Trace of all steps taken")
    completed: bool = Field(default=True, description="Whether the task was completed successfully")
    iterations: int = Field(default=1, ge=1, description="Total reasoning loops executed")
    total_latency_ms: float = Field(default=0.0, ge=0.0)
    blocked_actions: int = Field(default=0, ge=0, description="Count of blocked Tier 3 attempts")
