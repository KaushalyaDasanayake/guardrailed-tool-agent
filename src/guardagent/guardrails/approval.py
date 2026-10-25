"""Human-in-the-loop (HITL) approval schemas and decision data models."""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from guardagent.schemas.action import ActionTier, ToolCall


class ApprovalRequest(BaseModel):
    """Payload presented to a human reviewer when a Tier 2 action is proposed."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:12]}")
    step_number: int = Field(..., ge=1, description="Agent reasoning iteration number")
    tool_call: ToolCall = Field(..., description="Proposed tool invocation")
    tier: ActionTier = Field(default=ActionTier.TIER_2_MUTATION)
    risk_summary: str = Field(..., description="Human-readable explanation of proposed change")
    details: dict[str, Any] = Field(default_factory=dict, description="Parsed parameters for review")


class ApprovalDecision(BaseModel):
    """Decision submitted by human reviewer approving or denying the proposed action."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="ID matching the ApprovalRequest")
    approved: bool = Field(..., description="True if action is granted; False if denied")
    reviewer: str = Field(default="human_operator", description="Identifier of approving user")
    comment: str | None = Field(default=None, description="Optional reasoning or rejection feedback")
