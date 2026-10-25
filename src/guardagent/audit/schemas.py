"""Audit event data schemas and cryptographic hash chaining definitions."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from guardagent.schemas.action import ActionTier, ApprovalStatus


def compute_event_hash(
    event_id: str,
    timestamp: str,
    step_number: int,
    event_type: str,
    tool_name: str | None,
    arguments: dict[str, Any],
    tier: str,
    approval_status: str,
    previous_hash: str,
    reviewer: str | None = None,
    approval_comment: str | None = None,
    execution_success: bool | None = None,
    output_summary: str | None = None,
) -> str:
    """Compute deterministic SHA-256 digest of complete audit event payload chained with previous_hash."""
    canonical_payload = json.dumps(
        {
            "event_id": event_id,
            "timestamp": timestamp,
            "step_number": step_number,
            "event_type": event_type,
            "tool_name": tool_name or "",
            "arguments": arguments,
            "tier": tier,
            "approval_status": approval_status,
            "reviewer": reviewer or "",
            "approval_comment": approval_comment or "",
            "execution_success": execution_success,
            "output_summary": output_summary or "",
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


class AuditEvent(BaseModel):
    """Immutable, hash-chained audit event recording every agent action decision."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = Field(default="default_session")
    step_number: int = Field(..., ge=1)
    event_type: str = Field(..., description="E.g. action_proposed, action_executed, action_blocked, action_denied")
    tool_name: str | None = Field(default=None)
    arguments: dict[str, Any] = Field(default_factory=dict)
    tier: ActionTier = Field(default=ActionTier.TIER_1_READ)
    approval_status: ApprovalStatus = Field(default=ApprovalStatus.AUTO_APPROVED)
    reviewer: str | None = Field(default=None)
    approval_comment: str | None = Field(default=None)
    execution_success: bool | None = Field(default=None)
    output_summary: str | None = Field(default=None)
    latency_ms: float = Field(default=0.0, ge=0.0)
    previous_hash: str = Field(..., description="SHA-256 hash of the preceding record in the chain")
    current_hash: str = Field(..., description="SHA-256 hash of this record including previous_hash")
