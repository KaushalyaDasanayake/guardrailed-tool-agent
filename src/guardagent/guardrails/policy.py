"""Policy definitions, risk tiers, and rule configurations for action evaluation."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from guardagent.schemas.action import ActionTier


class PolicyDecision(str, Enum):
    """Outcome of policy evaluation on an action proposal."""

    ALLOW = "allow"  # Auto-approved execution (Tier 1)
    REQUIRE_APPROVAL = "require_approval"  # Needs human permission (Tier 2)
    BLOCK = "block"  # Prohibited by security policy (Tier 3)


class PolicyEvaluationResult(BaseModel):
    """Detailed evaluation result returned by the guardrail policy engine."""

    model_config = ConfigDict(extra="forbid")

    decision: PolicyDecision
    tier: ActionTier
    reason: str = Field(..., description="Justification for policy decision")
    rule_name: str = Field(default="default_policy", description="Specific rule triggered")
    violations: list[str] = Field(default_factory=list, description="List of detected policy violations")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Diagnostic parameters")


class SecurityPolicyConfig(BaseModel):
    """Runtime configurable thresholds and boundaries for the guardrail system."""

    model_config = ConfigDict(extra="forbid")

    allow_sql_writes: bool = Field(default=True, description="Whether INSERT/UPDATE can be proposed for approval")
    blocked_sql_keywords: list[str] = Field(
        default_factory=lambda: [
            "DROP",
            "DELETE",
            "TRUNCATE",
            "ALTER",
            "ATTACH",
            "DETACH",
            "PRAGMA",
            "VACUUM",
        ],
        description="SQL keywords permanently forbidden under Tier 3",
    )
    max_file_size_bytes: int = Field(default=1048576, description="Max allowed file write size (1MB)")
    enforce_human_approval: bool = Field(default=True, description="Enforce human confirmation for Tier 2")
