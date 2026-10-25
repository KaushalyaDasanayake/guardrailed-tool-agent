"""Guardrails package initialization."""

from __future__ import annotations

from guardagent.guardrails.approval import ApprovalDecision, ApprovalRequest
from guardagent.guardrails.gate import GuardrailGate
from guardagent.guardrails.inspectors import (
    inspect_file_path,
    inspect_prompt_injection,
    inspect_sql_query,
)
from guardagent.guardrails.interceptor import (
    ApprovalCallback,
    HumanInTheLoopInterceptor,
    default_cli_approval_callback,
)
from guardagent.guardrails.policy import (
    PolicyDecision,
    PolicyEvaluationResult,
    SecurityPolicyConfig,
)

__all__ = [
    "GuardrailGate",
    "PolicyDecision",
    "PolicyEvaluationResult",
    "SecurityPolicyConfig",
    "ApprovalRequest",
    "ApprovalDecision",
    "HumanInTheLoopInterceptor",
    "ApprovalCallback",
    "default_cli_approval_callback",
    "inspect_sql_query",
    "inspect_file_path",
    "inspect_prompt_injection",
]
