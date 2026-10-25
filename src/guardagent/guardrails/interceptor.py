"""Human-in-the-loop interceptor coordinating approval requests and operator callbacks."""

from __future__ import annotations

import logging
from collections.abc import Callable

from guardagent.guardrails.approval import ApprovalDecision, ApprovalRequest
from guardagent.schemas.action import ToolCall

logger = logging.getLogger(__name__)

# Callback signature: takes ApprovalRequest, returns ApprovalDecision
ApprovalCallback = Callable[[ApprovalRequest], ApprovalDecision]


def default_cli_approval_callback(request: ApprovalRequest) -> ApprovalDecision:
    """Synchronous interactive terminal approval handler."""
    print("\n" + "=" * 65)
    print(" ⚠️  HUMAN APPROVAL REQUIRED FOR TIER 2 SENSITIVE ACTION")
    print("=" * 65)
    print(f"Request ID:   {request.request_id}")
    print(f"Tool Name:    {request.tool_call.tool_name}")
    print(f"Risk Summary: {request.risk_summary}")
    print("Arguments:")
    for k, v in request.tool_call.arguments.items():
        print(f"  - {k}: {v}")
    print("=" * 65)

    choice = input("Approve this action? [y/N]: ").strip().lower()
    approved = choice in ("y", "yes")
    comment = "Approved via interactive CLI" if approved else "Denied by operator via CLI"

    return ApprovalDecision(
        request_id=request.request_id,
        approved=approved,
        reviewer="cli_operator",
        comment=comment,
    )


class HumanInTheLoopInterceptor:
    """Interceptor coordinating human review before execution of Tier 2 sensitive actions."""

    def __init__(
        self,
        callback: ApprovalCallback | None = None,
        auto_approve_tier_2: bool = False,
    ) -> None:
        self.callback = callback or default_cli_approval_callback
        self.auto_approve_tier_2 = auto_approve_tier_2
        self.pending_requests: dict[str, ApprovalRequest] = {}
        self.decision_history: list[ApprovalDecision] = []

    def request_approval(
        self,
        step_number: int,
        tool_call: ToolCall,
        risk_summary: str,
    ) -> ApprovalDecision:
        """Issue an approval request and wait for human decision via the configured callback."""
        req = ApprovalRequest(
            step_number=step_number,
            tool_call=tool_call,
            risk_summary=risk_summary,
            details=tool_call.arguments or {},
        )
        self.pending_requests[req.request_id] = req

        # Automatic approval mode (for automated testing or non-interactive environments)
        if self.auto_approve_tier_2:
            decision = ApprovalDecision(
                request_id=req.request_id,
                approved=True,
                reviewer="auto_policy_override",
                comment="Auto-approved by interceptor configuration",
            )
            self.decision_history.append(decision)
            self.pending_requests.pop(req.request_id, None)
            return decision

        try:
            raw_decision = self.callback(req)
            if not isinstance(raw_decision, ApprovalDecision):
                logger.error("Callback returned invalid decision type: %s; failing safe to DENIAL", type(raw_decision))
                decision = ApprovalDecision(
                    request_id=req.request_id,
                    approved=False,
                    reviewer="system_safety_fallback",
                    comment="Invalid decision type from approval callback",
                )
            else:
                decision = raw_decision
        except Exception as err:
            logger.error("Approval callback failed with error: %s; defaulting to DENIAL for safety", err)
            decision = ApprovalDecision(
                request_id=req.request_id,
                approved=False,
                reviewer="system_safety_fallback",
                comment=f"Callback failed: {err}",
            )
        finally:
            self.pending_requests.pop(req.request_id, None)

        self.decision_history.append(decision)
        return decision
