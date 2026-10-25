"""Unit tests for Human-in-the-Loop (HITL) approval interceptor and replanning."""

from __future__ import annotations

from unittest.mock import MagicMock

from guardagent.agent.react import ReActAgent
from guardagent.guardrails.approval import ApprovalDecision, ApprovalRequest
from guardagent.guardrails.gate import GuardrailGate
from guardagent.guardrails.interceptor import (
    HumanInTheLoopInterceptor,
)
from guardagent.schemas.action import ActionTier, ApprovalStatus, ToolCall
from guardagent.tools import get_default_registry


def test_hitl_approval_schemas():
    call = ToolCall(tool_name="write_file", arguments={"path": "note.txt", "content": "test"})
    req = ApprovalRequest(
        step_number=1,
        tool_call=call,
        tier=ActionTier.TIER_2_MUTATION,
        risk_summary="Writing to file",
    )
    assert req.step_number == 1
    assert req.tier == ActionTier.TIER_2_MUTATION
    assert req.request_id.startswith("req_")

    decision = ApprovalDecision(
        request_id=req.request_id,
        approved=True,
        reviewer="admin",
        comment="Looks good",
    )
    assert decision.approved is True
    assert decision.reviewer == "admin"


def test_interceptor_auto_approve_mode():
    interceptor = HumanInTheLoopInterceptor(auto_approve_tier_2=True)
    call = ToolCall(tool_name="write_file", arguments={"path": "note.txt", "content": "test"})

    decision = interceptor.request_approval(step_number=1, tool_call=call, risk_summary="Test risk")
    assert decision.approved is True
    assert len(interceptor.decision_history) == 1
    assert len(interceptor.pending_requests) == 0


def test_interceptor_custom_callback_approved():
    def _approve_callback(req: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            request_id=req.request_id,
            approved=True,
            reviewer="qa_lead",
            comment="Approved by QA",
        )

    interceptor = HumanInTheLoopInterceptor(callback=_approve_callback)
    call = ToolCall(tool_name="query_database", arguments={"query": "INSERT INTO employees VALUES (1)"})

    decision = interceptor.request_approval(step_number=1, tool_call=call, risk_summary="DB insert")
    assert decision.approved is True
    assert decision.reviewer == "qa_lead"
    assert decision.comment == "Approved by QA"


def test_interceptor_custom_callback_denied():
    def _deny_callback(req: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            request_id=req.request_id,
            approved=False,
            reviewer="security_officer",
            comment="Blocked: not allowed during maintenance window",
        )

    interceptor = HumanInTheLoopInterceptor(callback=_deny_callback)
    call = ToolCall(tool_name="write_file", arguments={"path": "secrets.txt", "content": "123"})

    decision = interceptor.request_approval(step_number=2, tool_call=call, risk_summary="Writing secrets")
    assert decision.approved is False
    assert decision.reviewer == "security_officer"
    assert "maintenance window" in decision.comment


def test_interceptor_callback_exception_fails_safe_to_denial():
    def _crashing_callback(req: ApprovalRequest) -> ApprovalDecision:
        raise ConnectionError("Operator console disconnected")

    interceptor = HumanInTheLoopInterceptor(callback=_crashing_callback)
    call = ToolCall(tool_name="write_file", arguments={"path": "file.txt"})

    decision = interceptor.request_approval(step_number=1, tool_call=call, risk_summary="Risk")
    # Must fail-safe to DENIAL rather than crashing or granting permission
    assert decision.approved is False
    assert decision.reviewer == "system_safety_fallback"
    assert "disconnected" in decision.comment


def test_react_agent_hitl_approval_flow():
    mock_llm = MagicMock()
    # Step 1: Propose writing file (Tier 2)
    # Step 2: Finalize answer after seeing execution result
    mock_llm.generate.side_effect = [
        "Thought: Need to save report.\nAction: write_file\nAction Input: {\"path\": \"report.txt\", \"content\": \"data\"}",
        "Thought: Saved successfully.\nFinal Answer: Report was written to report.txt.",
    ]

    # Operator approves
    interceptor = HumanInTheLoopInterceptor(
        callback=lambda req: ApprovalDecision(request_id=req.request_id, approved=True, comment="Operator confirmed")
    )
    agent = ReActAgent(
        llm_client=mock_llm,
        tool_registry=get_default_registry(),
        guardrail_gate=GuardrailGate(),
        interceptor=interceptor,
    )

    res = agent.run("Save summary to report.txt")
    assert res.completed is True
    assert len(res.steps) == 2
    assert res.steps[0].approval_status == ApprovalStatus.APPROVED
    assert "Operator confirmed" in res.steps[0].approval_reason


def test_react_agent_hitl_denial_replanning():
    mock_llm = MagicMock()
    # Step 1: Propose writing file (Tier 2)
    # Step 2: Agent observes denial and replans to abort
    mock_llm.generate.side_effect = [
        "Thought: Need to save report.\nAction: write_file\nAction Input: {\"path\": \"report.txt\", \"content\": \"data\"}",
        "Thought: The user denied file write permission. I must conclude without writing.\nFinal Answer: Operation aborted because human operator denied write permission.",
    ]

    # Operator denies
    interceptor = HumanInTheLoopInterceptor(
        callback=lambda req: ApprovalDecision(
            request_id=req.request_id,
            approved=False,
            comment="Denied: disk writes restricted",
        )
    )
    agent = ReActAgent(
        llm_client=mock_llm,
        tool_registry=get_default_registry(),
        guardrail_gate=GuardrailGate(),
        interceptor=interceptor,
    )

    res = agent.run("Save summary to report.txt")
    assert res.completed is True
    assert len(res.steps) == 2
    assert res.steps[0].approval_status == ApprovalStatus.DENIED
    assert "disk writes restricted" in res.steps[0].approval_reason
    assert "denied" in res.final_answer.lower()
