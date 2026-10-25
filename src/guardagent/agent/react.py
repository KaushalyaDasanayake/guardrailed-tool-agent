"""ReAct execution loop controller with step tracking, timeout, and cycle detection."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

from guardagent.agent.llm import BaseLLMClient
from guardagent.agent.prompts import build_system_prompt
from guardagent.audit.logger import HashChainedAuditLogger
from guardagent.guardrails.gate import GuardrailGate
from guardagent.guardrails.interceptor import HumanInTheLoopInterceptor
from guardagent.guardrails.policy import PolicyDecision
from guardagent.schemas.action import (
    ActionTier,
    AgentResponse,
    AgentStep,
    ApprovalStatus,
    ToolCall,
    ToolResult,
)
from guardagent.tools.base import ToolRegistry

logger = logging.getLogger(__name__)


def _parse_action_and_input(text: str) -> tuple[str | None, dict[str, Any] | None, str]:
    """Extract action tool name, parsed JSON argument dictionary, and thought reasoning."""
    thought_match = re.search(r"Thought:\s*([\s\S]*?)(?=\nAction:|\nFinal Answer:|\Z)", text)
    thought = thought_match.group(1).strip() if thought_match else ""

    action_match = re.search(r"Action:\s*([a-zA-Z0-9_-]+)", text)
    if not action_match:
        return None, None, thought

    tool_name = action_match.group(1).strip()

    # Search for Action Input block
    input_match = re.search(r"Action Input:\s*([\s\S]+?)(?=\n(?:Observation|Thought|Action):|\Z)", text)
    args: dict[str, Any] = {}
    if input_match:
        raw_input = input_match.group(1).strip()
        # Strip markdown code blocks if present
        if raw_input.startswith("```"):
            raw_input = re.sub(r"^```(?:json)?\s*", "", raw_input, flags=re.IGNORECASE)
            raw_input = re.sub(r"\s*```$", "", raw_input)
            raw_input = raw_input.strip()

        try:
            args = json.loads(raw_input)
            if not isinstance(args, dict):
                args = {"input": args}
        except json.JSONDecodeError:
            # Fallback regex search for outer JSON object
            obj_match = re.search(r"\{[\s\S]*\}", raw_input)
            if obj_match:
                try:
                    args = json.loads(obj_match.group(0))
                except json.JSONDecodeError:
                    args = {"input": raw_input}
            else:
                args = {"input": raw_input}

    return tool_name, args, thought


def _extract_final_answer(text: str) -> str | None:
    """Extract final answer if present in agent response."""
    match = re.search(r"Final Answer:\s*([\s\S]+)", text)
    if match:
        return match.group(1).strip()
    return None


class ReActAgent:
    """Core ReAct planning and tool execution controller."""

    def __init__(
        self,
        llm_client: BaseLLMClient,
        tool_registry: ToolRegistry,
        guardrail_gate: GuardrailGate | None = None,
        interceptor: HumanInTheLoopInterceptor | None = None,
        audit_logger: HashChainedAuditLogger | None = None,
        max_iterations: int = 6,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.llm_client = llm_client
        self.tool_registry = tool_registry
        self.guardrail_gate = guardrail_gate or GuardrailGate()
        self.interceptor = interceptor or HumanInTheLoopInterceptor(auto_approve_tier_2=True)
        self.audit_logger = audit_logger or HashChainedAuditLogger()
        self.max_iterations = max_iterations
        self.timeout_seconds = timeout_seconds

    def run(self, query: str) -> AgentResponse:
        """Execute autonomous ReAct loop on the provided user query."""
        clean_query = query.strip()
        if not clean_query:
            return AgentResponse(
                query=query,
                final_answer="No question or task was provided.",
                steps=[],
                completed=True,
                iterations=0,
                total_latency_ms=0.0,
            )

        start_time = time.perf_counter()
        tool_names = [t.name for t in self.tool_registry.list_tools()]
        system_prompt = build_system_prompt(
            tool_descriptions=self.tool_registry.get_descriptions(),
            tool_names=tool_names,
            max_iterations=self.max_iterations,
        )

        messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Question: {clean_query}"},
        ]

        steps: list[AgentStep] = []
        visited_actions: set[str] = set()
        blocked_count = 0
        final_answer = ""
        completed = False

        for iteration in range(1, self.max_iterations + 1):
            elapsed = time.perf_counter() - start_time
            if elapsed > self.timeout_seconds:
                logger.warning("ReAct loop exceeded timeout limit (%.1fs)", self.timeout_seconds)
                final_answer = f"Execution timed out after {elapsed:.1f} seconds."
                break

            step_start = time.perf_counter()
            response_text = self.llm_client.generate(messages)

            # Check for direct completion
            direct_answer = _extract_final_answer(response_text)
            if direct_answer is not None:
                step_latency = (time.perf_counter() - step_start) * 1000.0
                thought_match = re.search(r"Thought:\s*([\s\S]*?)(?=\nFinal Answer:|\Z)", response_text)
                thought_text = thought_match.group(1).strip() if thought_match else "Task completed."
                steps.append(
                    AgentStep(
                        step_number=iteration,
                        thought=thought_text,
                        approval_status=ApprovalStatus.AUTO_APPROVED,
                        latency_ms=step_latency,
                    )
                )
                final_answer = direct_answer
                completed = True
                break

            # Parse proposed tool action
            tool_name, args, thought = _parse_action_and_input(response_text)

            if not tool_name or not self.tool_registry.has(tool_name):
                # Unrecognized or missing tool syntax
                err_msg = f"Unknown or invalid tool action '{tool_name}'. Available: {tool_names}"
                blocked_count += 1
                step_latency = (time.perf_counter() - step_start) * 1000.0
                steps.append(
                    AgentStep(
                        step_number=iteration,
                        thought=thought or "Attempted invalid tool syntax.",
                        approval_status=ApprovalStatus.BLOCKED,
                        approval_reason=err_msg,
                        latency_ms=step_latency,
                    )
                )
                self.audit_logger.log_event(
                    step_number=iteration,
                    event_type="action_blocked",
                    tool_name=tool_name,
                    arguments=args or {},
                    tier=ActionTier.TIER_3_FORBIDDEN,
                    approval_status=ApprovalStatus.BLOCKED,
                    approval_comment=err_msg,
                    execution_success=False,
                    output_summary=err_msg,
                    latency_ms=step_latency,
                )
                messages.append({"role": "assistant", "content": response_text})
                messages.append({"role": "user", "content": f"Observation: ERROR: {err_msg}"})
                continue

            # Cycle detection
            fingerprint = f"{tool_name}:{json.dumps(args, sort_keys=True)}"
            if fingerprint in visited_actions:
                cycle_msg = f"Cycle detected: {tool_name} was already executed with identical arguments."
                logger.warning(cycle_msg)
                blocked_count += 1
                step_latency = (time.perf_counter() - step_start) * 1000.0
                steps.append(
                    AgentStep(
                        step_number=iteration,
                        thought=thought,
                        tool_call=ToolCall(tool_name=tool_name, arguments=args or {}),
                        approval_status=ApprovalStatus.BLOCKED,
                        approval_reason=cycle_msg,
                        latency_ms=step_latency,
                    )
                )
                self.audit_logger.log_event(
                    step_number=iteration,
                    event_type="action_blocked",
                    tool_name=tool_name,
                    arguments=args or {},
                    tier=ActionTier.TIER_3_FORBIDDEN,
                    approval_status=ApprovalStatus.BLOCKED,
                    approval_comment=cycle_msg,
                    execution_success=False,
                    output_summary=cycle_msg,
                    latency_ms=step_latency,
                )
                messages.append({"role": "assistant", "content": response_text})
                messages.append({"role": "user", "content": f"Observation: ERROR: {cycle_msg}"})
                continue

            visited_actions.add(fingerprint)
            tool_obj = self.tool_registry.get(tool_name)

            # Evaluate action proposal through GuardrailGate
            tool_call = ToolCall(
                tool_name=tool_name,
                arguments=args or {},
                tier=tool_obj.tier,
                justification=thought,
            )
            policy_eval = self.guardrail_gate.evaluate_proposal(tool_call, user_query=clean_query)
            tool_call.tier = policy_eval.tier

            # Tier 3 (Forbidden) -> Strictly Blocked
            if policy_eval.decision == PolicyDecision.BLOCK:
                blocked_count += 1
                step_latency = (time.perf_counter() - step_start) * 1000.0
                step = AgentStep(
                    step_number=iteration,
                    thought=thought,
                    tool_call=tool_call,
                    approval_status=ApprovalStatus.BLOCKED,
                    approval_reason=policy_eval.reason,
                    latency_ms=step_latency,
                )
                steps.append(step)

                # Record audit event for blocked action
                self.audit_logger.log_event(
                    step_number=iteration,
                    event_type="action_blocked",
                    tool_name=tool_name,
                    arguments=args or {},
                    tier=policy_eval.tier,
                    approval_status=ApprovalStatus.BLOCKED,
                    approval_comment=policy_eval.reason,
                    execution_success=False,
                    output_summary=f"Violations: {policy_eval.violations}",
                    latency_ms=step_latency,
                )

                obs_err = f"SECURITY POLICY BLOCKED: {policy_eval.reason} (Violations: {policy_eval.violations})"
                messages.append({"role": "assistant", "content": response_text})
                messages.append({"role": "user", "content": f"Observation: ERROR: {obs_err}"})
                continue

            # Tier 2 (Mutation / Sensitive) -> Human-in-the-Loop Approval Check
            approval_status = ApprovalStatus.AUTO_APPROVED
            approval_reason = policy_eval.reason
            reviewer_name: str | None = None

            if policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL:
                decision = self.interceptor.request_approval(
                    step_number=iteration,
                    tool_call=tool_call,
                    risk_summary=policy_eval.reason,
                )
                reviewer_name = decision.reviewer

                if not decision.approved:
                    # Human rejected the proposed action -> report denial back to agent for replanning
                    step_latency = (time.perf_counter() - step_start) * 1000.0
                    step = AgentStep(
                        step_number=iteration,
                        thought=thought,
                        tool_call=tool_call,
                        approval_status=ApprovalStatus.DENIED,
                        approval_reason=f"Human operator denied action: {decision.comment or 'Permission denied'}",
                        latency_ms=step_latency,
                    )
                    steps.append(step)

                    # Record audit event for operator denial
                    self.audit_logger.log_event(
                        step_number=iteration,
                        event_type="action_denied",
                        tool_name=tool_name,
                        arguments=args or {},
                        tier=policy_eval.tier,
                        approval_status=ApprovalStatus.DENIED,
                        reviewer=decision.reviewer,
                        approval_comment=decision.comment,
                        execution_success=False,
                        output_summary="Action denied by human operator",
                        latency_ms=step_latency,
                    )

                    denial_msg = f"ACTION DENIED BY HUMAN OPERATOR: {decision.comment or 'Permission denied'}. You must replan or abort without executing this action."
                    messages.append({"role": "assistant", "content": response_text})
                    messages.append({"role": "user", "content": f"Observation: {denial_msg}"})
                    continue

                approval_status = ApprovalStatus.APPROVED
                approval_reason = decision.comment or "Approved by human operator"

            try:
                res = tool_obj.execute(**(args or {}))
            except Exception as err:
                res = ToolResult(tool_name=tool_name, output="", success=False, error=str(err))

            step_latency = (time.perf_counter() - step_start) * 1000.0
            step = AgentStep(
                step_number=iteration,
                thought=thought,
                tool_call=tool_call,
                approval_status=approval_status,
                approval_reason=approval_reason,
                tool_result=res,
                latency_ms=step_latency,
            )
            steps.append(step)

            # Record audit event for executed action
            self.audit_logger.log_event(
                step_number=iteration,
                event_type="action_executed",
                tool_name=tool_name,
                arguments=args or {},
                tier=policy_eval.tier,
                approval_status=approval_status,
                reviewer=reviewer_name,
                approval_comment=approval_reason,
                execution_success=res.success,
                output_summary=res.output if res.success else res.error,
                latency_ms=step_latency,
            )

            observation_text = res.output if res.success else f"ERROR: {res.error}"
            messages.append({"role": "assistant", "content": response_text})
            messages.append({"role": "user", "content": f"Observation: {observation_text}"})

        if not completed and not final_answer:
            final_answer = f"Agent reached maximum reasoning limit ({self.max_iterations} iterations) without concluding."

        total_latency = (time.perf_counter() - start_time) * 1000.0

        return AgentResponse(
            query=clean_query,
            final_answer=final_answer,
            steps=steps,
            completed=completed,
            iterations=len(steps),
            total_latency_ms=total_latency,
            blocked_actions=blocked_count,
        )
