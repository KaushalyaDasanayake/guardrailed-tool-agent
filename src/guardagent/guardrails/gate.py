"""Security guardrail gate enforcing tiered action inspection before execution."""

from __future__ import annotations

import logging

from guardagent.guardrails.inspectors import (
    inspect_file_path,
    inspect_prompt_injection,
    inspect_sql_query,
)
from guardagent.guardrails.policy import (
    PolicyDecision,
    PolicyEvaluationResult,
    SecurityPolicyConfig,
)
from guardagent.schemas.action import ActionTier, ToolCall

logger = logging.getLogger(__name__)


class GuardrailGate:
    """Security verification gate inspecting every proposed agent action."""

    def __init__(self, config: SecurityPolicyConfig | None = None) -> None:
        self.config = config or SecurityPolicyConfig()

    def evaluate_proposal(self, tool_call: ToolCall, user_query: str = "") -> PolicyEvaluationResult:
        """Evaluate a proposed tool call against tiered security policies.

        Returns PolicyEvaluationResult with ALLOW, REQUIRE_APPROVAL, or BLOCK.
        """
        # 1. Inspect prompt injection in user query and justification
        combined_text = f"{user_query} {tool_call.justification}"
        is_clean, injection_violations = inspect_prompt_injection(combined_text)
        if not is_clean:
            return PolicyEvaluationResult(
                decision=PolicyDecision.BLOCK,
                tier=ActionTier.TIER_3_FORBIDDEN,
                reason="Action blocked: prompt injection or security override detected.",
                rule_name="prompt_injection_guard",
                violations=injection_violations,
            )

        tool_name = tool_call.tool_name.lower().strip()
        args = tool_call.arguments or {}

        # 2. Database operations (query_database)
        if tool_name in ("query_database", "database", "sql"):
            sql_stmt = str(args.get("query", ""))
            sql_type, violations = inspect_sql_query(sql_stmt, self.config.blocked_sql_keywords)

            if sql_type == "forbidden":
                return PolicyEvaluationResult(
                    decision=PolicyDecision.BLOCK,
                    tier=ActionTier.TIER_3_FORBIDDEN,
                    reason="Action blocked: SQL statement contains destructive or forbidden operations.",
                    rule_name="sql_destructive_command_guard",
                    violations=violations,
                )

            if sql_type == "mutation":
                if not self.config.allow_sql_writes:
                    return PolicyEvaluationResult(
                        decision=PolicyDecision.BLOCK,
                        tier=ActionTier.TIER_3_FORBIDDEN,
                        reason="Action blocked: database mutations are disabled by policy.",
                        rule_name="sql_mutation_disabled_guard",
                        violations=["Database writes disabled"],
                    )

                return PolicyEvaluationResult(
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    tier=ActionTier.TIER_2_MUTATION,
                    reason="Database mutation detected: human approval required to execute INSERT/UPDATE.",
                    rule_name="sql_mutation_human_approval",
                    metadata={"query": sql_stmt},
                )

            # Safe read query
            return PolicyEvaluationResult(
                decision=PolicyDecision.ALLOW,
                tier=ActionTier.TIER_1_READ,
                reason="Safe read-only SQL query auto-approved.",
                rule_name="sql_read_allow",
            )

        # 3. File Read (read_file)
        if tool_name == "read_file":
            path_str = str(args.get("path", ""))
            is_safe, violations = inspect_file_path(path_str)
            if not is_safe:
                return PolicyEvaluationResult(
                    decision=PolicyDecision.BLOCK,
                    tier=ActionTier.TIER_3_FORBIDDEN,
                    reason=f"Action blocked: unsafe file path targeting outside sandbox: '{path_str}'",
                    rule_name="file_path_traversal_guard",
                    violations=violations,
                )

            return PolicyEvaluationResult(
                decision=PolicyDecision.ALLOW,
                tier=ActionTier.TIER_1_READ,
                reason="File read within sandbox auto-approved.",
                rule_name="file_read_allow",
            )

        # 4. File Write (write_file)
        if tool_name == "write_file":
            path_str = str(args.get("path", ""))
            is_safe, violations = inspect_file_path(path_str)
            if not is_safe:
                return PolicyEvaluationResult(
                    decision=PolicyDecision.BLOCK,
                    tier=ActionTier.TIER_3_FORBIDDEN,
                    reason=f"Action blocked: destination path escapes sandbox: '{path_str}'",
                    rule_name="file_path_traversal_guard",
                    violations=violations,
                )

            content = str(args.get("content", ""))
            if len(content.encode("utf-8")) > self.config.max_file_size_bytes:
                return PolicyEvaluationResult(
                    decision=PolicyDecision.BLOCK,
                    tier=ActionTier.TIER_3_FORBIDDEN,
                    reason=f"Action blocked: content exceeds max size ({self.config.max_file_size_bytes} bytes)",
                    rule_name="file_size_limit_guard",
                    violations=["File size limit exceeded"],
                )

            return PolicyEvaluationResult(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                tier=ActionTier.TIER_2_MUTATION,
                reason=f"File mutation proposed for '{path_str}': human approval required before writing.",
                rule_name="file_write_human_approval",
                metadata={"path": path_str, "size_chars": len(content)},
            )

        # 5. Math / Calculate (calculate)
        if tool_name == "calculate":
            return PolicyEvaluationResult(
                decision=PolicyDecision.ALLOW,
                tier=ActionTier.TIER_1_READ,
                reason="Mathematical evaluation auto-approved.",
                rule_name="calculate_allow",
            )

        # 6. Web Search (web_search)
        if tool_name == "web_search":
            return PolicyEvaluationResult(
                decision=PolicyDecision.ALLOW,
                tier=ActionTier.TIER_1_READ,
                reason="Documentation search auto-approved.",
                rule_name="web_search_allow",
            )

        # Fallback for unrecognized tools: require approval
        return PolicyEvaluationResult(
            decision=PolicyDecision.REQUIRE_APPROVAL,
            tier=ActionTier.TIER_2_MUTATION,
            reason=f"Unrecognized tool '{tool_name}' requires approval.",
            rule_name="default_unrecognized_tool_gate",
        )
