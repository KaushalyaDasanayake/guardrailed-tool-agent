"""Evaluation runner testing the agent against the 20 golden scenarios."""

from __future__ import annotations

import json
from pathlib import Path

from guardagent.agent.llm import DeterministicAgentClient
from guardagent.agent.react import ReActAgent
from guardagent.guardrails.gate import GuardrailGate
from guardagent.schemas.action import ActionTier, ApprovalStatus
from guardagent.tools import get_default_registry


def run_scenario_evaluation(
    scenarios_path: str | Path = "eval/scenarios.jsonl",
) -> dict:
    """Run full evaluation suite against golden scenarios and compute security benchmarks."""
    path = Path(scenarios_path)
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    scenarios = [json.loads(line) for line in lines]

    agent = ReActAgent(
        llm_client=DeterministicAgentClient(),
        tool_registry=get_default_registry(),
        guardrail_gate=GuardrailGate(),
    )

    total_scenarios = len(scenarios)
    tier_accuracy_count = 0
    forbidden_blocked_count = 0
    total_forbidden = 0
    results: list[dict] = []

    for sc in scenarios:
        sc_id = sc["id"]
        expected_tier = ActionTier(sc["expected_tier"])
        should_block = sc["should_block"]

        response = agent.run(sc["prompt"])

        # Extract evaluated tier from first action step (if any)
        action_step = next((s for s in response.steps if s.tool_call is not None), None)

        actual_tier = action_step.tool_call.tier if action_step and action_step.tool_call else ActionTier.TIER_1_READ
        actual_status = action_step.approval_status if action_step else ApprovalStatus.AUTO_APPROVED

        # Check tier accuracy
        tier_matched = (actual_tier == expected_tier)
        if tier_matched:
            tier_accuracy_count += 1

        # Check block accuracy for Tier 3
        if should_block:
            total_forbidden += 1
            if actual_status == ApprovalStatus.BLOCKED:
                forbidden_blocked_count += 1

        results.append({
            "id": sc_id,
            "category": sc["category"],
            "expected_tier": expected_tier.value,
            "actual_tier": actual_tier.value,
            "expected_status": sc["expected_status"],
            "actual_status": actual_status.value,
            "tier_matched": tier_matched,
            "blocked": actual_status == ApprovalStatus.BLOCKED,
        })

    tier_accuracy = tier_accuracy_count / total_scenarios if total_scenarios else 0.0
    block_rate = forbidden_blocked_count / total_forbidden if total_forbidden else 1.0

    return {
        "total_scenarios": total_scenarios,
        "tier_classification_accuracy": round(tier_accuracy, 4),
        "forbidden_block_rate": round(block_rate, 4),
        "results": results,
    }


if __name__ == "__main__":
    report = run_scenario_evaluation()
    print("=" * 60)
    print("      GUARDAGENT: SECURITY GUARDRAIL BENCHMARK REPORT")
    print("=" * 60)
    print(f"Total Scenarios Evaluated: {report['total_scenarios']}")
    print(f"Tier Classification Accuracy: {report['tier_classification_accuracy']:.2%}")
    print(f"Tier 3 Forbidden Block Rate:  {report['forbidden_block_rate']:.2%}")
    print("=" * 60)
