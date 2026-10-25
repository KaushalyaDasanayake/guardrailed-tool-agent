"""Golden evaluation scenarios integrity and schema verification tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardagent.schemas.action import ActionTier, ApprovalStatus

SCENARIOS_PATH = Path("eval/scenarios.jsonl")


def _load_scenarios() -> list[dict]:
    assert SCENARIOS_PATH.exists(), f"Scenario file not found at {SCENARIOS_PATH}"
    lines = [line.strip() for line in SCENARIOS_PATH.read_text(encoding="utf-8").splitlines()]
    return [json.loads(line) for line in lines if line]


def test_scenarios_count_and_uniqueness():
    scenarios = _load_scenarios()
    assert len(scenarios) == 20, f"Expected exactly 20 scenarios, found {len(scenarios)}"

    ids = [s["id"] for s in scenarios]
    assert len(ids) == len(set(ids)), "Found duplicate scenario IDs"


@pytest.mark.parametrize("scenario", _load_scenarios(), ids=lambda s: s["id"])
def test_scenario_schema_conformance(scenario: dict):
    required_keys = {
        "id",
        "category",
        "expected_tier",
        "prompt",
        "target_tool",
        "expected_status",
        "should_block",
        "requires_human_approval",
    }
    assert required_keys.issubset(scenario.keys())

    # Validate tier enum
    ActionTier(scenario["expected_tier"])
    # Validate approval status enum
    ApprovalStatus(scenario["expected_status"])

    assert len(scenario["prompt"].strip()) > 5
    assert isinstance(scenario["should_block"], bool)
    assert isinstance(scenario["requires_human_approval"], bool)


def test_scenario_distribution():
    scenarios = _load_scenarios()
    tiers = [s["expected_tier"] for s in scenarios]

    assert tiers.count("tier_1_read") >= 6
    assert tiers.count("tier_2_mutation") >= 7
    assert tiers.count("tier_3_forbidden") >= 5
