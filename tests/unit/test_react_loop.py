"""Unit tests for the ReAct execution loop."""

from __future__ import annotations

from unittest.mock import MagicMock

from guardagent.agent.llm import DeterministicAgentClient
from guardagent.agent.react import ReActAgent
from guardagent.tools import get_default_registry


def test_react_empty_query():
    agent = ReActAgent(
        llm_client=DeterministicAgentClient(),
        tool_registry=get_default_registry(),
    )
    res = agent.run("   ")
    assert res.completed is True
    assert res.iterations == 0
    assert "No question" in res.final_answer


def test_react_direct_answer():
    agent = ReActAgent(
        llm_client=DeterministicAgentClient(),
        tool_registry=get_default_registry(),
    )
    res = agent.run("Hello! What tools and capabilities do you have?")
    assert res.completed is True
    assert len(res.steps) == 1
    assert "calculate" in res.final_answer
    assert res.steps[0].tool_call is None


def test_react_math_execution():
    agent = ReActAgent(
        llm_client=DeterministicAgentClient(),
        tool_registry=get_default_registry(),
    )
    res = agent.run("Calculate 45 * 12 + 180 and report the exact number.")
    assert res.completed is True
    assert len(res.steps) == 2
    # Step 1 invoked calculate
    assert res.steps[0].tool_call is not None
    assert res.steps[0].tool_call.tool_name == "calculate"
    assert res.steps[0].tool_result.output == "720"
    # Step 2 finalized
    assert "720" in res.final_answer


def test_react_cycle_detection():
    mock_llm = MagicMock()
    # Emits identical action repeatedly
    mock_llm.generate.return_value = (
        "Thought: Checking again.\nAction: calculate\nAction Input: {\"expression\": \"2+2\"}"
    )

    agent = ReActAgent(
        llm_client=mock_llm,
        tool_registry=get_default_registry(),
        max_iterations=3,
    )
    res = agent.run("Calculate 2+2 in loop")
    # Step 1 executes, Step 2 detects cycle
    assert len(res.steps) >= 2
    assert res.steps[1].approval_status.value == "blocked"
    assert "cycle detected" in res.steps[1].approval_reason.lower()


def test_react_max_iterations_abort():
    mock_llm = MagicMock()
    # Never emits Final Answer and generates varying thoughts
    counter = 0

    def _mock_gen(messages):
        nonlocal counter
        counter += 1
        return f"Thought: Thinking step {counter}.\nAction: calculate\nAction Input: {{\"expression\": \"{counter} + 1\"}}"

    mock_llm.generate.side_effect = _mock_gen

    agent = ReActAgent(
        llm_client=mock_llm,
        tool_registry=get_default_registry(),
        max_iterations=4,
    )
    res = agent.run("Never ending task")
    assert res.completed is False
    assert res.iterations == 4
    assert "maximum reasoning limit" in res.final_answer.lower()
