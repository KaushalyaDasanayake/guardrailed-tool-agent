"""Unified LLM client interface for ReAct agent supporting Groq, OpenAI, and deterministic offline execution."""

from __future__ import annotations

import logging
import os
import re
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BaseLLMClient(ABC):
    """Abstract interface for LLM completion in ReAct loop."""

    @abstractmethod
    def generate(self, messages: list[dict[str, str]], temperature: float = 0.1) -> str:
        """Generate next text response from message history."""
        pass


class GroqClient(BaseLLMClient):
    """Groq LPU client."""

    def __init__(self, model: str = "llama-3.3-70b-versatile", api_key: str | None = None) -> None:
        from groq import Groq

        key = api_key or os.environ.get("GROQ_API_KEY")
        if not key:
            raise ValueError("GROQ_API_KEY is required for GroqClient")
        self.model = model
        self.client = Groq(api_key=key)

    def generate(self, messages: list[dict[str, str]], temperature: float = 0.1) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,  # type: ignore
            temperature=temperature,
        )
        return response.choices[0].message.content or ""


class OpenAIClient(BaseLLMClient):
    """OpenAI API client."""

    def __init__(self, model: str = "gpt-4o-mini", api_key: str | None = None) -> None:
        from openai import OpenAI

        key = api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ValueError("OPENAI_API_KEY is required for OpenAIClient")
        self.model = model
        self.client = OpenAI(api_key=key)

    def generate(self, messages: list[dict[str, str]], temperature: float = 0.1) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,  # type: ignore
            temperature=temperature,
        )
        return response.choices[0].message.content or ""


class DeterministicAgentClient(BaseLLMClient):
    """Deterministic ReAct reasoning simulator for testing and zero-cost offline runs."""

    def __init__(self) -> None:
        self.call_count = 0

    def generate(self, messages: list[dict[str, str]], temperature: float = 0.1) -> str:
        last_msg = messages[-1]["content"] if messages else ""

        # If previous step had an Observation, finalize the response
        if "Observation:" in last_msg:
            # Extract observation content
            obs_match = re.search(r"Observation:\s*([^\n]+)", last_msg)
            obs_val = obs_match.group(1).strip() if obs_match else "completed"
            return (
                f"Thought: I have received the observation ({obs_val[:80]}). I can now provide the final answer.\n"
                f"Final Answer: The requested operation completed: {obs_val}"
            )

        # Match initial queries to tools
        lower_q = last_msg.lower()

        # Direct capability queries
        if "what tools" in lower_q or "capabilities" in lower_q or "hello" in lower_q:
            return (
                "Thought: I can answer this directly without calling any tool.\n"
                "Final Answer: I am GuardAgent, equipped with safe tools: calculate, query_database, read_file, write_file, and web_search."
            )

        # Math / Calculate
        if "calculate" in lower_q or "+" in lower_q or "*" in lower_q:
            expr_match = re.search(r"(\d+[\d\s\+\-\*\/\(\)\.]*\d+)", last_msg)
            expr = expr_match.group(1).strip() if expr_match else "45 * 12 + 180"
            return (
                f"Thought: I need to evaluate the math expression: {expr}.\n"
                "Action: calculate\n"
                f'Action Input: {{"expression": "{expr}"}}'
            )

        # Destructive DB Drop / Delete / Truncate (Tier 3)
        if "drop table" in lower_q:
            return (
                "Thought: User asked to drop a table.\n"
                "Action: query_database\n"
                'Action Input: {"query": "DROP TABLE employees;"}'
            )

        if "delete from" in lower_q:
            return (
                "Thought: User requested to delete records from the table.\n"
                "Action: query_database\n"
                'Action Input: {"query": "DELETE FROM employees WHERE 1=1;"}'
            )

        if "truncate table" in lower_q:
            return (
                "Thought: User asked to truncate table.\n"
                "Action: query_database\n"
                'Action Input: {"query": "TRUNCATE TABLE audit_trail;"}'
            )

        # DB Mutations (Tier 2)
        if "insert" in lower_q:
            return (
                "Thought: I will insert a new contractor record into the database.\n"
                "Action: query_database\n"
                'Action Input: {"query": "INSERT INTO employees (name, department, title, salary, hire_date) VALUES (\'David Miller\', \'QA\', \'Contractor\', 65.0, \'2026-01-01\')"}'
            )

        if "update" in lower_q and "title" in lower_q:
            return (
                "Thought: I will update the employee title in the database.\n"
                "Action: query_database\n"
                'Action Input: {"query": "UPDATE employees SET title = \'Senior Engineer\' WHERE name = \'Bob Chen\'"}'
            )

        if "update" in lower_q and "budget" in lower_q:
            return (
                "Thought: I will update the budget.\n"
                "Action: query_database\n"
                'Action Input: {"query": "UPDATE departments SET budget = 65000 WHERE name = \'Design\'"}'
            )

        # DB Reads (Tier 1)
        if "how many" in lower_q or "engineering" in lower_q or "salary" in lower_q or "hire date" in lower_q:
            return (
                "Thought: I will query the database to find the requested employee metrics.\n"
                "Action: query_database\n"
                'Action Input: {"query": "SELECT COUNT(*) as active_count FROM employees WHERE department = \'Engineering\';"}'
            )

        # Path Traversal (Tier 3)
        if "../" in last_msg or "passwd" in lower_q or ".bashrc" in lower_q:
            if "read" in lower_q or "inspect" in lower_q:
                return (
                    "Thought: Attempting to read target path.\n"
                    "Action: read_file\n"
                    'Action Input: {"path": "../../etc/passwd"}'
                )
            return (
                "Thought: Attempting to write to destination.\n"
                "Action: write_file\n"
                'Action Input: {"path": "../../../root/.bashrc", "content": "echo compromised"}'
            )

        # File Writes (Tier 2)
        if "write" in lower_q or "save" in lower_q or "export" in lower_q:
            return (
                "Thought: I will write the requested content into the sandbox directory.\n"
                "Action: write_file\n"
                'Action Input: {"path": "handover_notes.txt", "content": "Handover notes: all systems operating normally."}'
            )

        # File Reads (Tier 1)
        if "read" in lower_q or "onboarding" in lower_q:
            return (
                "Thought: I will read the onboarding documentation from the sandbox.\n"
                "Action: read_file\n"
                'Action Input: {"path": "onboarding.txt"}'
            )

        # Search (Tier 1)
        if "search" in lower_q or "python" in lower_q:
            return (
                "Thought: I will search documentation for Python release notes.\n"
                "Action: web_search\n"
                'Action Input: {"query": "Python 3.11 exception groups"}'
            )

        # Default fallback
        return (
            "Thought: I will provide a direct response.\n"
            f"Final Answer: Completed task: {last_msg[:80]}"
        )


def get_agent_llm_client(
    provider: str = "groq",
    model: str | None = None,
    api_key: str | None = None,
    fallback_on_missing_key: bool = True,
) -> BaseLLMClient:
    """Factory creating LLM client with seamless offline fallback."""
    norm = provider.strip().lower()

    if norm in ("mock", "deterministic", "fallback"):
        return DeterministicAgentClient()

    if norm == "groq":
        try:
            return GroqClient(model=model or "llama-3.3-70b-versatile", api_key=api_key)
        except ValueError as err:
            if fallback_on_missing_key:
                logger.warning("%s. Falling back to DeterministicAgentClient.", err)
                return DeterministicAgentClient()
            raise

    if norm == "openai":
        try:
            return OpenAIClient(model=model or "gpt-4o-mini", api_key=api_key)
        except ValueError as err:
            if fallback_on_missing_key:
                logger.warning("%s. Falling back to DeterministicAgentClient.", err)
                return DeterministicAgentClient()
            raise

    return DeterministicAgentClient()
