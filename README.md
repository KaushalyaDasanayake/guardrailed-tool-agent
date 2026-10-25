# Guardrailed Tool-Calling Agent (`guardagent`)

Autonomous ReAct tool-calling agent featuring deterministic planning loops, tiered security guardrails, Human-in-the-Loop (HITL) permission gates, and tamper-evident SHA-256 hash-chained audit trails.

---

## Architecture Overview
- **Planning Loop**: Stateful ReAct execution (`Thought -> Action -> Observation -> Final Answer`) with iteration and cycle guards.
- **Tiered Security Guardrails**:
  - **Tier 1 (Read-Only / Safe)**: Auto-approved reads (`SELECT`, math expressions, sandbox file reads, web queries).
  - **Tier 2 (Sensitive / Mutation)**: Requires human confirmation (`INSERT`, `UPDATE`, writing sandbox files).
  - **Tier 3 (Forbidden / Malicious)**: Strict policy veto (`DROP TABLE`, `DELETE FROM`, path traversal `../../`, shell commands).
- **Human-in-the-Loop Interceptor**: Synchronous CLI and asynchronous Web UI approval hooks with graceful denial replanning.
- **Audit Ledger**: Append-only JSONL event trail with cryptographic hash chaining ensuring log integrity.
- **Evaluation**: 20 frozen golden test scenarios evaluating safety refusal and tool execution accuracy.

---

## Quickstart

### 1. Installation
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Run Test Suite & Linter
```bash
pytest -v
ruff check .
```
