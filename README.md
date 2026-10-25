# Guardrailed Tool-Calling Agent (`guardagent`)

Autonomous ReAct tool-calling agent featuring deterministic planning loops, tiered security guardrails, Human-in-the-Loop (HITL) permission gates, and tamper-evident SHA-256 hash-chained audit trails.

---

## Architecture Overview
- **Planning Loop**: Stateful ReAct execution (`Thought -> Action -> Observation -> Final Answer`) with iteration depth guards and cycle detection.
- **Tiered Security Guardrails**:
  - **Tier 1 (Read-Only / Safe)**: Auto-approved reads (`SELECT`, math expressions, sandbox file reads, web queries).
  - **Tier 2 (Sensitive / Mutation)**: Requires human confirmation (`INSERT`, `UPDATE`, writing sandbox files).
  - **Tier 3 (Forbidden / Malicious)**: Strict policy veto (`DROP TABLE`, `DELETE FROM`, path traversal `../../`, prompt injection).
- **Human-in-the-Loop Interceptor**: Synchronous CLI and interactive Web UI approval hooks with graceful denial replanning.
- **Cryptographic Audit Ledger**: Append-only JSONL event trail with SHA-256 hash chaining ensuring mathematical tamper detection.
- **Evaluation**: 20 frozen golden test scenarios evaluating safety refusal and tool execution accuracy.
- **Interface**: Interactive Streamlit Studio with live step tracing and audit verification.

---

## Security Benchmark (20 Golden Scenarios)

Evaluated on `eval/scenarios.jsonl` covering read operations, write mutations, path traversal, SQL injection, and system override attempts:

| Metric | Target | Result |
|---|---|---|
| **Tier Classification Accuracy** | $\ge 95\%$ | **100.00%** |
| **Tier 3 Forbidden Block Rate** | $100\%$ | **100.00%** |
| **Cryptographic Audit Integrity** | $100\%$ | **100.00%** (0 broken links) |

---

## Quickstart

### 1. Installation
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"
```

### 2. Seed Database
```bash
python scripts/seed_db.py
```

### 3. Run Test Suite & Linter
```bash
pytest -v
ruff check .
```

### 4. Run Security Benchmark
```bash
python scripts/run_scenarios.py
```

### 5. Launch Streamlit Studio
```bash
streamlit run streamlit_app.py
```

---

## Milestones Delivered
- [x] **M0: Environment Setup, Tool Contracts & Golden Scenarios**
- [x] **M1: Core ReAct Agent Loop & Built-in Safe Tools**
- [x] **M2: Security Guardrail Engine & Policy Tiering**
- [x] **M3: Human-in-the-Loop (HITL) Interceptor & Permission Workflow**
- [x] **M4: Cryptographic Audit Trail & Observability**
- [x] **M5: Interactive Streamlit Studio & Benchmark Suite**
