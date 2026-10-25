"""Unit tests for cryptographic hash-chained audit logger and tamper detection."""

from __future__ import annotations

import json
from pathlib import Path

from guardagent.audit.logger import GENESIS_HASH, HashChainedAuditLogger
from guardagent.audit.schemas import compute_event_hash
from guardagent.schemas.action import ActionTier, ApprovalStatus


def test_compute_event_hash_deterministic():
    h1 = compute_event_hash(
        event_id="evt_01",
        timestamp="2026-10-25T00:00:00Z",
        step_number=1,
        event_type="action_executed",
        tool_name="calculate",
        arguments={"expression": "10+5"},
        tier="tier_1_read",
        approval_status="auto_approved",
        previous_hash=GENESIS_HASH,
    )
    h2 = compute_event_hash(
        event_id="evt_01",
        timestamp="2026-10-25T00:00:00Z",
        step_number=1,
        event_type="action_executed",
        tool_name="calculate",
        arguments={"expression": "10+5"},
        tier="tier_1_read",
        approval_status="auto_approved",
        previous_hash=GENESIS_HASH,
    )
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 length


def test_audit_logger_empty_log_valid(tmp_path: Path):
    log_file = tmp_path / "empty_audit.jsonl"
    logger = HashChainedAuditLogger(log_path=log_file)

    is_valid, count, err = logger.verify_integrity()
    assert is_valid is True
    assert count == 0
    assert err is None


def test_audit_logger_sequential_chain(tmp_path: Path):
    log_file = tmp_path / "test_audit.jsonl"
    logger = HashChainedAuditLogger(log_path=log_file)

    evt1 = logger.log_event(
        step_number=1,
        event_type="action_executed",
        tool_name="calculate",
        arguments={"expression": "2+2"},
        tier=ActionTier.TIER_1_READ,
        approval_status=ApprovalStatus.AUTO_APPROVED,
        execution_success=True,
    )
    assert evt1.previous_hash == GENESIS_HASH

    evt2 = logger.log_event(
        step_number=2,
        event_type="action_executed",
        tool_name="write_file",
        arguments={"path": "note.txt", "content": "data"},
        tier=ActionTier.TIER_2_MUTATION,
        approval_status=ApprovalStatus.APPROVED,
        reviewer="admin",
        execution_success=True,
    )
    assert evt2.previous_hash == evt1.current_hash

    is_valid, count, err = logger.verify_integrity()
    assert is_valid is True
    assert count == 2
    assert err is None


def test_audit_logger_detects_tampered_payload(tmp_path: Path):
    log_file = tmp_path / "tampered_audit.jsonl"
    logger = HashChainedAuditLogger(log_path=log_file)

    logger.log_event(step_number=1, event_type="action_executed", tool_name="calculate")
    logger.log_event(step_number=2, event_type="action_executed", tool_name="read_file")
    logger.log_event(step_number=3, event_type="action_executed", tool_name="write_file")

    is_valid, count, _ = logger.verify_integrity()
    assert is_valid is True
    assert count == 3

    # Tamper with the middle record: change tool_name without updating hash
    lines = log_file.read_text(encoding="utf-8").splitlines()
    data2 = json.loads(lines[1])
    data2["tool_name"] = "unauthorized_malicious_tool"
    lines[1] = json.dumps(data2)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Re-verify -> must detect corruption
    is_valid_after, verified_up_to, err = logger.verify_integrity()
    assert is_valid_after is False
    assert verified_up_to == 1
    assert "tampered" in err.lower() or "broken" in err.lower()


def test_audit_logger_detects_broken_chain(tmp_path: Path):
    log_file = tmp_path / "broken_chain_audit.jsonl"
    logger = HashChainedAuditLogger(log_path=log_file)

    logger.log_event(step_number=1, event_type="action_executed")
    logger.log_event(step_number=2, event_type="action_executed")

    # Modify previous_hash of record 2
    lines = log_file.read_text(encoding="utf-8").splitlines()
    data2 = json.loads(lines[1])
    data2["previous_hash"] = "f" * 64
    lines[1] = json.dumps(data2)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    is_valid, _, err = logger.verify_integrity()
    assert is_valid is False
    assert "broken" in err.lower()
