"""Append-only cryptographic hash-chained audit logger with tamper verification."""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardagent.audit.schemas import AuditEvent, compute_event_hash
from guardagent.schemas.action import ActionTier, ApprovalStatus

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


class HashChainedAuditLogger:
    """Manages append-only audit trail with SHA-256 hash chaining to detect tampering."""

    def __init__(self, log_path: str | Path = "audit_logs/audit_trail.jsonl") -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._get_latest_hash()

    def _get_latest_hash(self) -> str:
        """Read the hash of the most recent log line, or return GENESIS_HASH if empty."""
        if not self.log_path.exists():
            return GENESIS_HASH

        lines = [line.strip() for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return GENESIS_HASH

        try:
            last_entry = json.loads(lines[-1])
            return str(last_entry.get("current_hash", GENESIS_HASH))
        except json.JSONDecodeError:
            logger.error("Failed to decode last line of audit log; starting fresh hash chain")
            return GENESIS_HASH

    def log_event(
        self,
        step_number: int,
        event_type: str,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
        tier: ActionTier = ActionTier.TIER_1_READ,
        approval_status: ApprovalStatus = ApprovalStatus.AUTO_APPROVED,
        reviewer: str | None = None,
        approval_comment: str | None = None,
        execution_success: bool | None = None,
        output_summary: str | None = None,
        latency_ms: float = 0.0,
        session_id: str = "default_session",
    ) -> AuditEvent:
        """Record an immutable, hash-chained audit event."""
        with self._lock:
            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            timestamp = datetime.now(timezone.utc).isoformat()
            args = arguments or {}
            clean_summary = output_summary[:200] if output_summary else None

            current_hash = compute_event_hash(
                event_id=event_id,
                timestamp=timestamp,
                step_number=step_number,
                event_type=event_type,
                tool_name=tool_name,
                arguments=args,
                tier=tier.value,
                approval_status=approval_status.value,
                previous_hash=self._last_hash,
                reviewer=reviewer,
                approval_comment=approval_comment,
                execution_success=execution_success,
                output_summary=clean_summary,
            )

            event = AuditEvent(
                event_id=event_id,
                timestamp=timestamp,
                session_id=session_id,
                step_number=step_number,
                event_type=event_type,
                tool_name=tool_name,
                arguments=args,
                tier=tier,
                approval_status=approval_status,
                reviewer=reviewer,
                approval_comment=approval_comment,
                execution_success=execution_success,
                output_summary=clean_summary,
                latency_ms=latency_ms,
                previous_hash=self._last_hash,
                current_hash=current_hash,
            )

            # Append to log file
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")

            self._last_hash = current_hash
            return event

    def read_events(self, limit: int | None = None) -> list[AuditEvent]:
        """Read recorded audit events in chronological order."""
        if not self.log_path.exists():
            return []

        lines = [line.strip() for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        events: list[AuditEvent] = []
        for line in lines:
            try:
                events.append(AuditEvent.model_validate_json(line))
            except Exception as err:
                logger.error("Skipping corrupted audit record: %s", err)

        if limit is not None:
            if limit <= 0:
                return []
            return events[-limit:]
        return events

    def verify_integrity(self) -> tuple[bool, int, str | None]:
        """Verify the cryptographic SHA-256 chain across all historical events.

        Returns: (is_valid, verified_count, error_message)
        """
        events = self.read_events()
        if not events:
            return True, 0, None

        expected_prev = GENESIS_HASH

        for idx, event in enumerate(events):
            # 1. Verify previous_hash matches
            if event.previous_hash != expected_prev:
                return (
                    False,
                    idx,
                    f"Broken hash chain at event {idx} ({event.event_id}): expected previous_hash {expected_prev[:12]}, got {event.previous_hash[:12]}",
                )

            # 2. Recompute current_hash
            recomputed = compute_event_hash(
                event_id=event.event_id,
                timestamp=event.timestamp,
                step_number=event.step_number,
                event_type=event.event_type,
                tool_name=event.tool_name,
                arguments=event.arguments,
                tier=event.tier.value,
                approval_status=event.approval_status.value,
                previous_hash=event.previous_hash,
                reviewer=event.reviewer,
                approval_comment=event.approval_comment,
                execution_success=event.execution_success,
                output_summary=event.output_summary,
            )

            if event.current_hash != recomputed:
                return (
                    False,
                    idx,
                    f"Tampered record at event {idx} ({event.event_id}): recomputed hash {recomputed[:12]} does not match current_hash {event.current_hash[:12]}",
                )

            expected_prev = event.current_hash

        return True, len(events), None
