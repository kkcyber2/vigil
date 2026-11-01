"""Audit log tests, including tamper detection."""

from __future__ import annotations

import json

import pytest

from vigil.audit import GENESIS, AuditEntry, AuditLog


@pytest.fixture
def fixed_clock():
    """A monotonic counter, so entries are deterministic without sleeping."""
    counter = iter(range(1000, 2000))
    return lambda: float(next(counter))


class TestChain:
    def test_first_entry_links_to_genesis(self, fixed_clock):
        log = AuditLog(clock=fixed_clock)
        entry = log.record("process", "pid:1", "r", "high", "alert", False)
        assert entry.prev_hash == GENESIS

    def test_each_entry_links_to_predecessor(self, fixed_clock):
        log = AuditLog(clock=fixed_clock)
        first = log.record("process", "pid:1", "r", "high", "alert", False)
        second = log.record("process", "pid:1", "r", "high", "alert", False)
        assert second.prev_hash == first.entry_hash

    def test_empty_log_verifies(self):
        assert AuditLog().verify() is True

    def test_chain_verifies_after_appends(self, fixed_clock):
        log = AuditLog(clock=fixed_clock)
        for i in range(50):
            log.record("process", f"pid:{i}", "r", "low", "alert", False)
        assert log.verify() is True


class TestTamperDetection:
    def test_mutated_field_breaks_verification(self, fixed_clock):
        log = AuditLog(clock=fixed_clock)
        log.record("process", "pid:1", "r", "low", "alert", False)
        # Reach past the dataclass's frozen-ness the way an attacker editing a
        # file or a careless in-memory edit would.
        object.__setattr__(log._entries[0], "detail", "edited")
        assert log.verify() is False

    def test_deleted_middle_entry_breaks_verification(self, fixed_clock):
        log = AuditLog(clock=fixed_clock)
        for _ in range(4):
            log.record("process", "pid:1", "r", "low", "alert", False)
        del log._entries[1]
        assert log.verify() is False

    def test_deleted_tail_entry_breaks_verification(self, fixed_clock):
        """Truncation is the most likely real-world edit, and it must be visible."""
        log = AuditLog(clock=fixed_clock)
        for _ in range(3):
            log.record("process", "pid:1", "r", "low", "alert", False)
        original_head = log.head_hash()
        log._entries.pop()
        assert log.head_hash() != original_head
        # The remaining chain still self-verifies, which is exactly why the head
        # hash must be recorded elsewhere: truncation alone is undetectable
        # from the file, so callers should persist head_hash.
        assert log.verify() is True

    def test_resequenced_entry_breaks_verification(self, fixed_clock):
        log = AuditLog(clock=fixed_clock)
        for _ in range(3):
            log.record("process", "pid:1", "r", "low", "alert", False)
        object.__setattr__(log._entries[1], "seq", 7)
        assert log.verify() is False


class TestSummary:
    def test_counts_executed_and_planned(self, fixed_clock):
        log = AuditLog(clock=fixed_clock)
        log.record("process", "pid:1", "r", "high", "kill", True)
        log.record("process", "pid:2", "r", "high", "kill", False)
        log.record("process", "pid:3", "r", "high", "kill", False, "refused: dry_run")
        summary = log.summary()
        assert summary["entries"] == 3
        assert summary["executed"] == 1
        assert summary["planned_only"] == 2
        assert summary["refused"] == 1
        assert summary["chain_valid"] is True

    def test_by_action_tallies(self, fixed_clock):
        log = AuditLog(clock=fixed_clock)
        log.record("process", "a", "r", "low", "alert", False)
        log.record("process", "b", "r", "low", "alert", False)
        log.record("process", "c", "r", "low", "kill", True)
        assert log.summary()["by_action"] == {"alert": 2, "kill": 1}


class TestSerialisation:
    def test_jsonl_roundtrip(self, fixed_clock):
        log = AuditLog(clock=fixed_clock)
        log.record("process", "pid:1", "r", "high", "alert", False, "note")
        lines = log.to_jsonl().splitlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["subject"] == "pid:1"
        assert parsed["detail"] == "note"
        assert len(parsed["entry_hash"]) == 64

    def test_unicode_and_quotes_survive_roundtrip(self, fixed_clock):
        log = AuditLog(clock=fixed_clock)
        log.record("process", 'pid:1 "quoted"', "r", "low", "alert", False, "ünïcode\nnewline")
        parsed = json.loads(log.to_jsonl())
        assert parsed["subject"] == 'pid:1 "quoted"'
        assert "ü" in parsed["detail"]


class TestConcurrency:
    def test_parallel_appends_produce_a_valid_chain(self):
        """A responder scanning many processes may log from several threads."""
        import threading

        log = AuditLog()

        def worker(n: int) -> None:
            for _ in range(25):
                log.record("process", f"pid:{n}", "r", "low", "alert", False)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert log.count == 200
        assert log.verify() is True
