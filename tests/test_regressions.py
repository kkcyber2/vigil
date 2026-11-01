"""Regression tests for the two bugs found while building this.

Both were found by running the engine, not by reading it, and both were the kind
that pass a casual review: the audit trail looked healthy in each case while the
system did the wrong thing.
"""

from __future__ import annotations

import pytest

from vigil.actuator import RecordingActuator
from vigil.audit import AuditLog
from vigil.engine import Engine
from vigil.models import Process, Snapshot
from vigil.response import ResponsePolicy
from vigil.rules import Condition, MatchMode, Rule, RuleSet, Severity


def kill_ruleset() -> RuleSet:
    rs = RuleSet()
    rs.add(
        Rule(
            id="kill-tmp",
            title="t",
            severity=Severity.CRITICAL,
            scope="process",
            action="kill",
            conditions=(Condition("exe", MatchMode.CONTAINS, "/tmp/"),),
        )
    )
    return rs


def target(pid: int = 4242, uid: int = 1000) -> Process:
    return Process(pid=pid, name="x", exe="/tmp/x", uid=uid)


class TestAuditLogNotDiscarded:
    def test_caller_supplied_audit_log_receives_entries(self):
        """Bug 1: AuditLog defined __len__, so an empty log was falsy.

        `self.audit = audit or AuditLog()` then replaced the caller's log with
        a fresh one. Every entry went to the discarded instance and the caller
        saw an empty log while believing it had a full record.
        """
        mine = AuditLog()
        engine = Engine(rules=kill_ruleset(), audit=mine)
        engine.run(Snapshot(processes=[target()]))

        assert mine.count > 0
        assert engine.audit is mine

    def test_empty_audit_log_is_not_falsy(self):
        """The root cause, asserted directly.

        If AuditLog ever regains __len__, this fails and the engine's identity
        check above becomes load-bearing again.
        """
        log = AuditLog()
        assert bool(log) is True

    def test_len_is_not_defined(self):
        log = AuditLog()
        assert not hasattr(log, "__len__") or "__len__" in type(log).__dict__

    def test_count_property_reports_correctly(self):
        log = AuditLog()
        assert log.count == 0
        log.record("process", "pid:1", "r", "low", "alert", False)
        assert log.count == 1


class TestProcessReachesActuator:
    def test_kill_action_actually_reaches_actuator(self):
        """Bug 2: Detection rebuilt its process from a dict that was never set.

        The process-scoped path left context["process"] as None, so _respond
        saw no process and every kill was logged "skipped: no process to kill".
        The audit trail looked healthy; nothing was ever killed.
        """
        actuator = RecordingActuator()
        engine = Engine(
            rules=kill_ruleset(),
            policy=ResponsePolicy(dry_run=False, max_action="kill"),
            actuator=actuator,
        )
        report = engine.run(Snapshot(processes=[target()]))

        assert report.actions_executed == 1
        assert len(actuator.calls) == 1
        assert actuator.calls[0].action == "kill"
        assert actuator.calls[0].subject == "pid:4242"

    def test_no_action_is_silently_skipped(self):
        """A skipped action means a mis-scoped rule; it must be counted."""
        actuator = RecordingActuator()
        report = Engine(
            rules=kill_ruleset(),
            policy=ResponsePolicy(dry_run=False, max_action="kill"),
            actuator=actuator,
        ).run(Snapshot(processes=[target()]))

        assert report.actions_skipped == 0

    def test_detection_carries_the_live_process(self):
        det = Engine(rules=kill_ruleset()).evaluate(Snapshot(processes=[target()]))[0]
        assert det.process is not None
        assert det.process.pid == 4242

    def test_connection_detection_carries_both_objects(self):
        from vigil.models import Connection

        proc = target()
        conn = Connection(
            pid=4242, local_addr="10.0.0.5", local_port=1,
            remote_addr="203.0.113.9", remote_port=443,
        )
        rs = RuleSet()
        rs.add(
            Rule(
                id="egress", title="t", severity=Severity.HIGH, scope="connection",
                action="block",
                conditions=(Condition("process.exe", MatchMode.CONTAINS, "/tmp/"),),
            )
        )
        det = Engine(rules=rs).evaluate(
            Snapshot(processes=[proc], connections=[conn])
        )[0]
        assert det.process is not None
        assert det.connection is not None
        assert det.subject == "pid:4242"

    def test_block_on_process_detection_is_skipped_not_crashing(self):
        """A block rule scoped to a process has no connection to block."""
        rs = RuleSet()
        rs.add(
            Rule(
                id="bad-scope", title="t", severity=Severity.CRITICAL,
                scope="process", action="block",
                conditions=(Condition("exe", MatchMode.CONTAINS, "/tmp/"),),
            )
        )
        actuator = RecordingActuator()
        report = Engine(
            rules=rs,
            policy=ResponsePolicy(dry_run=False, max_action="block"),
            actuator=actuator,
        ).run(Snapshot(processes=[target()]))

        assert report.actions_executed == 0
        assert report.actions_skipped == 1
        assert actuator.calls == []


class TestEndToEndOrdering:
    def test_dry_run_leaves_actuator_untouched_but_logs(self):
        actuator = RecordingActuator()
        audit = AuditLog()
        report = Engine(
            rules=kill_ruleset(),
            policy=ResponsePolicy(dry_run=True, max_action="kill"),
            actuator=actuator,
            audit=audit,
        ).run(Snapshot(processes=[target()]))

        assert report.actions_planned == 1
        assert report.actions_executed == 0
        assert actuator.calls == []
        assert audit.count == 1
        assert "dry_run" in audit.entries[0].detail

    def test_init_is_never_killed_even_with_every_permission(self):
        """The single most important end-to-end assertion in the suite."""
        actuator = RecordingActuator()
        Engine(
            rules=kill_ruleset(),
            policy=ResponsePolicy(
                dry_run=False,
                max_action="kill",
                protected_uids=set(),  # even with root unprotected
            ),
            actuator=actuator,
        ).run(Snapshot(processes=[target(pid=1, uid=0)]))

        assert actuator.calls == []
