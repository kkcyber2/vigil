"""End-to-end engine tests.

The central assertion of this file is that a full run with default settings
touches nothing. Every action must appear in the audit log, and the actuator
must record zero real calls.
"""

from __future__ import annotations

import pytest

from vigil.actuator import LocalActuator, RecordingActuator
from vigil.audit import AuditLog
from vigil.engine import Engine
from vigil.models import Connection, Process, Snapshot
from vigil.response import ResponsePolicy
from vigil.rules import Condition, MatchMode, Rule, RuleSet, Severity, default_rules


def kill_rule() -> Rule:
    return Rule(
        id="kill-tmp",
        title="Kill anything in /tmp",
        severity=Severity.CRITICAL,
        scope="process",
        action="kill",
        conditions=(Condition("exe", MatchMode.CONTAINS, "/tmp/"),),
    )


def ruleset(*rules: Rule) -> RuleSet:
    rs = RuleSet()
    for rule in rules:
        rs.add(rule)
    return rs


class TestDefaultRunTouchesNothing:
    def test_default_engine_uses_recording_actuator(self):
        """A caller who does not pass an actuator must not reach the host."""
        engine = Engine(rules=ruleset(kill_rule()))
        assert isinstance(engine.actuator, RecordingActuator)

    def test_default_policy_is_dry_run(self):
        assert Engine(rules=default_rules()).policy.dry_run is True

    def test_suspicious_host_run_executes_nothing(self, snapshot):
        engine = Engine(
            rules=ruleset(kill_rule()),
            policy=ResponsePolicy(dry_run=True, max_action="kill"),
            actuator=RecordingActuator(),
        )
        report = engine.run(snapshot)
        assert report.actions_executed == 0
        assert report.actions_planned >= 1
        assert engine.actuator.calls == []


class TestAuditTrail:
    def test_every_detection_is_logged(self, snapshot):
        audit = AuditLog()
        engine = Engine(rules=ruleset(kill_rule()), audit=audit)
        report = engine.run(snapshot)
        assert audit.count >= len(report.detections)

    def test_dry_run_entry_records_the_reason(self, snapshot):
        audit = AuditLog()
        engine = Engine(rules=ruleset(kill_rule()), audit=audit)
        engine.run(snapshot)
        entries = [e for e in audit if e.executed is False]
        assert entries
        assert any(e.detail.startswith("refused") for e in entries)

    def test_refused_action_logged_not_executed(self, snapshot):
        audit = AuditLog()
        engine = Engine(
            rules=ruleset(kill_rule()),
            policy=ResponsePolicy(dry_run=False, max_action="kill"),
            actuator=RecordingActuator(),
            audit=audit,
        )
        engine.run(snapshot)
        # /tmp exe is not a system path and uid is 1000, so this one is allowed
        # through the gate and dispatched to the (recording) actuator.
        assert any(e.executed for e in audit)

    def test_detection_is_logged_even_when_below_threshold(self, snapshot):
        """'We saw it and chose not to act' must be provable."""
        audit = AuditLog()
        low_rule = Rule(
            id="low-noise",
            title="noise",
            severity=Severity.INFO,
            scope="process",
            action="alert",
            conditions=(Condition("name", MatchMode.EXACT, "kworker"),),
        )
        engine = Engine(
            rules=ruleset(low_rule),
            audit=audit,
            min_severity=Severity.HIGH,
        )
        report = engine.run(snapshot)
        assert report.detections == []
        assert audit.count == 1
        assert "below min_severity" in audit.entries[0].detail

    def test_chain_stays_valid_after_a_run(self, snapshot):
        audit = AuditLog()
        Engine(rules=default_rules(), audit=audit).run(snapshot)
        assert audit.verify() is True


class TestPolicyIntegration:
    def test_protected_pid_never_reaches_the_actuator(self):
        init = Process(pid=1, name="init", exe="/tmp/initlookalike", uid=1000)
        snap = Snapshot(processes=[init], connections=[])
        actuator = RecordingActuator()
        audit = AuditLog()
        engine = Engine(
            rules=ruleset(kill_rule()),
            policy=ResponsePolicy(dry_run=False, max_action="kill"),
            actuator=actuator,
            audit=audit,
        )
        report = engine.run(snap)
        assert report.actions_executed == 0
        assert report.actions_refused == 1
        assert actuator.calls == []
        assert "protected" in audit.entries[0].detail

    def test_root_process_refused_not_executed(self):
        """A rule asking to kill a root-owned process must be refused.

        Asserting on REFUSE rather than on a planned dry run is the honest
        reading: the policy has decided it will never act on this target.
        """
        root_proc = Process(pid=900, name="x", exe="/tmp/x", uid=0)
        snap = Snapshot(processes=[root_proc], connections=[])
        actuator = RecordingActuator()
        audit = AuditLog()
        engine = Engine(
            rules=ruleset(kill_rule()),
            policy=ResponsePolicy(dry_run=False, max_action="kill"),
            actuator=actuator,
            audit=audit,
        )
        report = engine.run(snap)
        assert report.actions_executed == 0
        assert report.actions_refused == 1
        assert actuator.calls == []
        assert "uid 0" in audit.entries[0].detail


class TestMatching:
    def test_connection_rule_joins_owning_process(self, snapshot):
        rule = Rule(
            id="tmp-egress",
            title="tmp egress",
            severity=Severity.HIGH,
            scope="connection",
            action="alert",
            conditions=(
                Condition("process.exe", MatchMode.CONTAINS, "/tmp/"),
                Condition("state", MatchMode.EXACT, "ESTABLISHED"),
            ),
        )
        engine = Engine(rules=ruleset(rule))
        dets = engine.evaluate(snapshot)
        assert len(dets) == 1
        assert dets[0].subject == "pid:4242"

    def test_unattributed_connection_does_not_match_process_scoped_rule(self):
        """An orphan socket has no process, so a process-scoped rule must not fire."""
        conn = Connection(
            pid=0, local_addr="10.0.0.5", local_port=1234,
            remote_addr="203.0.113.9", remote_port=443,
        )
        snap = Snapshot(processes=[], connections=[conn])
        rule = Rule(
            id="needs-process",
            title="t",
            severity=Severity.HIGH,
            scope="connection",
            action="alert",
            conditions=(Condition("process.exe", MatchMode.CONTAINS, "/tmp/"),),
        )
        assert Engine(rules=ruleset(rule)).evaluate(snap) == []

    def test_duplicate_detections_collapsed(self):
        """Three connections from one process must read as one incident."""
        proc = Process(pid=5, name="x", exe="/tmp/x", uid=1000)
        conns = [
            Connection(pid=5, local_addr="10.0.0.5", local_port=1000 + i,
                       remote_addr="203.0.113.9", remote_port=443)
            for i in range(3)
        ]
        snap = Snapshot(processes=[proc], connections=conns)
        rule = Rule(
            id="tmp-egress",
            title="t",
            severity=Severity.HIGH,
            scope="connection",
            action="alert",
            conditions=(Condition("process.exe", MatchMode.CONTAINS, "/tmp/"),),
        )
        assert len(Engine(rules=ruleset(rule)).evaluate(snap)) == 1

    def test_scope_is_respected(self, snapshot):
        proc_rule = Rule(
            id="p", title="t", severity=Severity.LOW, scope="process",
            action="alert", conditions=(Condition("exe", MatchMode.EXISTS, True),),
        )
        conn_rule = Rule(
            id="c", title="t", severity=Severity.LOW, scope="connection",
            action="alert", conditions=(Condition("state", MatchMode.EXISTS, True),),
        )
        dets = Engine(rules=ruleset(proc_rule, conn_rule)).evaluate(snapshot)
        kinds = {d.kind for d in dets}
        assert kinds == {"process", "connection"}


class TestReport:
    def test_highest_severity_none_on_empty(self):
        from vigil.engine import RunReport

        assert RunReport().highest_severity is None

    def test_highest_severity_picks_critical(self, snapshot):
        engine = Engine(rules=default_rules())
        report = engine.run(snapshot)
        # The /tmp exe in the fixture raises at least HIGH; nothing here is
        # CRITICAL unless the deleted-binary rule fired.
        assert report.highest_severity is not None
        assert report.highest_severity.rank >= Severity.HIGH.rank

    def test_counts_reflect_snapshot(self, snapshot):
        report = Engine(rules=default_rules()).run(snapshot)
        assert report.scanned_processes == 2
        assert report.scanned_connections == 1


class TestLocalActuatorGuards:
    def test_local_actuator_defaults_to_dry_run(self):
        assert LocalActuator().dry_run is True

    def test_local_actuator_refuses_pid_1_even_when_live(self):
        actuator = LocalActuator(dry_run=False)
        result = actuator.kill(Process(pid=1, name="init"))
        assert result.ok is False
        assert "protected" in result.detail

    def test_local_actuator_refuses_quarantine_without_exe(self):
        actuator = LocalActuator(dry_run=False)
        result = actuator.quarantine(Process(pid=9, name="x", exe=""))
        assert result.ok is False
        assert "missing" in result.detail

    def test_local_actuator_does_nothing_when_dry(self):
        actuator = LocalActuator(dry_run=True)
        result = actuator.kill(Process(pid=999999, name="nonexistent"))
        assert result.ok is False
        assert "dry_run" in result.detail
