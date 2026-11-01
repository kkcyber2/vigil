"""The engine: evaluate a snapshot against rules, then respond within policy.

The control flow is deliberately linear and auditable:

    snapshot -> context -> match rules -> policy gate -> actuator -> audit

No rule can act directly. No actuator call happens without a policy decision
logged immediately before it. That ordering is the whole safety argument.

A note on why Detection carries live objects rather than serialised dicts:
the first version of this file rebuilt a Process from `context["process"]` at
respond time. Because the process-scoped path never populated that dict, every
kill was logged as "skipped: no process to kill" while the audit trail looked
healthy. Carrying the object makes that failure impossible to express.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .actuator import ActionResult, Actuator, RecordingActuator
from .audit import AuditLog
from .models import Connection, Process, Snapshot
from .response import Decision, ResponsePolicy
from .rules import RuleSet, Severity


@dataclass
class Detection:
    rule_id: str
    rule_title: str
    severity: Severity
    action: str
    subject: str
    kind: str
    description: str = ""
    # The live objects the rule fired on. Exactly one of these is set for a
    # well-formed detection; an "alert" may fire with neither.
    process: Optional[Process] = None
    connection: Optional[Connection] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.rule_title,
            "severity": self.severity.value,
            "action": self.action,
            "subject": self.subject,
            "kind": self.kind,
            "description": self.description,
            "process": self.process.to_dict() if self.process else None,
            "connection": self.connection.to_dict() if self.connection else None,
        }


@dataclass
class RunReport:
    detections: List[Detection] = field(default_factory=list)
    actions_executed: int = 0
    actions_planned: int = 0
    actions_refused: int = 0
    actions_skipped: int = 0
    scanned_processes: int = 0
    scanned_connections: int = 0

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.detections:
            return None
        return max(self.detections, key=lambda d: d.severity.rank).severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detections": [d.to_dict() for d in self.detections],
            "actions_executed": self.actions_executed,
            "actions_planned": self.actions_planned,
            "actions_refused": self.actions_refused,
            "actions_skipped": self.actions_skipped,
            "scanned_processes": self.scanned_processes,
            "scanned_connections": self.scanned_connections,
            "highest_severity": (
                self.highest_severity.value if self.highest_severity else None
            ),
        }


class Engine:
    """Wires rules, policy, actuator and audit log together."""

    def __init__(
        self,
        rules: RuleSet,
        policy: Optional[ResponsePolicy] = None,
        actuator: Optional[Actuator] = None,
        audit: Optional[AuditLog] = None,
        min_severity: Severity = Severity.LOW,
    ) -> None:
        self.rules = rules
        # Explicit None checks, not `x or Default()`. AuditLog is a container,
        # and a falsy empty one was silently replaced by a fresh instance --
        # the caller then never saw a single entry and had no idea.
        self.policy = policy if policy is not None else ResponsePolicy()
        # Default to the recording actuator, never LocalActuator: a caller who
        # wants to touch the host must say so in code.
        self.actuator = actuator if actuator is not None else RecordingActuator()
        self.audit = audit if audit is not None else AuditLog()
        self.min_severity = min_severity

    # -- matching ---------------------------------------------------------

    def evaluate(self, snapshot: Snapshot) -> List[Detection]:
        """Match rules against a snapshot without responding."""
        detections: List[Detection] = []
        index = snapshot.process_index()

        for proc in snapshot.processes:
            ctx = snapshot.context_for_process(proc)
            for rule in self.rules:
                if rule.matches(ctx):
                    detections.append(
                        Detection(
                            rule_id=rule.id,
                            rule_title=rule.title,
                            severity=rule.severity,
                            action=rule.action,
                            subject=proc.subject(),
                            kind="process",
                            description=rule.description,
                            process=proc,
                        )
                    )

        for conn in snapshot.connections:
            owner = index.get(conn.pid)
            ctx = snapshot.context_for_connection(conn, owner)
            for rule in self.rules:
                if rule.matches(ctx):
                    detections.append(
                        Detection(
                            rule_id=rule.id,
                            rule_title=rule.title,
                            severity=rule.severity,
                            action=rule.action,
                            # Attribute to the process when known, so the
                            # operator sees "pid:4242" rather than a socket
                            # tuple they cannot act on.
                            subject=owner.subject() if owner else conn.subject(),
                            kind="connection",
                            description=rule.description,
                            process=owner,
                            connection=conn,
                        )
                    )

        return self._dedupe(detections)

    @staticmethod
    def _dedupe(detections: List[Detection]) -> List[Detection]:
        """Collapse identical rule+subject pairs.

        A process with three connections to the same host would otherwise
        produce three identical findings, and the operator would read that as
        three incidents.
        """
        seen = set()
        out: List[Detection] = []
        for det in detections:
            key = (det.rule_id, det.subject)
            if key in seen:
                continue
            seen.add(key)
            out.append(det)
        return out

    # -- response ---------------------------------------------------------

    def run(self, snapshot: Snapshot) -> RunReport:
        """Evaluate and respond. This is the entry point the CLI calls."""
        report = RunReport(
            scanned_processes=len(snapshot.processes),
            scanned_connections=len(snapshot.connections),
        )

        for det in self.evaluate(snapshot):
            if det.severity.rank < self.min_severity.rank:
                # Still recorded: "we saw it and chose not to act" is a
                # decision worth being able to prove later.
                self.audit.record(
                    kind=det.kind,
                    subject=det.subject,
                    rule_id=det.rule_id,
                    severity=det.severity.value,
                    action=det.action,
                    executed=False,
                    detail=f"below min_severity {self.min_severity.value}",
                )
                report.actions_skipped += 1
                continue

            report.detections.append(det)
            self._respond(det, report)

        return report

    def _respond(self, det: Detection, report: RunReport) -> None:
        """Gate, then execute or simulate, then record — in that order."""
        decision = self.policy.evaluate(
            det.action,
            det.rule_id,
            process=det.process,
            connection=det.connection,
        )

        if decision.decision is Decision.REFUSE:
            self.audit.record(
                kind=det.kind,
                subject=det.subject,
                rule_id=det.rule_id,
                severity=det.severity.value,
                action=det.action,
                executed=False,
                detail=decision.reason,
            )
            report.actions_refused += 1
            return

        if decision.decision is Decision.DRY_RUN:
            result = self._dispatch(RecordingActuator(), det)
            self.audit.record(
                kind=det.kind,
                subject=det.subject,
                rule_id=det.rule_id,
                severity=det.severity.value,
                action=det.action,
                executed=False,
                detail=f"{decision.reason}; {result.detail}",
            )
            report.actions_planned += 1
            return

        result = self._dispatch(self.actuator, det)
        self.audit.record(
            kind=det.kind,
            subject=det.subject,
            rule_id=det.rule_id,
            severity=det.severity.value,
            action=det.action,
            executed=result.ok,
            detail=result.detail,
        )
        if result.ok:
            report.actions_executed += 1
        elif result.detail.startswith("skipped"):
            report.actions_skipped += 1
        else:
            report.actions_refused += 1

    @staticmethod
    def _dispatch(actuator: Actuator, det: Detection) -> ActionResult:
        """Hand one action to an actuator.

        The branches below produce a "skipped" result rather than raising when
        the detection lacks the object the action needs. That is a finding
        about a mis-specified rule (a kill rule scoped to connections), and it
        should be visible in the audit trail rather than fatal.
        """
        if det.action == "alert":
            return actuator.alert(det.process, det.rule_title)

        if det.action == "kill":
            if det.process is None:
                return _skip("kill", det.subject, "no process attributed")
            return actuator.kill(det.process)

        if det.action == "quarantine":
            if det.process is None:
                return _skip("quarantine", det.subject, "no process attributed")
            return actuator.quarantine(det.process)

        if det.action == "block":
            if det.connection is None:
                return _skip("block", det.subject, "no connection on this detection")
            return actuator.block(det.connection)

        return _skip(det.action, det.subject, f"unhandled action {det.action!r}")


def _skip(action: str, subject: str, why: str) -> ActionResult:
    return ActionResult(action, subject, ok=False, detail=f"skipped: {why}")
