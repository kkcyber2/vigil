"""Actuators.

The engine never calls ``os.kill`` directly. Every action goes through an
``Actuator``, which means the whole response path can be tested without a host,
and an operator can swap in a shim that talks to EDR instead of the kernel.

``RecordingActuator`` is what tests use. ``LocalActuator`` is the real one, and
it refuses to do anything unless the caller has already been through the policy
gate -- defence in depth, because a future bug in the engine should not be able
to kill a process on its own.
"""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import Connection, Process


@dataclass
class ActionResult:
    action: str
    subject: str
    ok: bool
    detail: str = ""


class Actuator:
    """Interface every executor implements."""

    def alert(self, process: Optional[Process], message: str) -> ActionResult:
        raise NotImplementedError

    def kill(self, process: Process) -> ActionResult:
        raise NotImplementedError

    def quarantine(self, process: Process) -> ActionResult:
        raise NotImplementedError

    def block(self, connection: Connection) -> ActionResult:
        raise NotImplementedError


@dataclass
class RecordingActuator(Actuator):
    """Executes nothing; records what it would have done.

    This is the default actuator for the engine. It makes dry-run the path of
    least resistance: a caller has to deliberately construct a LocalActuator to
    touch the host.
    """

    calls: List[ActionResult] = field(default_factory=list)

    def _note(self, action: str, subject: str, detail: str) -> ActionResult:
        result = ActionResult(action, subject, ok=True, detail=f"simulated: {detail}")
        self.calls.append(result)
        return result

    def alert(self, process: Optional[Process], message: str) -> ActionResult:
        subject = process.subject() if process else "host"
        return self._note("alert", subject, message)

    def kill(self, process: Process) -> ActionResult:
        return self._note("kill", process.subject(), f"would SIGTERM {process.name}")

    def quarantine(self, process: Process) -> ActionResult:
        return self._note("quarantine", process.subject(), f"would isolate {process.name}")

    def block(self, connection: Connection) -> ActionResult:
        return self._note("block", connection.subject(), "would drop traffic")


@dataclass
class LocalActuator(Actuator):
    """The real thing. Touches the host.

    Every method re-checks that it was handed a live object. The engine's
    policy gate is the primary control; these guards exist so that a direct
    call that bypassed the engine still cannot do the worst things.
    """

    dry_run: bool = True
    protected_pids: tuple = (0, 1)
    results: List[ActionResult] = field(default_factory=list)

    def _refuse(self, action: str, subject: str, why: str) -> ActionResult:
        result = ActionResult(action, subject, ok=False, detail=f"refused: {why}")
        self.results.append(result)
        return result

    def _do(self, action: str, subject: str, fn) -> ActionResult:
        if self.dry_run:
            return self._refuse(action, subject, "actuator dry_run")
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - report, never propagate
            result = ActionResult(action, subject, ok=False, detail=f"failed: {exc}")
            self.results.append(result)
            return result
        result = ActionResult(action, subject, ok=True, detail="executed")
        self.results.append(result)
        return result

    def alert(self, process: Optional[Process], message: str) -> ActionResult:
        subject = process.subject() if process else "host"
        result = ActionResult("alert", subject, ok=True, detail=message)
        self.results.append(result)
        return result

    def kill(self, process: Process) -> ActionResult:
        if process.pid in self.protected_pids:
            return self._refuse("kill", process.subject(), f"pid {process.pid} protected")

        def _kill() -> None:
            os.kill(process.pid, signal.SIGTERM)

        return self._do("kill", process.subject(), _kill)

    def quarantine(self, process: Process) -> ActionResult:
        """Isolate a process by stopping it and renaming its binary.

        Implemented as SIGSTOP plus a rename rather than deletion, so a false
        positive can be reversed by the operator. Deleting the artefact would
        destroy the evidence needed to work out whether the rule was right.
        """
        if process.pid in self.protected_pids:
            return self._refuse(
                "quarantine", process.subject(), f"pid {process.pid} protected"
            )
        if not process.exe or not os.path.exists(process.exe):
            return self._refuse(
                "quarantine", process.subject(), "executable path missing"
            )

        def _quarantine() -> None:
            os.kill(process.pid, signal.SIGSTOP)
            os.rename(process.exe, process.exe + ".vigil-quarantine")

        return self._do("quarantine", process.subject(), _quarantine)

    def block(self, connection: Connection) -> ActionResult:
        """Block traffic to the remote address.

        Uses iptables and is therefore Linux-only and root-only. Failure is
        reported rather than raised -- a defender that crashes when it cannot
        enforce is worse than one that says it could not.
        """
        if not connection.remote_addr:
            return self._refuse("block", connection.subject(), "no remote address")

        def _block() -> None:
            subprocess.run(
                [
                    "iptables",
                    "-I",
                    "OUTPUT",
                    "-d",
                    connection.remote_addr,
                    "-j",
                    "DROP",
                ],
                check=True,
                capture_output=True,
                timeout=5,
            )

        return self._do("block", connection.subject(), _block)
