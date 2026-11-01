"""Observed host state.

Everything a rule can match against is one of these three types. Keeping them
frozen means a collector cannot mutate state after it has been evaluated, which
would make the audit trail disagree with the decision it recorded.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Process:
    """One running process, as observed at a point in time."""

    pid: int
    ppid: int = 0
    name: str = ""
    exe: str = ""
    cmdline: str = ""
    uid: int = 0
    start_time: float = 0.0

    def subject(self) -> str:
        return f"pid:{self.pid}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Connection:
    """One network connection, optionally attributed to a process."""

    pid: int
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str = "ESTABLISHED"
    protocol: str = "tcp"
    # The kernel's socket inode. It is the only reliable join key between a
    # /proc/net/tcp row and the pid that owns it, so it is carried on the model
    # rather than looked up twice.
    inode: str = ""

    def subject(self) -> str:
        return f"conn:{self.protocol}:{self.remote_addr}:{self.remote_port}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Snapshot:
    """A point-in-time view of the host."""

    processes: List[Process] = field(default_factory=list)
    connections: List[Connection] = field(default_factory=list)

    def process_index(self) -> Dict[int, Process]:
        return {p.pid: p for p in self.processes}

    def context_for_process(self, proc: Process) -> Dict[str, Any]:
        """Flatten a process into a rule-matchable context.

        The same fields appear at the top level and under ``process`` so a rule
        can be written either way without the author having to remember which
        event type it targets.
        """
        body = proc.to_dict()
        ctx: Dict[str, Any] = {"kind": "process"}
        ctx.update(body)
        ctx["process"] = body
        return ctx

    def context_for_connection(
        self, conn: Connection, proc: Optional[Process] = None
    ) -> Dict[str, Any]:
        """Flatten a connection, joining its owning process when known.

        ``process`` is present but empty when the pid is unowned or the
        process exited between the connection scan and the process scan. A
        rule that dereferences ``process.name`` must therefore be written to
        tolerate an empty dict rather than assume attribution.
        """
        body = conn.to_dict()
        ctx: Dict[str, Any] = {"kind": "connection"}
        ctx.update(body)
        ctx["connection"] = body
        ctx["process"] = proc.to_dict() if proc else {}
        return ctx

    def is_empty(self) -> bool:
        return not self.processes and not self.connections


def resolve(context: Dict[str, Any], path: str) -> Any:
    """Resolve a dotted path against a context, returning None when absent.

    Absent and present-but-None are deliberately indistinguishable here: a rule
    matching on a field the collector could not populate should not fire, and
    returning None gives the operators a single "no value" case to handle.
    """
    if not path:
        return None
    node: Any = context
    for part in path.split("."):
        if isinstance(node, dict):
            if part not in node:
                return None
            node = node[part]
        else:
            node = getattr(node, part, None)
            if node is None:
                return None
    return node
