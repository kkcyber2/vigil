"""Response authorisation.

An autonomous defender holds the power to kill processes and drop traffic. That
power has to be bounded by something other than the detector's own judgement,
because detectors are wrong regularly.

The rules here are deliberately restrictive and are evaluated in order, each
one able to refuse. Refusal is the default: an action runs only when the policy
affirmatively allows it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from .models import Connection, Process


class Decision(str, Enum):
    ALLOW = "allow"
    DRY_RUN = "dry_run"
    REFUSE = "refuse"


@dataclass
class PolicyResult:
    decision: Decision
    reason: str

    @property
    def may_execute(self) -> bool:
        return self.decision is Decision.ALLOW


# Actions ranked by how hard they are to undo. The threshold gate compares an
# action's rank against the configured maximum, so raising the ceiling is a
# deliberate, visible act rather than a side effect of adding a rule.
ACTION_RANK: Dict[str, int] = {
    "alert": 0,
    "block": 1,
    "quarantine": 2,
    "kill": 3,
}

IRREVERSIBLE = {"kill", "quarantine"}


@dataclass
class ResponsePolicy:
    """Bounds what the engine is permitted to do.

    Defaults are chosen so that importing this module and running the engine
    cannot damage the host: dry_run is on, the ceiling is "alert", and the two
    PIDs that matter most on a Unix system are protected.
    """

    # Dry-run is the default. Turning it off must be an explicit, reviewable act.
    dry_run: bool = True

    # Highest-ranked action this policy will permit.
    max_action: str = "alert"

    # Never act on these processes. pid 1 is init: killing it takes the machine
    # down. pid 0 does not exist and signals a collector bug.
    protected_pids: Set[int] = field(default_factory=lambda: {0, 1})

    # Never act on processes owned by these users. Acting on root-owned
    # processes from a non-root agent invites partial failures and lockouts.
    protected_uids: Set[int] = field(default_factory=lambda: {0})

    # Never kill anything whose executable matches these prefixes.
    protected_paths: List[str] = field(
        default_factory=lambda: ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/lib/"]
    )

    # Only act on addresses in these networks, if set. Off by default: an
    # operator enabling response should say which ranges they own.
    allowed_networks: Optional[List[str]] = None

    # Rules whose id appears here only ever alert, whatever action they declare.
    never_act_rules: Set[str] = field(default_factory=set)

    def evaluate(
        self,
        action: str,
        rule_id: str,
        process: Optional[Process] = None,
        connection: Optional[Connection] = None,
    ) -> PolicyResult:
        """Decide whether this action may run. Every branch gives a reason."""

        if action not in ACTION_RANK:
            return PolicyResult(
                Decision.REFUSE, f"refused: unknown action {action!r}"
            )

        if action in self.never_act_rules or rule_id in self.never_act_rules:
            return PolicyResult(
                Decision.DRY_RUN,
                f"refused: {action} suppressed by never_act_rules for {rule_id}",
            )

        if ACTION_RANK[action] > ACTION_RANK.get(self.max_action, 0):
            return PolicyResult(
                Decision.DRY_RUN,
                f"refused: {action} exceeds max_action={self.max_action!r}",
            )

        if process is not None:
            if process.pid in self.protected_pids:
                return PolicyResult(
                    Decision.REFUSE,
                    f"refused: pid {process.pid} is protected (init or invalid)",
                )
            if process.uid in self.protected_uids:
                return PolicyResult(
                    Decision.REFUSE,
                    f"refused: pid {process.pid} runs as uid {process.uid}, which is protected",
                )
            for prefix in self.protected_paths:
                if process.exe.startswith(prefix):
                    return PolicyResult(
                        Decision.DRY_RUN,
                        f"refused: {process.exe} is a system path ({prefix})",
                    )

        if connection is not None and self.allowed_networks is not None:
            if not any(
                _in_network(connection.remote_addr, net)
                for net in self.allowed_networks
            ):
                return PolicyResult(
                    Decision.DRY_RUN,
                    f"refused: {connection.remote_addr} is outside allowed_networks",
                )

        if self.dry_run:
            return PolicyResult(
                Decision.DRY_RUN, "refused: dry_run enabled: recorded but not executed"
            )

        return PolicyResult(Decision.ALLOW, "allowed")


def _in_network(address: str, network: str) -> bool:
    """Prefix check for IPv4 CIDR, tolerant of malformed input.

    Deliberately not using ipaddress for the hot path here because the caller
    may pass a hostname or an empty string from an unattributed socket, and a
    raised exception inside a policy check would fail open.
    """
    try:
        import ipaddress

        return ipaddress.ip_address(address) in ipaddress.ip_network(
            network, strict=False
        )
    except (ValueError, TypeError):
        return False
