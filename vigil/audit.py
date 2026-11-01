"""Append-only audit log.

The point of this module is that a responder which cannot say *what it did and
why* is worse than no responder: an autonomous agent that kills processes
without a record is an outage waiting for a cause nobody can find.

Every entry carries a hash chain so a log that has been edited or truncated is
detectable. It is not tamper-proof against someone with write access to the
file, but it makes silent alteration require deliberate effort.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List

GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: float
    kind: str
    subject: str
    rule_id: str
    severity: str
    action: str
    executed: bool
    detail: str
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "kind": self.kind,
            "subject": self.subject,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "action": self.action,
            "executed": self.executed,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


def _digest(payload: Dict[str, Any]) -> str:
    """Hash the canonical JSON of an entry body.

    sort_keys and a fixed separator make the digest independent of dict
    ordering, so the same entry always produces the same hash.
    """
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class AuditLog:
    """Thread-safe append-only log with hash chaining."""

    def __init__(self, clock=None) -> None:
        # Injectable so tests assert on exact timestamps rather than sleeping.
        self._clock = clock or time.time
        self._entries: List[AuditEntry] = []
        self._lock = threading.Lock()

    def __iter__(self):
        return iter(list(self._entries))

    # Deliberately NOT defining __len__. A log with no entries is falsy under
    # bool(), and `audit or AuditLog()` in the engine then silently substituted
    # a fresh log for the caller's -- every entry went somewhere else. Use
    # .count instead so emptiness is never mistaken for absence.
    @property
    def count(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> List[AuditEntry]:
        with self._lock:
            return list(self._entries)

    def record(
        self,
        kind: str,
        subject: str,
        rule_id: str,
        severity: str,
        action: str,
        executed: bool,
        detail: str = "",
    ) -> AuditEntry:
        """Append one entry, chaining it to its predecessor."""
        with self._lock:
            prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS
            body = {
                "seq": len(self._entries),
                "ts": self._clock(),
                "kind": kind,
                "subject": subject,
                "rule_id": rule_id,
                "severity": severity,
                "action": action,
                "executed": executed,
                "detail": detail,
                "prev_hash": prev_hash,
            }
            entry = AuditEntry(entry_hash=_digest(body), **body)
            self._entries.append(entry)
            return entry

    def verify(self) -> bool:
        """Recompute the chain and report whether it is intact.

        Catches three distinct failures: a mutated field (its hash no longer
        matches), a deleted entry (the seq numbers skip or a prev_hash does not
        line up), and a resequenced entry.
        """
        with self._lock:
            prev = GENESIS
            for index, entry in enumerate(self._entries):
                if entry.seq != index:
                    return False
                if entry.prev_hash != prev:
                    return False
                body = {
                    "seq": entry.seq,
                    "ts": entry.ts,
                    "kind": entry.kind,
                    "subject": entry.subject,
                    "rule_id": entry.rule_id,
                    "severity": entry.severity,
                    "action": entry.action,
                    "executed": entry.executed,
                    "detail": entry.detail,
                    "prev_hash": entry.prev_hash,
                }
                if _digest(body) != entry.entry_hash:
                    return False
                prev = entry.entry_hash
            return True

    def head_hash(self) -> str:
        """Current chain head - publish this or compare it across runs."""
        with self._lock:
            return self._entries[-1].entry_hash if self._entries else GENESIS

    def to_jsonl(self) -> str:
        return "\n".join(
            json.dumps(e.to_dict(), sort_keys=True) for e in self.entries
        )

    def summary(self) -> Dict[str, Any]:
        """Counts by action and whether each was actually executed."""
        planned = 0
        executed = 0
        blocked = 0
        by_action: Dict[str, int] = {}
        for entry in self.entries:
            by_action[entry.action] = by_action.get(entry.action, 0) + 1
            if entry.executed:
                executed += 1
                continue
            # Every entry below this line was not executed, and the reasons
            # are mutually exclusive. An earlier version tested the detail
            # prefix alone, so a dry-run entry ("refused: dry_run enabled")
            # was counted as BOTH "recorded only" and "refused" -- one
            # finding reported as two different outcomes.
            if _is_policy_refusal(entry.detail):
                blocked += 1
            else:
                planned += 1
        return {
            "entries": len(self._entries),
            "executed": executed,
            "planned_only": planned,
            "refused": blocked,
            "by_action": by_action,
            "chain_valid": self.verify(),
            "head_hash": self.head_hash(),
        }


def _is_policy_refusal(detail: str) -> bool:
    """Distinguish a policy refusal from a dry run.

    Both are logged with a "refused:" prefix, because in both cases the action
    did not run. But they mean different things operationally: a refusal is the
    policy saying no to a permitted action, while a dry run is the whole mode of
    the tool. Only the former belongs in the `refused` tally.
    """
    if not detail.startswith("refused"):
        return False
    return "dry_run" not in detail
