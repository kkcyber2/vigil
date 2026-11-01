"""Declarative detection rules.

A rule is data, not code, so a rule pack can be reviewed and version-controlled
without anyone reading Python. The matcher is deliberately small: exact, list
membership, and regex — anything more expressive becomes a programming language
with worse tooling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import Snapshot, resolve


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank


class MatchMode(str, Enum):
    EXACT = "exact"
    CONTAINS = "contains"
    REGEX = "regex"
    IN = "in"
    CONTAINS_ANY = "contains_any"
    EXISTS = "exists"


@dataclass(frozen=True)
class Condition:
    """One field/operator/value triple."""

    field: str
    mode: MatchMode
    value: Any = None

    def __post_init__(self) -> None:
        # Compile eagerly so a bad pattern fails at load, not mid-incident.
        if self.mode is MatchMode.REGEX and isinstance(self.value, str):
            try:
                re.compile(self.value)
            except re.error as exc:
                raise ValueError(
                    f"rule condition on {self.field!r} has an invalid regex "
                    f"{self.value!r}: {exc}"
                ) from exc

    def evaluate(self, context: Dict[str, Any]) -> bool:
        actual = resolve(context, self.field)

        if self.mode is MatchMode.EXISTS:
            # value is the expected presence, defaulting to True.
            want = True if self.value is None else bool(self.value)
            return (actual is not None) is want

        if actual is None:
            # A missing field never satisfies a value comparison. This is what
            # stops an unattributed connection from matching a rule that names
            # a process, which would otherwise fire on every orphan socket.
            return False

        if self.mode is MatchMode.EXACT:
            return actual == self.value

        if self.mode is MatchMode.IN:
            try:
                return actual in (self.value or ())
            except TypeError:
                return False

        if self.mode is MatchMode.CONTAINS:
            return str(self.value).lower() in str(actual).lower()

        if self.mode is MatchMode.CONTAINS_ANY:
            haystack = str(actual).lower()
            return any(str(v).lower() in haystack for v in (self.value or ()))

        if self.mode is MatchMode.REGEX:
            return re.search(str(self.value), str(actual)) is not None

        raise ValueError(f"unhandled match mode {self.mode}")

    def describe(self) -> str:
        if self.mode is MatchMode.EXISTS:
            want = True if self.value is None else bool(self.value)
            return f"{self.field} {'is' if want else 'is not'} present"
        if self.mode is MatchMode.IN:
            return f"{self.field} in {list(self.value or ())}"
        if self.mode is MatchMode.CONTAINS_ANY:
            return f"{self.field} contains any of {list(self.value or ())}"
        return f"{self.field} {self.mode.value} {self.value!r}"


@dataclass(frozen=True)
class Rule:
    """A detection rule.

    ``scope`` decides which event stream the rule is evaluated against:
    "process", "connection", or "any". A rule whose conditions only reference
    connection fields but which is scoped to "process" silently never fires —
    that is a real authoring mistake, so ``RuleSet`` warns about it.
    """

    id: str
    title: str
    severity: Severity
    scope: str = "any"
    conditions: Tuple[Condition, ...] = ()
    action: str = "alert"
    description: str = ""
    tags: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.scope not in ("process", "connection", "any"):
            raise ValueError(
                f"rule {self.id!r} has invalid scope {self.scope!r}; "
                "expected 'process', 'connection' or 'any'"
            )
        if not self.conditions:
            raise ValueError(
                f"rule {self.id!r} has no conditions; a rule with no "
                "conditions would match every event"
            )

    def matches(self, context: Dict[str, Any]) -> bool:
        kind = context.get("kind", "any")
        if self.scope != "any" and self.scope != kind:
            return False
        return all(c.evaluate(context) for c in self.conditions)

    def explain(self) -> str:
        joined = " AND ".join(c.describe() for c in self.conditions)
        return f"[{self.severity.value}] {self.title} — {joined}"

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Rule":
        if not isinstance(data, dict):
            raise ValueError(f"rule must be an object, got {type(data).__name__}")
        try:
            rid = data["id"]
            title = data["title"]
            sev = data["severity"]
        except KeyError as exc:
            raise ValueError(f"rule is missing required key {exc}") from exc

        try:
            severity = Severity(str(sev).lower())
        except ValueError as exc:
            raise ValueError(
                f"rule {rid!r} has unknown severity {sev!r}; expected one of "
                f"{[s.value for s in Severity]}"
            ) from exc

        conditions: List[Condition] = []
        for raw in data.get("conditions", []):
            try:
                field_name = raw["field"]
                mode = raw.get("mode", "exact")
            except KeyError as exc:
                raise ValueError(f"rule {rid!r} has a condition missing {exc}") from exc
            try:
                cond_mode = MatchMode(mode)
            except ValueError as exc:
                raise ValueError(
                    f"rule {rid!r} has unknown match mode {mode!r}; expected "
                    f"one of {[m.value for m in MatchMode]}"
                ) from exc
            conditions.append(Condition(field_name, cond_mode, raw.get("value")))

        return Rule(
            id=rid,
            title=title,
            severity=severity,
            scope=data.get("scope", "any"),
            conditions=tuple(conditions),
            action=data.get("action", "alert"),
            description=data.get("description", ""),
            tags=tuple(data.get("tags", ())),
        )


@dataclass
class RuleSet:
    """A collection of rules, indexed by the scope they apply to."""

    rules: List[Rule] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterable[Rule]:
        return iter(self.rules)

    def add(self, rule: Rule) -> None:
        if any(r.id == rule.id for r in self.rules):
            raise ValueError(f"duplicate rule id {rule.id!r}")
        self.rules.append(rule)

    def extend(self, rules: Iterable[Rule]) -> None:
        for rule in rules:
            self.add(rule)

    def get(self, rule_id: str) -> Optional[Rule]:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def warnings(self) -> List[str]:
        """Authoring mistakes that would make a rule silently inert.

        These are not errors — a rule may legitimately be written broadly — but
        a rule scoped to "process" whose every condition targets connection
        fields can never fire, and that is worth saying out loud.
        """
        out: List[str] = []
        for rule in self.rules:
            if rule.scope == "process":
                conn_only = all(
                    c.field.startswith("connection.") for c in rule.conditions
                )
                if conn_only:
                    out.append(
                        f"rule {rule.id!r} is scoped to processes but every "
                        "condition reads connection.* — it can never fire"
                    )
            elif rule.scope == "connection":
                proc_only = all(
                    c.field.startswith("process.") for c in rule.conditions
                )
                if proc_only:
                    out.append(
                        f"rule {rule.id!r} is scoped to connections but every "
                        "condition reads process.* — connections without an "
                        "attributed process will never match"
                    )
        return out

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "RuleSet":
        if not isinstance(data, dict) or "rules" not in data:
            raise ValueError("rule pack must be an object with a 'rules' list")
        raw_rules = data["rules"]
        if not isinstance(raw_rules, list):
            raise ValueError("'rules' must be a list")
        rs = RuleSet()
        for raw in raw_rules:
            rs.add(Rule.from_dict(raw))
        return rs


def default_rules() -> RuleSet:
    """A conservative baseline pack.

    Every rule here is written to be quiet on a healthy developer laptop. A
    detector that cries wolf on day one gets uninstalled on day two, so the
    thresholds favour precision over recall.
    """
    rs = RuleSet()
    rs.extend(
        [
            Rule(
                id="proc-tmp-exec",
                title="Executable running from a world-writable temp directory",
                severity=Severity.HIGH,
                scope="process",
                conditions=(
                    Condition("exe", MatchMode.REGEX, r"^/tmp/|^/var/tmp/|^/dev/shm/"),
                ),
                action="alert",
                description=(
                    "Legitimate installers do run from /tmp, so this is a "
                    "signal rather than a verdict. It matters most when the "
                    "binary is also unsigned or unusually named."
                ),
                tags=("execution", "persistence"),
            ),
            Rule(
                id="proc-deleted-binary",
                title="Running process whose binary has been deleted from disk",
                severity=Severity.CRITICAL,
                scope="process",
                conditions=(
                    Condition("exe", MatchMode.CONTAINS, "(deleted)"),
                ),
                action="alert",
                description=(
                    "A process holding a deleted executable is how a dropper "
                    "hides from casual inspection: the file is gone, the "
                    "process is not."
                ),
                tags=("defense-evasion",),
            ),
            Rule(
                id="proc-shell-from-tmp",
                title="Interpreter spawned with a temp-directory working binary",
                severity=Severity.HIGH,
                scope="process",
                conditions=(
                    Condition("name", MatchMode.IN, ["sh", "bash", "dash", "zsh"]),
                    Condition("exe", MatchMode.CONTAINS_ANY, ["/tmp/", "/dev/shm/"]),
                ),
                action="alert",
                description="Typical of a reverse shell staged through a dropper.",
                tags=("execution",),
            ),
            Rule(
                id="proc-netcat-listen",
                title="Netcat-family tool invoked in listen mode",
                severity=Severity.MEDIUM,
                scope="process",
                conditions=(
                    Condition(
                        "name", MatchMode.IN, ["nc", "ncat", "netcat", "socat"]
                    ),
                    Condition("cmdline", MatchMode.REGEX, r"\s-l|--listen"),
                ),
                action="alert",
                description=(
                    "Also fires for legitimate debugging. Pair with an "
                    "unexpected inbound connection before treating it as C2."
                ),
                tags=("c2", "execution"),
            ),
            Rule(
                id="conn-bare-ip-high-port",
                title="Outbound connection to a bare IP on an ephemeral port",
                severity=Severity.MEDIUM,
                scope="connection",
                conditions=(
                    Condition("remote_addr", MatchMode.REGEX, r"^\d{1,3}(\.\d{1,3}){3}$"),
                    Condition("remote_port", MatchMode.REGEX, r"^(4[0-9]{4}|[5-9][0-9]{4})$"),
                ),
                action="alert",
                description=(
                    "Direct-to-IP traffic on a high port skips DNS and is "
                    "common for C2. Many legitimate services do this too, so "
                    "treat it as a lead, not a finding."
                ),
                tags=("c2", "network"),
            ),
            Rule(
                id="conn-tmp-process-egress",
                title="Process running from temp directory holds an outbound connection",
                severity=Severity.HIGH,
                scope="connection",
                conditions=(
                    Condition("process.exe", MatchMode.CONTAINS_ANY, ["/tmp/", "/dev/shm/"]),
                    Condition("state", MatchMode.EXACT, "ESTABLISHED"),
                ),
                action="alert",
                description=(
                    "The combination is far more suspicious than either half: "
                    "a binary in a world-writable directory talking to the "
                    "network."
                ),
                tags=("c2", "execution"),
            ),
            Rule(
                id="proc-crypto-miner-name",
                title="Process name matches a known cryptominer",
                severity=Severity.HIGH,
                scope="process",
                conditions=(
                    Condition(
                        "name",
                        MatchMode.IN,
                        ["xmrig", "minerd", "cpuminer", "kdevtmpfsi", "kinsing"],
                    ),
                ),
                action="quarantine",
                description="Known miner families; there is no legitimate reason for these to run.",
                tags=("impact", "resource-hijacking"),
            ),
        ]
    )
    return rs
