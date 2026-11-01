"""Command line interface.

    vigil scan                  summarise the host against the default rules
    vigil scan --json           machine-readable output
    vigil scan --rules custom.json
    vigil scan --live ...       actually respond (still policy-gated)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .actuator import LocalActuator, RecordingActuator
from .audit import AuditLog
from .collector import LinuxCollector
from .engine import Engine, RunReport
from .response import ResponsePolicy
from .rules import RuleSet, Severity, default_rules


_LABEL = {
    "critical": ("CRIT", "\033[1;31m"),
    "high": ("HIGH", "\033[31m"),
    "medium": ("MED ", "\033[33m"),
    "low": ("LOW ", "\033[36m"),
    "info": ("INFO", "\033[2m"),
}


def _badge(severity: str, colour: bool) -> str:
    text, code = _LABEL[severity]
    return f"{code}{text}\033[0m" if colour else text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigil",
        description=(
            "Autonomous host defender. Detects and, if permitted, responds. "
            "Dry-run by default: nothing is killed or blocked unless --live "
            "is passed AND the policy ceiling allows the action."
        ),
    )
    parser.add_argument("--version", action="version", version=f"vigil {__version__}")

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan the host and report")
    scan.add_argument(
        "--rules",
        type=Path,
        help="path to a JSON rule pack; the built-in baseline is used if omitted",
    )
    scan.add_argument(
        "--json", action="store_true", help="emit JSON instead of a table"
    )
    scan.add_argument(
        "--min-severity",
        default="low",
        choices=[s.value for s in Severity],
        help="ignore findings below this severity (default: low)",
    )
    scan.add_argument(
        "--live",
        action="store_true",
        help=(
            "permit real response actions. Without this the run is a dry run. "
            "Use together with --max-action."
        ),
    )
    scan.add_argument(
        "--max-action",
        default="alert",
        choices=["alert", "block", "quarantine", "kill"],
        help="highest-ranked action the policy will allow (default: alert)",
    )
    scan.add_argument(
        "--allow-uid",
        type=int,
        action="append",
        default=None,
        help=(
            "permit acting on processes owned by this uid. Repeatable. By "
            "default root-owned processes are never touched."
        ),
    )
    scan.add_argument(
        "--audit-out", type=Path, help="write the hash-chained audit log as JSONL"
    )
    scan.add_argument(
        "--no-colour", action="store_true", help="disable ANSI colour"
    )

    sub.add_parser("rules", help="print the built-in rule pack as JSON")

    validate = sub.add_parser(
        "validate", help="check a rule pack for authoring mistakes"
    )
    validate.add_argument("path", type=Path)

    return parser


def load_rules(path: Optional[Path]) -> RuleSet:
    if path is None:
        return default_rules()
    raw = json.loads(path.read_text())
    return RuleSet.from_dict(raw)


def rules_to_dict(rules: RuleSet) -> dict:
    return {
        "rules": [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity.value,
                "scope": r.scope,
                "action": r.action,
                "description": r.description,
                "tags": list(r.tags),
                "conditions": [
                    {"field": c.field, "mode": c.mode.value, "value": c.value}
                    for c in r.conditions
                ],
            }
            for r in rules
        ]
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        print(json.dumps(rules_to_dict(default_rules()), indent=2))
        return 0

    if args.command == "validate":
        try:
            rules = RuleSet.from_dict(json.loads(args.path.read_text()))
        except (OSError, ValueError) as exc:
            print(f"invalid rule pack: {exc}", file=sys.stderr)
            return 2
        warnings = rules.warnings()
        print(f"loaded {len(rules)} rules from {args.path}")
        if warnings:
            print("warnings:")
            for warning in warnings:
                print(f"  - {warning}")
            return 1
        print("no authoring warnings")
        return 0

    if args.command != "scan":
        parser.print_help()
        return 2

    collector = LinuxCollector()
    if not collector.available:
        print("error: /proc is not available; vigil is Linux-only", file=sys.stderr)
        return 2

    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError) as exc:
        print(f"error loading rules: {exc}", file=sys.stderr)
        return 2

    for warning in rules.warnings():
        print(f"rule warning: {warning}", file=sys.stderr)

    protected_uids = {0}
    if args.allow_uid:
        protected_uids -= set(args.allow_uid)

    policy = ResponsePolicy(
        dry_run=not args.live,
        max_action=args.max_action,
        protected_uids=protected_uids,
    )
    actuator = (
        LocalActuator(dry_run=not args.live) if args.live else RecordingActuator()
    )
    audit = AuditLog()
    engine = Engine(
        rules=rules,
        policy=policy,
        actuator=actuator,
        audit=audit,
        min_severity=Severity(args.min_severity),
    )

    report = engine.run(collector.snapshot())

    if args.json:
        payload = report.to_dict()
        payload["audit"] = audit.summary()
        print(json.dumps(payload, indent=2))
    else:
        _print_human(report, audit, not args.no_colour and sys.stdout.isatty())

    if args.audit_out:
        args.audit_out.write_text(audit.to_jsonl())

    # Exit 1 when anything at high or above was found, so a cron job or CI step
    # can test the exit code instead of parsing output.
    highest = report.highest_severity
    if highest is not None and highest.rank >= Severity.HIGH.rank:
        return 1
    return 0


def _print_human(report: RunReport, audit: AuditLog, colour: bool) -> None:
    print(
        f"vigil: scanned {report.scanned_processes} processes, "
        f"{report.scanned_connections} connections"
    )
    if not report.detections:
        print("no findings")
        return

    print()
    for det in sorted(report.detections, key=lambda d: -d.severity.rank):
        print(f"  [{_badge(det.severity.value, colour)}] {det.rule_title}")
        print(f"          {det.subject}  ({det.rule_id} -> {det.action})")
        if det.description:
            print(f"          {det.description}")

    summary = audit.summary()
    print()
    print(
        f"  {summary['executed']} executed, {summary['planned_only']} recorded only, "
        f"{summary['refused']} refused"
    )
    if not audit.verify():
        print("  WARNING: audit chain does not verify", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
