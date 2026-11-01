# The response path, verified end to end

Creating a `LocalActuator` is not the same as proving it kills the right thing and
nothing else. This page records what was actually executed against a real host,
including the run where the tool had permission and was still stopped.

## Setup

A copy of `/bin/sleep` was staged into a world-writable temp directory and left
running. That is the shape of a dropper: a binary outside the package manager's
paths, executing from a directory anything can write to. `proc-tmp-exec` should
catch it.

## Four runs

| Configuration | Result |
|---|---|
| plain scan, before staging | clean, no findings |
| after staging: dry run with a permissive ceiling | detected; process **still alive** |
| live run, ceiling left at `alert` | kill refused by policy; process **still alive** |
| live run, ceiling raised and the uid explicitly permitted | `executed=True`; process **dead** |

**The third row is the one worth keeping.** The tool had a matching rule, a
`kill` action on that rule, and `--live` on the command line. The ceiling still
stopped it, and the audit entry said so in words rather than in a status code.

## Two bugs this found

Both passed an initial read of the code. Both are the kind that produce a
healthy-looking audit trail while nothing happens — which is worse than an
obvious crash.

### 1. Every response was a silent no-op

`Detection` rebuilt its `Process` from `context["process"]`, but the
process-scoped path never populated that key. So `_respond` saw no process and
every kill was logged as `skipped: no process to kill`, on every run, forever.
The audit trail showed a well-formed entry each time.

Fix: `Detection` carries the live object. `tests/test_regressions.py` asserts
that a kill reaches the actuator and that `actions_skipped == 0`.

### 2. The caller's audit log was discarded

`AuditLog` defined `__len__`, so an empty log was falsy. `self.audit = audit or
AuditLog()` therefore replaced the caller's instance with a fresh one on
construction. Every entry went to an object the caller never looked at.

Fix: explicit `is None` checks. The regression test asserts
`engine.audit is mine`, and a second test asserts `bool(AuditLog()) is True` so
the root cause cannot come back quietly.

## The suite

```
107 passed
```

CI runs it on Python 3.9, 3.11 and 3.12, then runs the CLI against the runner's
own `/proc` so the collector is exercised against a real kernel rather than only
against fixtures. A further CI step parses the audit output and asserts that no
dry-run entry was ever marked `executed`.

## What was not verified

- `block` was never exercised against a real `iptables`. The code path is
  covered by tests with an injected actuator; it was not run with root.
- `quarantine` was not run against a live process. The rename and `SIGSTOP`
  logic is tested, but never executed on an actual binary.
- No run on a host with `/proc` mounted `hidepid`, where other users' processes
  are invisible and the socket-inode join will silently under-report.
- Only one Linux distribution and kernel, in a container.

Stating this is the point. "It has a kill action" and "I watched it kill a
process and confirmed the process died" are different claims, and only the second
is worth anything in a tool that terminates things.
