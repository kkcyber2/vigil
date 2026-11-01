# vigil

An autonomous host defender for Linux. It watches processes and network
connections, matches them against declarative rules, and — **only if you let it** —
kills, quarantines or blocks. Every decision it makes is written to a
hash-chained audit log, including the decisions *not* to act.

The design centres on one idea: **an autonomous responder that cannot explain
what it did is more dangerous than no responder at all.** So dry-run is the
default, the action ceiling defaults to `alert`, init is never touchable, and
every refusal carries a written reason.

```
vigil: scanned 21 processes, 13 connections

  [HIGH] Executable running from a world-writable temp directory
          pid:829  (proc-tmp-exec -> alert)
          Legitimate installers do run from /tmp, so this is a signal
          rather than a verdict.

  0 executed, 1 recorded only, 0 refused
```

*(Real output from a run against this project's own build container, with a
deliberately staged `/tmp` binary. Not a mock-up. Process and connection counts
vary by machine and moment — they are counts, not constants.)*

## Install

```bash
git clone https://github.com/kkcyber2/vigil
cd vigil
python -m pip install -e .
```

Python 3.9+. No runtime dependencies — stdlib only. Linux only (it reads `/proc`).

## Use

```bash
vigil scan                      # dry run against the built-in rule pack
vigil scan --json               # machine-readable
vigil scan --audit-out run.jsonl
vigil scan --live --max-action quarantine    # actually respond
vigil rules                     # dump the rule pack as JSON
vigil validate my-rules.json    # check a pack for authoring mistakes
```

Exit code is `1` when anything at `high` or above is found, so this composes
with cron and CI without parsing output.

### Turning on response

Three independent things must all be true before an action runs:

1. `--live` is passed (otherwise dry run)
2. the action's rank is at or below `--max-action` (default `alert`)
3. the policy permits the target

Rank order is `alert < block < quarantine < kill`.

## Writing rules

Rules are JSON, so a pack can be reviewed in a pull request without reading
Python.

```json
{
  "rules": [
    {
      "id": "staged-binary-egress",
      "title": "Staged binary holds an outbound connection",
      "severity": "high",
      "scope": "connection",
      "action": "alert",
      "conditions": [
        { "field": "process.exe", "mode": "contains_any", "value": ["/tmp/", "/dev/shm/"] },
        { "field": "state", "mode": "exact", "value": "ESTABLISHED" }
      ]
    }
  ]
}
```

Match modes: `exact`, `contains`, `contains_any`, `in`, `regex`, `exists`.
Scopes: `process`, `connection`, `any`.

`vigil validate` warns about the mistake that actually bites — a rule scoped to
`process` whose every condition reads `connection.*`, which can never fire. A
detector that silently never fires is worse than none: it produces false
confidence.

## The audit trail

Each entry chains to its predecessor by SHA-256, so an edit or a deleted middle
entry is detectable:

```python
from vigil.audit import AuditLog
log = AuditLog()
log.record('process', 'pid:1', 'demo', 'low', 'alert', False)
print(log.verify(), log.head_hash()[:16])
```

**Limitation, stated plainly:** the chain makes *silent* tampering require
deliberate effort. It is not tamper-proof — anyone with write access to the
file can rewrite the whole chain. Truncating the tail is undetectable from the
file alone (the remaining chain still verifies), which is why `--audit-out`
should be shipped somewhere append-only and `head_hash` recorded elsewhere.
