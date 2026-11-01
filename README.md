# vigil

An autonomous host defender for Linux. It watches processes and network
connections, matches them against declarative rules, and — **only if you let
it** — kills, quarantines or blocks. Every decision is written to a
hash-chained audit log, including the decisions *not* to act.

The design centres on one idea: **an autonomous responder that cannot explain
what it did is more dangerous than no responder at all.** So dry-run is the
default, the action ceiling defaults to `alert`, init is never touchable, and
every refusal carries a written reason.

```
vigil: scanned 21 processes, 12 connections

  [HIGH] Executable running from a world-writable temp directory
          pid:3289  (proc-tmp-exec -> alert)

  0 executed, 0 recorded only, 1 refused
```

## Install

```bash
git clone https://github.com/kkcyber2/vigil
cd vigil && python -m pip install -e .
```

Python 3.9+. No runtime dependencies. Linux only (it reads `/proc`).

## Use

```bash
vigil scan                          # dry run, built-in rule pack
vigil scan --json                   # machine-readable
vigil scan --audit-out run.jsonl    # hash-chained decision log
vigil scan --live --max-action quarantine
vigil rules                         # dump the pack as JSON
vigil validate my-rules.json        # authoring checks
```

Exit code is `1` when anything at `high` or above is found, so it composes with
cron and CI without parsing output.

Three independent conditions must hold before an action runs: `--live` is
passed, the action is within `--max-action` (default `alert`), and the policy
permits the target. Rank order is `alert < block < quarantine < kill`.

One easy mistake: the default policy protects processes owned by the superuser,
so an elevated run without `--allow-uid` reports every finding as refused. That
is correct behaviour that reads like a fault. `--allow-uid 0` overrides it.

## What it detects

Seven rules ship by default — deleted-but-running binaries (critical), temp-dir
executables, temp-dir interpreters, temp-dir processes with egress, known miner
names, netcat in listen mode, and bare-IP traffic on ephemeral ports.

A finding is a lead, not a verdict. See
**[docs/limitations.md](docs/limitations.md)** for what it fundamentally cannot
see — no eBPF, no auditd, no persistence inspection, no state between runs.

## Rules are data

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
        { "field": "process.exe", "mode": "contains_any", "value": ["/tmp/"] },
        { "field": "state", "mode": "exact", "value": "ESTABLISHED" }
      ]
    }
  ]
}
```

Modes: `exact`, `contains`, `contains_any`, `in`, `regex`, `exists`.
Scopes: `process`, `connection`, `any`.

`vigil validate` warns about the mistake that actually bites — a rule scoped to
`process` whose every condition reads `connection.*`, which can never fire. A
detector that silently never fires is worse than none.

## Verification

**109 tests pass.** CI covers Python 3.9, 3.11 and 3.12, runs the CLI against
the runner's own `/proc`, and asserts no dry-run entry is ever marked executed.
The response path was verified end to end against a real staged binary. Three
bugs that produced a healthy-looking audit trail while doing nothing were found
this way and are pinned by regression tests.

Full record, including what was **not** verified:
**[docs/verification.md](docs/verification.md)**.

## Authorised use

Run this on hosts you own or are explicitly authorised to administer. It reads
process and connection state, which on many systems is itself sensitive, and it
can terminate processes. Unauthorised use may be unlawful.

## License

MIT. See [LICENSE](LICENSE).
