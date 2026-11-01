# vigil

An autonomous host defender for Linux. It watches processes and network
connections, matches them against declarative rules, and — **only if you let it** —
kills, quarantines or blocks. Every decision is written to a hash-chained audit
log, including the decisions *not* to act.

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

*(Real output, against this project's own build container with a deliberately
staged `/tmp` binary. Counts vary by machine — they are measurements, not
constants.)*

## Install

```bash
git clone https://github.com/kkcyber2/vigil
cd vigil
python -m pip install -e .
```

Python 3.9+. No runtime dependencies — stdlib only. Linux only (it reads `/proc`).

## Use

```bash
vigil scan                       # dry run against the built-in rule pack
vigil scan --json                # machine-readable
vigil scan --audit-out run.jsonl
vigil scan --live --max-action quarantine     # actually respond
vigil rules                      # dump the rule pack as JSON
vigil validate my-rules.json     # check a pack for authoring mistakes
```

Exit code is `1` when anything at `high` or above is found, so this composes with
cron and CI without parsing output.

### Turning on response

Three independent things must all be true before an action runs:

1. `--live` is passed (otherwise dry run)
2. the action's rank is at or below `--max-action` (default `alert`)
3. the policy permits the target

Rank order is `alert < block < quarantine < kill`. `--allow-uid` lets you permit
action against a uid you own; root-owned processes are protected by default and
`pid 1` is refused outright, at both the policy and the actuator layer.

## What it detects

Seven rules ship in the default pack:

| Rule | Severity | Action |
|---|---|---|
| `proc-deleted-binary` — binary deleted from disk, process still running | critical | alert |
| `proc-tmp-exec` — executable in a world-writable directory | high | alert |
| `proc-shell-from-tmp` — interpreter with a temp-dir binary | high | alert |
| `conn-tmp-process-egress` — temp-dir process with established egress | high | alert |
| `proc-crypto-miner-name` — known miner family names | high | quarantine |
| `proc-netcat-listen` — netcat/socat in listen mode | medium | alert |
| `conn-bare-ip-high-port` — bare-IP traffic on an ephemeral port | medium | alert |

A finding is a lead, not a verdict. See **[docs/limitations.md](docs/limitations.md)**
for what it fundamentally cannot see — no eBPF, no auditd, no persistence
inspection, no state between runs — and why the pack is tuned for precision over
recall.

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
        { "field": "process.exe", "mode": "contains_any", "value": ["/tmp/", "/dev/shm/"] },
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
detector that silently never fires is worse than none: it produces false
confidence.

## Verification

**107 tests pass.** CI covers Python 3.9, 3.11 and 3.12, runs the CLI against the
runner's own `/proc`, and asserts that no dry-run entry is ever marked `executed`.

The response path was verified end to end against a real staged binary — including
a run where the tool had both a matching rule and permission, and the action
ceiling still stopped it. Two bugs that produced a *healthy-looking* audit trail
while doing nothing were found this way and are pinned by regression tests. Full
record, plus an explicit list of what was **not** verified:
**[docs/verification.md](docs/verification.md)**.

## Legal and authorised use

Run this on hosts you own or are explicitly authorised to administer. It reads
process and connection state, which on many systems is itself sensitive, and it
can terminate processes. Unauthorised use against systems you do not control may
be unlawful.

## License

MIT. See [LICENSE](LICENSE).
