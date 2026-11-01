# Limitations

## What vigil does not see

- **Anything needing kernel telemetry.** No eBPF, no auditd integration, no
  fanotify. A rootkit that hides from `/proc` hides from vigil completely.
- **Fileless execution** beyond the deleted-binary case. In-memory payloads that
  never touch disk leave no `exe` link to inspect.
- **Lateral movement.** It sees this host, one moment at a time, and keeps no
  state between runs. A beacon firing once every ten minutes will not be caught
  by a scan that runs every minute.
- **Credential access.** Nothing here reads `/etc/shadow` or keyrings.
- **Persistence mechanisms** — cron, systemd units, shell profiles, LD_PRELOAD.
  These are not inspected at all.
- **Windows and macOS.** `/proc` only.
- **Container escapes**, though it will report on processes inside a container
  as though they were on the host.

## The rules are heuristics

`proc-tmp-exec` fires on legitimate installers. `conn-bare-ip-high-port` fires
on plenty of ordinary traffic. The shipped pack is tuned to stay quiet on a
healthy machine — seven rules is a deliberate trade of recall for precision,
because a detector that cries wolf on day one gets uninstalled on day two.

Nowhere in this tool does a finding mean "compromise". Treat every one as a lead.

## The response path

- `block` shells out to `iptables` and needs root. A non-root run reports the
  failure rather than raising, but it will not block.
- `quarantine` sends `SIGSTOP` and renames the binary to `*.vigil-quarantine`
  rather than deleting it. Destroying the artefact would destroy the evidence
  needed to work out whether the rule was right. A stopped process still holds
  its memory, so it is recoverable by hand.
- Killing a process loses its memory. If the host may be compromised, capture a
  memory image before responding.
- **No rollback.** A wrong kill is not undoable.
- **No global brake.** Policy is checked per action. On a noisy host there is no
  "stop responding after N actions" circuit breaker, which is a real gap.
- **Rules run per scan, not per event.** Between two scans is a blind spot whose
  size is whatever your cron interval says.
- **No state.** The engine does not remember what it saw last time, so it cannot
  suppress an alert it already raised and will re-report the same finding on
  every run.

## The audit log

The SHA-256 chain makes *silent* tampering require deliberate effort. It is not
tamper-proof: anyone with write access to the file can rewrite the whole chain.
Truncating the tail is undetectable from the file alone, because the remaining
chain still verifies. Ship `--audit-out` somewhere append-only and record
`head_hash` elsewhere.

## Tested on

Developed and verified on Linux with `/proc`. The parsers are tested against
real kernel output on every platform, but `LinuxCollector` itself has not been
run against a distribution other than the build container. It has not been run
on a hardened host where `/proc` is mounted with `hidepid`, where other users'
processes will be invisible to it.
