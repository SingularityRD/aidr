# Incident Response Runbook

**Operating draft:** The times below are internal triage targets, not staffed coverage or customer response commitments. The approved customer support schedule, named responders, paging route, and incident-notice process are still required before supported sale; see [support operations](support-v7.md).

## Security Incident Severity Levels

### SEV 1 - Critical
- Active exploitation in production
- Data breach confirmed
- RCE vulnerability being exploited

**Response Time**: Immediate (< 15 minutes)

### SEV 2 - High
- Potential vulnerability identified
- Suspicious activity detected
- Dependency with known CVE in use

**Response Time**: < 4 hours

### SEV 3 - Medium
- Security scanner finding
- Code review security concern
- Minor dependency update needed

**Response Time**: < 24 hours

---

## Incident Response Procedure

### 1. Detection
- Monitor CodeQL alerts: https://github.com/SingularityRD/aidr/security/code-scanning
- Monitor Semgrep findings: https://github.com/SingularityRD/aidr/security/code-scanning
- If approved runtime/browser Sentry telemetry is configured, monitor its
  actual project and alert route; otherwise use local logs and deployed
  monitoring. A repository URL alone is not an operating alert.

### 2. Triage
```bash
# Run the repository's production-dependency audit (package.json script).
pnpm audit:prod
```

### 3. Containment
- For vulnerable dependency: Pin to safe version immediately
- For exposed secret: Rotate credentials immediately
- For active exploit: Disable affected feature flag

### 4. Investigation
```bash
# Check git history for affected code
git log --all --source --remotes --full-history -- <file>

# Find tracked source references (works from any shell with Git installed).
git grep -n "functionName" -- packages/
```

### 5. Remediation
- Apply fix
- Add regression test
- Update security documentation if needed

### 6. Post-Incident
- Document in security advisories
- Update detection rules if applicable

## Durable State Lock Unavailable

The telemetry queue, SIEM delivery state, and fleet-response journal fail closed
when a lock is empty, malformed, foreign-hosted, or otherwise cannot be tied to
a known-dead process. Do not treat an old timestamp as proof that an owner has
stopped, and do not delete the queue, journal, or delivery state to clear an
alert.

1. Stop or pause every AIDR process that can write the affected state directory,
   including processes on other hosts that share the volume.
2. Preserve a copy of the state directory and exact lock path. Record the lock
   marker, host, PID, process-generation timestamp, and service logs; redact
   secrets before sharing evidence.
3. Confirm no writer remains on any host. If that cannot be established, leave
   the lock in place and escalate to the state owner.
4. Only after confirming all writers are stopped, move the exact lock path aside
   as a recoverable quarantine item. Do not move or remove the state file, WAL,
   telemetry queue, or response journal.
5. Start one writer, verify queue/journal health and reconcile pending events or
   response-command outcomes before restoring normal concurrency. Treat an
   unknown command outcome as requiring reconciliation, never as permission to
   execute the command again.
