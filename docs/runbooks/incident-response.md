# Incident Response Runbook

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
- Monitor Sentry errors: https://sentry.io/organizations/singularityrd/

### 2. Triage
```bash
# Check current security status
pnpm audit --prod
pnpm run lint:versions
```

### 3. Containment
- For vulnerable dependency: Pin to safe version immediately
- For exposed secret: Rotate credentials immediately
- For active exploit: Disable affected feature flag

### 4. Investigation
```bash
# Check git history for affected code
git log --all --source --remotes --full-history -- <file>

# Find all references to affected function
grep -r "functionName" packages/
```

### 5. Remediation
- Apply fix
- Add regression test
- Update security documentation if needed

### 6. Post-Incident
- Document in security advisories
- Update detection rules if applicable
