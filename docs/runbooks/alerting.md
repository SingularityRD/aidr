# Alerting Runbook

Complete guide for configuring and managing alerts for Singularity AIDR production systems using PagerDuty, OpsGenie, and Sentry.

## Table of Contents

- [Alert Sources](#alert-sources)
- [PagerDuty Setup Guide](#pagerduty-setup-guide)
- [OpsGenie Setup Guide](#opsgenie-setup-guide)
- [On-Call Rotation Setup](#on-call-rotation-setup)
- [Escalation Procedures](#escalation-procedures)
- [Alert Triage Guide](#alert-triage-guide)

---

## Alert Sources

### 1. Sentry (Error Monitoring)

**What it tracks:**
- Application crashes and exceptions
- Performance degradation (slow transactions)
- Release health (crash-free rate)
- Custom business logic alerts

**Integration:** Already configured in code via `@sentry/node` and `@sentry/browser`

**Key Projects:**
- `aidr-core` — Core library errors
- `aidr-claude-code` — Claude Code hook errors
- `aidr-extension` — VS Code/Cursor extension errors
- `aidr-dashboard` — Dashboard React errors

### 2. CI/CD Failures (GitHub Actions)

**What it tracks:**
- Build failures
- Test failures (unit, integration, E2E)
- Security scan failures (CodeQL, Semgrep)
- Secret leak detection (gitleaks)
- Dependency audit failures

**Workflows monitored:**
- `ci.yml` — Launch gate (PR checks)
- `release.yml` — Production releases
- `codeql.yml` — Security scanning
- `semgrep.yml` — Static analysis

### 3. Infrastructure (Optional)

**What it tracks:**
- Dashboard uptime (Vercel/Netlify)
- npm registry availability
- Extension marketplace status

---

## PagerDuty Setup Guide

### Step 1: Create Service

1. Navigate to: https://subdomain.pagerduty.com/services
2. Click **New Service**
3. Configure:
   - **Name:** Singularity AIDR Production
   - **Description:** Production alerts for Singularity AIDR
   - **Integration Type:** Events API v2
   - **Escalation Policy:** Create new (see below)

### Step 2: Get Integration Key

After creating the service:
1. Go to **Integrations** tab
2. Copy the **Integration Key** (looks like `r+xxxxx`)
3. Store as `PAGERDUTY_INTEGRATION_KEY` in GitHub secrets

### Step 3: Configure GitHub Actions

Add to `.github/workflows/ci.yml`:

```yaml
- name: Notify PagerDuty on Failure
  if: failure() && github.ref == 'refs/heads/main'
  uses: Entle/action-pagerduty-alert@0.2.0
  with:
    pagerduty-integration-key: ${{ secrets.PAGERDUTY_INTEGRATION_KEY }}
    pagerduty-dedup-key: github-actions-${{ github.run_id }}
    incident-summary: "CI Failure: ${{ github.workflow }}"
    incident-severity: critical
```

### Step 4: Sentry Integration

1. In PagerDuty: Go to service → **Integrations** → **Add Integration**
2. Choose **Sentry** from the list
3. In Sentry: Go to **Settings** → **Integrations** → **PagerDuty**
4. Add the PagerDuty service key
5. Configure alert rules to send high-severity issues to PagerDuty

---

## OpsGenie Setup Guide

### Step 1: Create Team

1. Navigate to: https://app.opsgenie.com/teams
2. Click **Add Team**
3. Configure:
   - **Name:** Singularity AIDR
   - **Description:** Production support team
   - **Members:** Add on-call engineers

### Step 2: Create API Integration

1. Go to **Settings** → **Integrations** → **Add Integration**
2. Select **API** integration type
3. Configure:
   - **Name:** GitHub Actions
   - **Owner Team:** Singularity AIDR
   - **Priority:** P2 (Critical), P3 (Warning)
4. Copy the **API Key** (looks like `xxxxx-xxxxx-xxxxx`)
5. Store as `OPSGENIE_API_KEY` in GitHub secrets

### Step 3: Configure Alert Policies

1. Go to **Policies** → **Alert Policies**
2. Create policy:
   ```
   Policy Name: CI Critical Failures
   Conditions:
     - Priority equals P2
     - Source contains "github-actions"
   Actions:
     - Notify immediately
     - Escalate after 15 minutes if unacknowledged
   ```

### Step 4: GitHub Actions Integration

Add to `.github/workflows/ci.yml`:

```yaml
- name: Notify OpsGenie on Critical Failure
  if: failure() && github.ref == 'refs/heads/main'
  uses: opsgenie/opsgenie-action@v1.0
  with:
    api_key: ${{ secrets.OPSGENIE_API_KEY }}
    message: "AIDR Production CI Failure"
    priority: P2
    description: |
      Workflow: ${{ github.workflow }}
      Run: ${{ github.run_id }}
      Commit: ${{ github.sha }}
      Author: ${{ github.actor }}
    tags: ci,production,aidr
```

### Step 5: Sentry Integration

1. In OpsGenie: Go to **Integrations** → **Add Integration**
2. Select **Sentry** from the marketplace
3. Configure:
   - **Organization:** singularityrd
   - **Project:** aidr-core
   - **Alert Filter:** Only "error" level events

---

## On-Call Rotation Setup

### PagerDuty Schedule

#### Tier 1 — Primary On-Call

1. Navigate to: https://subdomain.pagerduty.com/schedules
2. Create new schedule:
   - **Name:** AIDR Primary On-Call
   - **Time Zone:** UTC (adjust for team)
   - **Rotation Type:** Weekly
   - **Start Date:** Next Monday
   - **Handoff Time:** 09:00

3. Add team members (in order):
   - Engineer A (Week 1)
   - Engineer B (Week 2)
   - Engineer C (Week 3)

#### Tier 2 — Escalation

1. Create second schedule:
   - **Name:** AIDR Escalation
   - **Rotation Type:** Weekly (offset by 1 day)
   - **Members:** Engineering leads

#### Escalation Policy

1. Go to: https://subdomain.pagerduty.com/escalation_policies
2. Create policy:
   ```
   Name: AIDR Production Escalation
   
   Level 1 (0 minutes):
     - AIDR Primary On-Call schedule
   
   Level 2 (15 minutes):
     - AIDR Escalation schedule
   
   Level 3 (30 minutes):
     - Engineering Manager (direct notification)
   
   Final (60 minutes):
     - CTO notification
   ```

### OpsGenie Schedule

1. Navigate to: https://app.opsgenie.com/schedules
2. Create schedule:
   - **Name:** AIDR On-Call
   - **Timezone:** UTC
   - **Rotations:**
     - Type: Weekly
     - Participants: Engineer A, Engineer B, Engineer C
     - Start: Next Monday 09:00

3. Set up routing rules:
   - **P1 (Critical):** Immediate call + SMS + email
   - **P2 (High):** Push notification + email
   - **P3 (Medium):** Email only (during business hours)

### Calendar Integration

#### Export PagerDuty to Google/Outlook Calendar

```bash
# PagerDuty provides calendar URLs
# Settings → Schedules → Export to Calendar

# Google Calendar:
# Settings → Add calendar → From URL
# Paste the PagerDuty iCal URL
```

#### OpsGenie Calendar Export

1. Go to: https://app.opsgenie.com/settings/calendar
2. Click **Export to Calendar**
3. Copy iCal URL
4. Subscribe in your calendar app

---

## Escalation Procedures

### Severity Levels

| Level | Definition | Response Time | Escalation Path |
|-------|-----------|---------------|-----------------|
| P1 | Production down / Data loss | 5 minutes | On-call → Lead → Manager → CTO |
| P2 | Major feature broken | 15 minutes | On-call → Lead → Manager |
| P3 | Minor issue / Degraded | 1 hour | On-call (next business day if overnight) |
| P4 | Cosmetic / Enhancement | 24 hours | Ticket queue |

### Escalation Flow

```
Alert Fires
    │
    ▼
┌─────────────────┐
│ Level 1: Primary│ ← 0 min
│   On-Call Eng   │
└─────────────────┘
    │ (unacknowledged)
    ▼
┌─────────────────┐
│ Level 2: Escalation│ ← 15 min
│   Senior Eng    │
└─────────────────┘
    │ (unacknowledged)
    ▼
┌─────────────────┐
│ Level 3: Manager│ ← 30 min
│   Eng Manager   │
└─────────────────┘
    │ (unacknowledged)
    ▼
┌─────────────────┐
│ Level 4: Exec   │ ← 60 min
│   CTO/VP Eng    │
└─────────────────┘
```

### Manual Escalation

If on-call needs help:

```bash
# PagerDuty: Add responder
# Use PagerDuty mobile app or web UI
# "Add Responder" → Select team member

# OpsGenie: Add responder
# Use OpsGenie mobile app
# "Add Team" or "Add User"
```

### War Room Protocol

For P1 incidents requiring immediate response:

1. **Create Slack channel:** `#incident-YYYY-MM-DD-brief-description`
2. **Page all hands:**
   ```bash
   # PagerDuty: Trigger "All Hands" escalation policy
   # OpsGenie: Use "Incident Command" feature
   ```
3. **Bridge call:**
   - Zoom: https://zoom.us/j/incident-bridge
   - Or Google Meet: Meet link
4. **Roles:**
   - **Incident Commander:** Senior on-call engineer
   - **Scribe:** Document timeline in Slack
   - **Comms:** Engineering manager (stakeholder updates)

---

## Alert Triage Guide

### Sentry Alert Triage

When you receive a Sentry alert:

1. **Acknowledge within 5 minutes**

2. **Classify severity:**
   - **P1:** Crash loop, data corruption, security breach
   - **P2:** Feature broken for many users
   - **P3:** Edge case error, single user affected

3. **Initial investigation:**
   ```bash
   # Check release
   sentry releases info <release-version>
   
   # View error details in Sentry UI
   # Check: Stack trace, Breadcrumbs, Tags, User impact
   ```

4. **Decision tree:**
   ```
   Is it a new error in latest release?
   ├── YES → Consider rollback
   │
   └── NO → Is it spiking?
       ├── YES → Check for external dependency failure
       └── NO → Add to backlog for next sprint
   ```

### CI Failure Triage

When CI fails on main/master:

1. **Immediate (P2):**
   - Secret leak detected (gitleaks)
   - Security scan failure (CodeQL critical)

2. **Urgent (P3):**
   - Build failure blocking releases
   - Test failure in core functionality

3. **Standard (P4):**
   - Flaky test failure
   - Coverage threshold miss

**Response:**
```bash
# 1. Check CI logs
curl -s https://api.github.com/repos/SingularityRD/aidr/actions/runs/<run-id>/logs

# 2. Reproduce locally
git checkout <failing-commit>
pnpm install
pnpm test

# 3. Fix and merge
# Or revert if critical
```

### Custom Alert Examples

Add to codebase for business-critical alerts:

```typescript
// packages/core/src/engine.ts
import * as Sentry from '@sentry/node';

// Critical: High-confidence malware detected
if (verdict.decision === 'deny' && confidence > 0.95) {
  Sentry.captureMessage('High-confidence malware blocked', {
    level: 'warning',
    tags: {
      threat_type: 'malware',
      confidence: confidence.toString(),
    },
  });
}

// Critical: Detection bypass attempt
if (suspiciousPatternDetected) {
  Sentry.captureException(new Error('Potential bypass attempt'), {
    level: 'fatal',
    tags: {
      alert_type: 'security',
    },
  });
}
```

---

## Alert Reference

### Sentry Alert Rules

Configure in Sentry: https://sentry.io/settings/singularityrd/projects/aidr-core/alerts/

| Rule Name | Condition | Action | Severity |
|-----------|-----------|--------|----------|
| New Issue | New issue created | Slack #alerts | Info |
| High Volume | >100 events in 5 min | PagerDuty | P2 |
| Regression | Resolved issue reoccurs | Email + Slack | P3 |
| Release Health | Crash-free rate <99% | PagerDuty | P2 |
| Performance | Transaction p95 >2s | Slack | P3 |

### GitHub Actions Notifications

Add to workflows for Slack notifications:

```yaml
- name: Slack Notification on Failure
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    channel: '#aidr-alerts'
    webhook_url: ${{ secrets.SLACK_WEBHOOK_URL }}
    fields: repo,message,commit,author,action,eventName,ref,workflow
```

### Alert Suppression

**PagerDuty:**
- Use **Event Rules** to suppress non-actionable alerts
- Create **Maintenance Windows** during planned deployments

**OpsGenie:**
- Use **Alert Policies** to drop low-priority alerts during off-hours
- **Notification Policies** to delay non-urgent notifications

---

## Testing Alerts

### PagerDuty Test Alert

```bash
curl -X POST https://events.pagerduty.com/v2/enqueue \
  -H "Content-Type: application/json" \
  -d '{
    "routing_key": "YOUR_INTEGRATION_KEY",
    "event_action": "trigger",
    "dedup_key": "test-alert-$(date +%s)",
    "payload": {
      "summary": "Test alert from Singularity AIDR",
      "severity": "info",
      "source": "test-script"
    }
  }'
```

### OpsGenie Test Alert

```bash
curl -X POST https://api.opsgenie.com/v2/alerts \
  -H "Content-Type: application/json" \
  -H "Authorization: GenieKey YOUR_API_KEY" \
  -d '{
    "message": "Test alert from Singularity AIDR",
    "priority": "P3",
    "source": "test-script"
  }'
```

### Sentry Test Alert

Trigger from CLI:
```bash
# Using Sentry CLI
sentry-cli send-event -m "Test alert" --level warning

# Or from application code
Sentry.captureMessage("Test alert", { level: "warning" });
```

---

## On-Call Checklist

### Start of Shift

- [ ] Acknowledge handoff from previous on-call
- [ ] Review open incidents in PagerDuty/OpsGenie
- [ ] Check Sentry for new issues in last 24h
- [ ] Review #aidr-alerts Slack channel
- [ ] Ensure phone charged, PagerDuty app installed

### During Shift

- [ ] Acknowledge alerts within SLA (5 min for P1, 15 min for P2)
- [ ] Update incident timeline with actions taken
- [ ] Escalate if stuck for >30 minutes
- [ ] Document all incidents in incident log

### End of Shift

- [ ] Create handoff notes for next on-call
- [ ] Ensure no unresolved P1/P2 incidents
- [ ] Update runbooks based on lessons learned
- [ ] Review alert noise (suggest suppressions if too chatty)

---

## Additional Resources

- PagerDuty Documentation: https://support.pagerduty.com/
- OpsGenie Documentation: https://support.atlassian.com/opsgenie/
- Sentry Alerting: https://docs.sentry.io/product/alerts/
- Incident Response Runbook: [incident-response.md](./incident-response.md)
