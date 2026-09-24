# Alerting Runbook

**Status: configuration template only — production paging is not proven.** This
document describes possible PagerDuty, OpsGenie, and Sentry setup; it does not
mean those services, routes, alert rules, credentials, responders, or an on-call
rotation are configured. The repository has Sentry client hooks and a scheduled
Sentry-to-GitHub issue-sync workflow with an optional Slack notification, but
no PagerDuty or OpsGenie delivery integration. Before production GO, an owner
must configure the chosen service, verify credentials and routing, trigger a
real test event, and record responder acknowledgement. Do not treat this
runbook, CI success, or a local test as evidence of delivered pages or an SLA.

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

**Code hooks:** Sentry clients exist in `packages/core/src/sentry.ts` and
`packages/dashboard/src/sentry.ts`. Node runtime delivery additionally requires
`SENTRY_ENABLED=true` (or `1`) and a real `SENTRY_DSN`; browser delivery uses
its separately configured DSN. Provider-side project/rule configuration is
also required; these files do not prove that either
is present or that an alert reaches an operator.

**Proposed project names (verify against the configured DSNs; repository code
does not establish that these projects exist):**
- `aidr-core` — Core library errors
- `aidr-claude-code` — Claude Code hook errors
- VS Code/Cursor extension crash telemetry is not initialized; no extension
  Sentry project is implied by the current code
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
- `release-version.yml` — version PR only (does not publish)
- `release-rc.yml` — protected release-candidate build
- `release-promote.yml` — manually dispatched promotion/rollback/yank
- `codeql.yml` — Security scanning
- `semgrep.yml` — Static analysis
- `error-to-insight.yml` — scheduled Sentry issue sync; its optional Slack step is not an on-call paging route

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

There is no PagerDuty step in the current workflows. Do not paste an unpinned
third-party action into CI. If PagerDuty is selected, add a reviewed integration
that references an immutable action commit (or a separately reviewed API
client), keeps the integration key in an approved secret store, limits workflow
permissions, and has an end-to-end test receipt before relying on it.

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

There is no OpsGenie step in the current workflows. If OpsGenie is selected,
use an owner-reviewed, immutable integration, keep its key in an approved secret
store, restrict workflow permissions, and prove delivery and acknowledgement
before treating it as an operational alert path.

### Step 5: Sentry Integration

1. In OpsGenie: Go to **Integrations** → **Add Integration**
2. Select **Sentry** from the marketplace
3. Configure:
   - **Organization:** singularityrd
   - **Project:** aidr-core
   - **Alert Filter:** Only "error" level events

---

## On-Call Rotation Setup

The schedules, example participants, severities, and response times in this
section are planning examples, not assigned people or an approved support SLA.
Replace them with named, available responders and obtain approval before using
any timing as a customer commitment.

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

The table and flow below are illustrative configuration examples only. Their
severity labels, response times, and escalation roles are not assigned,
staffed, measured, or approved customer commitments. Do not page or promise
these routes until the selected provider, named responders, and customer
schedule have passed the acceptance test at the top of this document.

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

Template only. For an actual security incident, use the approved restricted
incident channel and bridge from the customer-specific plan. No Slack channel,
all-hands policy, or bridge URL is established by this repository.

If those routes have been configured and tested, the incident commander may:

1. **Open the restricted incident channel** using the approved incident ID.
2. **Page assigned responders** using the tested escalation policy:
   ```bash
   # PagerDuty: Trigger "All Hands" escalation policy
   # OpsGenie: Use "Incident Command" feature
   ```
3. **Bridge call:** use the customer-approved, access-controlled bridge; no
   working bridge URL is stored in this repository.
4. **Roles (assign named people in the incident record):**
   - **Incident Commander:** Senior on-call engineer
   - **Scribe:** Document timeline in Slack
   - **Comms:** Engineering manager (stakeholder updates)

---

## Alert Triage Guide

### Sentry Alert Triage

When you receive a Sentry alert:

1. Acknowledge through the configured route within the approved support target.
   The 5-minute value formerly shown here was an example, not an approved or
   measured response target.

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

# 2. Reproduce in a disposable worktree so the active checkout stays untouched
git worktree add --detach <temporary-path> <failing-commit>
cd <temporary-path>
pnpm install --frozen-lockfile
pnpm test

# 3. Fix and merge
# Or revert if critical
```

### Custom Alert Examples

Illustrative only; these events are not currently emitted by this example code.
Before adding them, agree the signal/threshold and verify privacy redaction,
sampling, duplicate suppression, and delivery to an acknowledged responder.

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

The rows below are proposed examples, not existing Sentry alert rules or
verified thresholds. Configure and test them in the real project before relying
on them.

In Sentry, open the project identified by the configured runtime or browser DSN,
then configure and test the proposed rules there. The repository does not prove
that an `aidr-core` project exists.

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
  uses: 8398a7/action-slack@1750b5085f3ec60384090fb7c52965ef822e869e # v3.18.0
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

- [ ] Acknowledge alerts within the approved support target (the 5/15-minute
  examples above are not an approved or measured SLA)
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
