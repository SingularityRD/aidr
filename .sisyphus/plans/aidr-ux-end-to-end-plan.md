# AIDR End-to-End UX Plan - Gartner-Ready Security Product

## Executive Summary

**Vision**: Singularity AIDR becomes the "Stripe of AI Security" - one-line integration, powerful defaults, transparent pricing.

**Core Philosophy**: 
- **Zero-config setup**: `npx aidr-setup` → Works in 30 seconds
- **1-Free-Per-User**: Every developer gets 1 project free forever
- **Invisible security**: Works in background, speaks up only when needed
- **Clear upgrade path**: Usage-based, feature-based, no surprises

---

## 1. Landing Page Design

### Hero Section
```
┌─────────────────────────────────────────────────────────┐
│  Singularity AIDR                                        │
│  ─────────────────────────────────────────────────     │
│  AI Agent Security in 30 Seconds                         │
│                                                          │
│  🛡️ One command: npx aidr-setup                          │
│  ✅ Zero configuration                                    │
│  🔒 150+ threat patterns                                  │
│  📊 Real-time protection                                  │
│                                                          │
│  [Get Started Free] [View Demo] [Documentation]          │
│                                                          │
│  🟢 Used by 10,000+ developers                          │
└─────────────────────────────────────────────────────────┘
```

**Key Messages**:
- "Security that doesn't slow you down"
- "Works with Claude, Cursor, VS Code, OpenClaw"
- "Free forever for your first project"

### Social Proof Section
- Logo cloud: Vercel, Stripe, Linear style
- Testimonial cards
- "Trusted by teams at [company logos]"

### How It Works (3 Steps)
```
1. Run: npx aidr-setup
   ↓
2. AIDR protects automatically
   ↓
3. Review threats in dashboard
```

### Feature Grid
| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| Tool Calls | 100/day | Unlimited | Unlimited |
| Threat Detection | Basic | Full 150+ | Full + Custom |
| NVD CVE Feed | ❌ | ✅ | ✅ + EPSS |
| MITRE Mapping | ❌ | ✅ | ✅ + STIX |
| Projects | 1 | 3 | Unlimited |
| Extra Agents | - | $3/mo each | $2/mo each |
| Support | Community | Email | Priority |

### Pricing Section (Updated - Extra Agents $2-3)
```
┌─────────────┬─────────────┬─────────────┐
│   FREE      │    PRO      │ ENTERPRISE  │
│  $0/month   │  $9/month   │ $49/month   │
├─────────────┼─────────────┼─────────────┤
│ 1 Project   │ 3 Projects  │ Unlimited   │
│ 100 calls/day│ Unlimited  │ Unlimited   │
│ Basic rules │ All features│ All + SLA   │
│             │ 30d logs    │ 1y logs     │
├─────────────┼─────────────┼─────────────┤
│ Extra:      │ +$3/agent   │ +$2/agent   │
│ [Start Free]│ [Start Pro] │ [Contact]   │
│ No CC req'd │ 14-day trial│ Sales       │
└─────────────┴─────────────┴─────────────┘

**Extra Agents**: Add more team members
- Pro: $3/month per extra agent
- Enterprise: $2/month per extra agent (bulk discount)
```

**Pricing Psychology**:
- Low entry barrier ($9 vs $19)
- Clear value at each tier
- Agent pricing encourages team adoption
- Enterprise gets volume discount

---

## 2. User Journey Map

### Phase 1: Discovery (0-30 seconds)
**User**: Hears about AIDR (Twitter, GitHub, word of mouth)
**Action**: Visits landing page
**Goal**: Understand value in 5 seconds
**Success**: Clicks "Get Started Free"

### Phase 2: Installation (30 seconds - 2 minutes)
**User**: Runs `npx aidr-setup`
**System**: 
1. Detects environment (Claude/Cursor/VS Code)
2. Creates config with smart defaults
3. Registers hooks automatically
4. Tests connection
5. Shows success message

**Output**:
```
🛡️  Singularity AIDR Setup

✓ Environment: Claude Code detected
✓ Config: ~/.singularity-aidr/config.json
✓ Hooks: Claude Code integrated
✓ Threat DB: 150 rules active
✓ Test: Protection working

🎯 AIDR is now active!

Free tier: 100 tool calls/day
Upgrade anytime: aidr upgrade

[View Dashboard] [Read Docs] [Dismiss]
```

### Phase 3: Daily Usage (Invisible)
**User**: Works normally with AI agent
**AIDR**: 
- Monitors every tool call (<50ms latency)
- Blocks/denies silently when safe
- Asks permission when uncertain
- Logs everything

**User sees**: Nothing (ideally)

### Phase 4: First Alert (Education Moment)
**Trigger**: User attempts risky command
**AIDR Response**:
```
⚠️  AIDR paused this command

Command: curl https://install.sh | bash
Risk: Supply chain attack vector

Why?
• Pipe-to-shell pattern detected
• Domain not in trusted list
• Could execute arbitrary code

Options:
[🔒 Use Safe Alternative]
[📖 Learn More]
[⏩ Proceed Anyway (I understand risks)]

Your choice helps AIDR learn. This alert won't show again for this pattern.
```

### Phase 5: Dashboard Discovery (Week 1)
**User**: Runs `aidr dashboard` or visits web URL
**Sees**:
- Security score (A+ to F)
- Recent activity graph
- Top threats blocked
- Usage quota (X/100 remaining)
- Upgrade prompt (if approaching limit)

### Phase 6: Upgrade Decision (When quota hits 80%)
**Trigger**: Usage alert
**Message**:
```
🎯 You've used 80/100 free calls today

Upgrade to Pro for:
✓ Unlimited tool calls
✓ Real-time CVE feed
✓ MITRE ATT&CK mapping
✓ 3 projects
✓ Extra agents $3/mo each

[Upgrade Now - $9/mo] [Remind Me Later] [Stay Free]
```

---

## 3. Dashboard Layout

### Overview Tab
```
┌──────────────────────────────────────────────────────┐
│  Security Score: A+  🟢                               │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   │
│                                                       │
│  Activity (24h)            Threats Blocked             │
│  ┌──────────────────┐     ┌──────────────────┐        │
│  │  Sparkline graph │     │  MITRE T1059: 2  │        │
│  │  245 calls       │     │  Supply Chain: 1 │        │
│  └──────────────────┘     └──────────────────┘        │
│                                                       │
│  Quota: 67/100 (Free)        [Upgrade to Pro]        │
│  ████████████░░░░░░░░░░░░░  Unlimited calls + more    │
└──────────────────────────────────────────────────────┘
```

### Activity Feed
```
┌──────────────────────────────────────────────────────┐
│  Recent Activity                                      │
│  ──────────────────────────────────────────────────   │
│                                                       │
│  ✅ 14:32  Write to /tmp/test.txt                    │
│  ✅ 14:30  Read ~/.bashrc                             │
│  ⚠️  14:28  curl | bash (asked → user approved)      │
│  🚫 14:15  rm -rf / (blocked)                        │
│                                                       │
│  [View All] [Export Log]                              │
└──────────────────────────────────────────────────────┘
```

### Threats Tab
```
┌──────────────────────────────────────────────────────┐
│  Blocked Threats (Last 30 Days)                      │
│  ──────────────────────────────────────────────────   │
│                                                       │
│  MITRE ATT&CK Breakdown:                             │
│  • T1059 Command Execution: 12                       │
│  • T1567 Exfiltration: 3                             │
│  • T1552 Credential Access: 2                        │
│                                                       │
│  [View Details] [Generate Report]                    │
└──────────────────────────────────────────────────────┘
```

### Settings Tab
```
┌──────────────────────────────────────────────────────┐
│  Sensitivity: [Balanced ▼]                           │
│  Mode: [Local ▼]                                      │
│                                                       │
│  Features:                                            │
│  ☑️ NVD CVE Feed (Pro)                              │
│  ☑️ MITRE Mapping (Pro)                             │
│  ☐ Custom Rules (Enterprise)                        │
│                                                       │
│  [Save] [Reset to Defaults]                           │
└──────────────────────────────────────────────────────┘
```

---

## 4. 1-Free-Per-User Strategy

### Core Rule
"Every human gets 1 free project forever"

### Implementation
- Sign up with email → 1 free project
- No credit card required
- No time limit
- Basic features (100 calls/day, basic threats)

### Why This Works
1. **Zero friction**: Try immediately, no payment
2. **Real value**: 100 calls/day = genuine utility
3. **Habit formation**: Daily usage creates dependency
4. **Natural upgrade**: Hit limit → pay for convenience
5. **Viral growth**: Dev tells team "we need this"

### Upgrade Triggers
- Daily quota >80% (gentle nudge)
- Need team features (hard limit)
- Want CVE feed (feature gate)
- 30 days of consistent usage (email campaign)

---

## 5. Alert/Notification System

### Alert Levels

**Level 1: Silent (Default)**
- Safe operations: logged only
- User sees: nothing

**Level 2: Inline (Ask)**
- Uncertain operations: brief pause
- User sees: 1-line explanation + [Allow/Deny]

**Level 3: Modal (Block)**
- Dangerous operations: full stop
- User sees: detailed warning + alternatives

**Level 4: Dashboard (Summary)**
- Daily/weekly digest
- User sees: security report email

### Alert Design Principles
1. **Explain why**: MITRE technique ID, CVE reference
2. **Offer alternatives**: Safer ways to achieve goal
3. **One-click actions**: No complex decision trees
4. **Learn from choice**: "Don't ask again for this pattern"
5. **No alert fatigue**: Smart batching, severity filtering

---

## 6. Technical Implementation Plan

### Components to Build

1. **Landing Page** (Next.js + Tailwind)
   - Hero, features, pricing, testimonials
   - SEO optimized, fast loading
   - Analytics tracking

2. **Dashboard Web App** (Next.js + React)
   - Real-time activity feed
   - Usage graphs (Recharts)
   - Team management
   - Settings panel

3. **CLI Tool** (Node.js)
   - `aidr-setup`: One-command install
   - `aidr dashboard`: Open web dashboard
   - `aidr status`: Check protection status
   - `aidr upgrade`: Handle subscription

4. **Auth System** (Clerk/Supabase)
   - Email/password + OAuth
   - API key management
   - Team/organization support

5. **Billing Integration** (Stripe)
   - Subscription management
   - Usage metering
   - Invoice generation

6. **Backend API** (Fastify/Express)
   - Usage tracking
   - Quota enforcement
   - Webhook handling
   - Real-time updates

### Database Schema (Simplified)

```typescript
// Users
interface User {
  id: string;
  email: string;
  tier: 'free' | 'pro' | 'enterprise';
  createdAt: Date;
  apiKeys: string[];
}

// Projects (1 free per user)
interface Project {
  id: string;
  userId: string;
  name: string;
  tier: 'free' | 'pro' | 'enterprise';
  dailyQuota: number;
  currentUsage: number;
}

// Usage Logs
interface UsageLog {
  id: string;
  projectId: string;
  toolName: string;
  decision: 'allow' | 'deny' | 'ask';
  timestamp: Date;
  threatId?: string;
}
```

---

## 7. Success Metrics

### North Star Metric
**Weekly Active Developers (WAD)**: Developers with ≥1 protected tool call

### Leading Indicators
- Time to first protection (<30 seconds target)
- Daily tool calls per user (engagement)
- Free → Pro conversion rate (target: 5-10%)
- NPS score (target: >50)
- Support ticket volume (low = good UX)

### Lagging Indicators
- Monthly Recurring Revenue (MRR)
- Customer Acquisition Cost (CAC)
- Lifetime Value (LTV)
- Churn rate

---

## 8. Implementation Roadmap

### Phase 1: MVP (Week 1-2)
- [ ] Landing page (static)
- [ ] CLI setup command
- [ ] Basic auth (email only)
- [ ] Free tier enforcement

### Phase 2: Core UX (Week 3-4)
- [ ] Dashboard web app
- [ ] Usage tracking
- [ ] Upgrade flow
- [ ] Alert system

### Phase 3: Growth (Week 5-6)
- [ ] Team features
- [ ] Pro/Enterprise tiers
- [ ] Billing integration
- [ ] Email campaigns

### Phase 4: Scale (Week 7-8)
- [ ] Performance optimization
- [ ] Advanced analytics
- [ ] Enterprise sales flow
- [ ] Partnerships

---

## 9. Risk Mitigation

### Technical Risks
- **Latency**: <50ms target, async processing
- **False positives**: Smart defaults, easy override
- **Privacy**: Local-first, no code exfiltration

### Business Risks
- **Low conversion**: Optimize pricing page, add testimonials
- **High churn**: Better onboarding, usage alerts
- **Support burden**: Self-serve docs, community

---

## 10. Open Questions

1. Should free tier require email verification?
2. How to handle abuse (1 free per user enforcement)?
3. Which payment provider (Stripe vs Paddle vs LemonSqueezy)?
4. Should we offer annual discount?
5. Team features: per-seat or flat rate?

---

**Plan Status**: Ready for implementation
**Priority**: P0 - Critical for product success
**Estimated Effort**: 6-8 weeks (2 developers)
