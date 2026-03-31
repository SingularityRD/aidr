# AIDR Implementation Plan v1.0
## For: Metis (Pre-planning) and Momus (Plan Review)

### Executive Summary
Implement complete AIDR (AI Agent Detection & Response) product based on lean-optimized principles but with rich web dashboard, Supabase auth, and Lemon Squeezy payments.

### User Decisions (Confirmed)
1. **Dashboard**: Rich web dashboard (Next.js + Tailwind) - Full featured
2. **Auth**: Supabase lite - Email auth only (no OAuth complexity)  
3. **Landing**: Static HTML with Lemon Squeezy embed (use existing landing)
4. **Core**: Based on aidr-lean-optimized.md principles

### Scope
- npx aidr-setup command
- CLI tool with core detection engine
- Web dashboard (Next.js app with stats, logs, config)
- Supabase integration (auth + PostgreSQL for audit)
- Lemon Squeezy subscription management
- Full audit trail system

### Technical Stack
| Component | Technology |
|-----------|-----------|
| CLI/Core | TypeScript (existing packages/core) |
| Dashboard | Next.js 14 + Tailwind + shadcn/ui |
| Auth | Supabase Auth (email only) |
| Database | Supabase PostgreSQL |
| Payments | Lemon Squeezy |
| Deployment | Vercel (dashboard), npm (CLI) |

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    USER LAYER                           │
├─────────────────────────────────────────────────────────┤
│  CLI: npx aidr-setup    │    Web: app.aidr.security     │
│  - Core engine          │    - Dashboard               │
│  - Local config         │    - Stats & logs            │
│  - Detection logic      │    - Settings                │
└──────────┬────────────────────────────┬─────────────────┘
           │                            │
           ▼                            ▼
┌──────────────────┐           ┌──────────────────────┐
│   CORE ENGINE    │           │   DASHBOARD API      │
│   (TypeScript)   │           │   (Next.js API)      │
│                  │           │                      │
│ • 150 rules      │◄─────────►│ • Auth middleware    │
│ • Heuristics     │  Webhook  │ • Audit endpoints    │
│ • MITRE mapping  │  (events) │ • Usage tracking    │
└──────────┬───────┘           └──────────┬───────────┘
           │                              │
           ▼                              ▼
┌──────────────────┐           ┌──────────────────────┐
│   LOCAL SQLITE   │           │   SUPABASE           │
│   (Cache/Config) │           │   • Auth (email)     │
│                  │           │   • PostgreSQL       │
└──────────────────┘           │   • Audit logs       │
                               └──────────┬───────────┘
                                          │
                                          ▼
                               ┌──────────────────────┐
                               │   LEMON SQUEEZY      │
                               │   • Subscriptions    │
                               │   • Webhooks         │
                               └──────────────────────┘
```

### Database Schema (Supabase)

```sql
-- Users (managed by Supabase Auth)
-- Profiles extension
CREATE TABLE profiles (
  id UUID REFERENCES auth.users PRIMARY KEY,
  tier TEXT CHECK (tier IN ('free', 'pro', 'proplus')) DEFAULT 'free',
  lemon_squeezy_customer_id TEXT,
  lemon_squeezy_subscription_id TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Usage tracking
CREATE TABLE usage_logs (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id),
  tool_name TEXT NOT NULL,
  tool_input JSONB,
  decision TEXT CHECK (decision IN ('allow', 'deny', 'ask')),
  threat_id TEXT,
  mitre_technique TEXT,
  latency_ms INTEGER,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Audit trail (immutable)
CREATE TABLE audit_trail (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id),
  action TEXT NOT NULL,
  details JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Custom rules (Pro tier)
CREATE TABLE custom_rules (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID REFERENCES profiles(id),
  name TEXT NOT NULL,
  pattern TEXT NOT NULL,
  action TEXT CHECK (action IN ('allow', 'deny', 'ask')),
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW()
);
```

### API Endpoints (Dashboard)

```typescript
// Auth (Supabase handles, custom wrappers)
POST /api/auth/register     // Email signup
POST /api/auth/login        // Email login
POST /api/auth/logout       // Signout

// Dashboard
GET  /api/dashboard/stats        // Overview stats
GET  /api/dashboard/activity     // Recent logs (paginated)
GET  /api/dashboard/threats      // Threat summary
GET  /api/dashboard/usage        // Usage quota

// Configuration
GET  /api/config                 // Get user config
POST /api/config                 // Update config
GET  /api/config/rules           // Get custom rules (Pro)
POST /api/config/rules           // Add custom rule (Pro)
DELETE /api/config/rules/:id     // Delete rule (Pro)

// Billing (Lemon Squeezy)
GET  /api/billing/status         // Current tier
POST /api/billing/checkout       // Create checkout
POST /api/billing/portal         // Customer portal
POST /api/billing/webhook        // LS webhooks
```

### File Structure

```
packages/
├── core/                    # Existing - detection engine
│   ├── src/
│   │   ├── engine.ts        # Core detection
│   │   ├── heuristics.ts    # 150 rules
│   │   └── cli.ts           # CLI commands
│   └── package.json
├── dashboard/               # NEW - Next.js app
│   ├── app/
│   │   ├── (auth)/          # Auth routes
│   │   ├── (dashboard)/     # Protected routes
│   │   │   ├── page.tsx     # Overview
│   │   │   ├── activity/
│   │   │   ├── threats/
│   │   │   └── settings/
│   │   └── api/             # API routes
│   ├── components/
│   │   ├── ui/              # shadcn components
│   │   ├── stats-card.tsx
│   │   ├── activity-table.tsx
│   │   └── threat-chart.tsx
│   ├── lib/
│   │   ├── supabase.ts      # Supabase client
│   │   └── lemon-squeezy.ts # Payment client
│   └── package.json
├── landing/                 # NEW - Static HTML
│   ├── index.html
│   ├── css/
│   └── js/
└── cli/                     # NEW - npm package
    ├── bin/
    │   └── aidr.js          # Entry point
    ├── src/
    │   ├── setup.ts         # npx aidr-setup
    │   ├── status.ts        # aidr status
    │   └── config.ts        # aidr config
    └── package.json
```

### Implementation Phases

#### Phase 1: Foundation (Week 1)
- [ ] Core engine optimization (existing packages/core)
- [ ] CLI tool structure (npx aidr-setup)
- [ ] Local SQLite for cache/config

#### Phase 2: Auth & DB (Week 2)
- [ ] Supabase project setup
- [ ] Database schema migration
- [ ] Email auth integration
- [ ] Profile management

#### Phase 3: Dashboard (Week 3)
- [ ] Next.js project setup
- [ ] Dashboard layout (sidebar + main)
- [ ] Overview page (stats)
- [ ] Activity page (logs)
- [ ] Settings page

#### Phase 4: Payments (Week 4)
- [ ] Lemon Squeezy setup
- [ ] Subscription webhooks
- [ ] Tier enforcement
- [ ] Upgrade flow

#### Phase 5: Integration (Week 5)
- [ ] CLI ↔ Dashboard sync
- [ ] Audit trail implementation
- [ ] Webhook handlers
- [ ] Error handling

#### Phase 6: Polish (Week 6)
- [ ] Landing page update
- [ ] Documentation
- [ ] Testing
- [ ] Deploy (Vercel + npm)

### Key Decisions Needed

1. **Real-time updates**: Polling (30s) vs WebSocket?
2. **Dashboard SSR**: Server-side rendering vs static export?
3. **Rate limiting**: API rate limits for dashboard?
4. **Offline mode**: CLI works offline, dashboard requires auth?
5. **Data sync**: How often CLI syncs with cloud?

### Performance Targets

| Metric | Target | Measurement |
|--------|--------|---------------|
| Detection latency | p95 <50ms | Avg of 1000 calls |
| Dashboard load | <2s | Time to interactive |
| CLI startup | <100ms | Time to first output |
| DB query | <100ms | p95 query time |
| Bundle size | <200KB | Dashboard initial JS |

### Security Considerations

- Supabase Row Level Security (RLS) for all tables
- API key rotation for CLI
- Webhook signature verification (Lemon Squeezy)
- Input sanitization on all endpoints
- Rate limiting on auth endpoints

### Compliance

- GDPR: Data export/deletion endpoints
- Audit logs: Immutable, 1-year retention
- Privacy: Local-first processing, cloud for sync only

---

## For Metis Review

Please analyze:
1. Are there hidden complexities I'm missing?
2. Is the scope appropriate for lean principles?
3. What could fail/go wrong?
4. Are there better alternatives?

## For Momus Review

Please verify:
1. Is the plan complete enough to execute?
2. Are acceptance criteria clear?
3. What dependencies need resolution?
4. Is the timeline realistic?

---

**Plan Version**: 1.0
**Status**: Ready for review
