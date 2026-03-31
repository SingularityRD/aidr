# Singularity AIDR Dashboard (Supabase)

This is a minimal multi-tenant dashboard for:

- User login (Supabase Auth)
- API key generation (hash-only storage)
- Agent inventory (per `iid`)
- Incidents view (derived from `events` telemetry)
- Billing / seat usage (1 agent free, $2 per extra agent / month)

## Setup

1. Create a Supabase project and apply the schema in `supabase/migrations/`.
2. Configure Supabase Auth:

   - Email magic link works out of the box.
   - Optional: enable Google provider and add a redirect URL for the SPA callback:
     - Local dev: `http://localhost:5173/auth/callback`
     - Production: `https://YOUR_DOMAIN/auth/callback`
3. Create `packages/dashboard/.env.local`:

```bash
VITE_SUPABASE_URL=...
VITE_SUPABASE_ANON_KEY=...
```

## Run

```bash
pnpm install
pnpm -C packages/dashboard dev
```

## Connect an agent

1. Sign in to the dashboard.
2. Create an API key (shown once).
3. On the agent machine, set:

```json
{
  "auth": { "api_key": "aidr_live_..." },
  "control_plane": { "enabled": true, "send_audit_logs": true }
}
```
