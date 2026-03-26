# Singularity AIDR Dashboard (Supabase)

This is a minimal multi-tenant dashboard for:

- User login (Supabase Auth)
- API key generation (hash-only storage)
- Agent inventory (per `iid`)
- Recent event timeline (from control plane ingest)

## Setup

1. Create a Supabase project and apply the schema in `supabase/migrations/`.
2. Configure Supabase Auth (email magic link is enough).
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
