# Supabase Control Plane (Self-host / Reference)

This folder contains a reference **Supabase** schema + edge function for running a minimal Singularity AIDR control plane:

- Email auth (Supabase Auth)
- API key table (hash-only)
- Agent inventory (per installation id `iid`)
- Event ingestion endpoint (`ingest` edge function)
- Optional reputation endpoints (`url-check`, `file-check` edge functions)
- Row-Level Security policies for a multi-tenant dashboard

## What you get

- **1 free agent** per user by default (`entitlements.included_agents = 1`)
- **Paid agents** can be enabled by increasing `entitlements.extra_agents`

## Deploy (high level)

1. Create a Supabase project.
2. Apply migrations in `supabase/migrations/`.
3. Deploy the edge function in `supabase/functions/ingest`.
   - Optional: also deploy `supabase/functions/url-check` and `supabase/functions/file-check` if you want self-hosted reputation.
4. Set `control_plane.endpoint` to `https://YOUR_PROJECT.supabase.co/functions` and set `auth.api_key` in the agent config.

The edge function requires:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

These are provided automatically in the Supabase Edge Functions runtime.
