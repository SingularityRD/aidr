# Supabase Control Plane (Self-host / Reference)

This folder contains a reference **Supabase** schema + edge function for running a minimal Singularity AIDR control plane:

- Email auth (Supabase Auth)
- API key table (hash-only)
- Enrollment tokens (hash-only, one-time exchange for API keys)
- Device auth sessions (device-code flow)
- Pilot gating (applications + admin approvals)
- Public waitlist intake
- Agent inventory (per installation id `iid`)
- Event ingestion endpoint (`ingest` edge function)
- Billing primitives (Paddle checkout URL + webhook stub)
- Optional reputation endpoints (`url-check`, `file-check` edge functions)
- Row-Level Security policies for a multi-tenant dashboard

## What you get

- **1 free agent** per user by default (`entitlements.included_agents = 1`)
- **Paid agents** can be enabled by increasing `entitlements.extra_agents`

## Deploy (high level)

1. Create a Supabase project.
2. Apply migrations in `supabase/migrations/`.
3. Deploy the edge functions you need:
   - Required for telemetry + seats: `supabase/functions/ingest`
   - Recommended for dashboard UX: `supabase/functions/api-keys`, `supabase/functions/enrollment-tokens`
   - Enrollment exchange (agent bootstrap): `supabase/functions/enroll`
   - Device auth (prompt-install bootstrap): `supabase/functions/device-start`, `supabase/functions/device-poll`, `supabase/functions/device-verify`
   - Pilot gate: `supabase/functions/pilot-apply`, `supabase/functions/pilot-status`, `supabase/functions/pilot-admin`
   - Waitlist intake: `supabase/functions/waitlist-signup`
   - Optional billing: `supabase/functions/billing-checkout`, `supabase/functions/paddle-webhook`
   - Optional reputation: `supabase/functions/url-check`, `supabase/functions/file-check`
   - Optional premium intel delivery: `supabase/functions/packs-manifest`, `supabase/functions/packs-download`
   - Optional revocations feed: `supabase/functions/revocations`
4. Set `control_plane.endpoint` to `https://YOUR_PROJECT.supabase.co/functions` and set `auth.api_key` in the agent config.

The edge function requires (provided automatically in the Supabase Edge Functions runtime):

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

Commercial v1 (managed-first) requires additional secrets for signing and premium pack key derivation:

- `AIDR_ENTITLEMENT_SIGNING_KEY_ID`
- `AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64`
  - Base64 of the Ed25519 private key (PKCS8 PEM bytes).
- `AIDR_PACK_MASTER_KEY_B64`
  - Base64 of a 32-byte master key used to derive per-tenant AES-256-GCM pack keys (HKDF-SHA256).
- `AIDR_REVOCATION_SIGNING_KEY_ID`
- `AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64`
- `AIDR_REVOCATION_EPOCH` (default `1`)
- `AIDR_REVOCATION_TTL_HOURS` (default `24`)
- `AIDR_ENTITLEMENT_TTL_HOURS` (default `168`)
- `AIDR_ENTITLEMENT_GRACE_HOURS` (default `72`)

Operationally:

- Rotate signing keys by rolling `*_KEY_ID` and updating client `licensing.public_keys_pem` / `intel_packs.trusted_keys_path`.
- Treat `AIDR_PACK_MASTER_KEY_B64` as a crown-jewel secret; leaking it effectively leaks premium pack encryption for all tenants.
