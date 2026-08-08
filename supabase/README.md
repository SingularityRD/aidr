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
- Billing/entitlement primitives (enterprise invoice reconciliation plus a disabled legacy checkout/webhook stub)
- Optional reputation endpoints (`url-check`, `file-check` edge functions)
- Row-Level Security policies for a multi-tenant dashboard

## What you get

- **1 free agent** per user by default (`entitlements.included_agents = 1`)
- **Paid agents** can be enabled by increasing `entitlements.extra_agents`

## Deploy (high level)

1. Create a Supabase project.
2. Run `pnpm supabase:check`, then apply migrations in `supabase/migrations/`.
3. Deploy the edge functions you need:
   - Required for telemetry + seats: `supabase/functions/ingest`
   - Recommended for dashboard UX: `supabase/functions/api-keys`, `supabase/functions/enrollment-tokens`
   - Enrollment exchange (agent bootstrap): `supabase/functions/enroll`
   - Device auth (prompt-install bootstrap): `supabase/functions/device-start`, `supabase/functions/device-poll`, `supabase/functions/device-verify`
   - Pilot gate: `supabase/functions/pilot-apply`, `supabase/functions/pilot-status`, `supabase/functions/pilot-admin`
   - Waitlist intake: `supabase/functions/waitlist-signup`
   - Legacy billing functions (do not deploy or advertise for direct GA): `supabase/functions/billing-checkout`, `supabase/functions/paddle-webhook`
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

## Migration history and tenant boundary

Migration files use unique 14-digit versions and an explicit dependency order:

`initial → reputation → golive → device/pilot/waitlist → control-plane API → commercial → team RBAC → tenant hardening → hybrid tenancy → atomic team creation`.

The repository previously had several `20260327_*.sql` files with the same
version and a lexical order that attempted to alter tables before creating
them. The files are now ordered and uniquely versioned so a clean local reset
is deterministic. If a real Supabase project has already recorded the legacy
8-digit migration names, stop before `db push`: reconcile the migration
history with the project owner (or perform a reviewed one-time backfill) and
do not silently run the renamed files as new migrations.

The canonical control-plane tenant key is the authenticated user UUID
(`auth.users.id`) for entitlements, agents, events, API keys, and snapshots.
The optional team RBAC layer adds `teams.id` and membership-based RLS for
shared policies/audit views; it does not replace the user UUID boundary.
Every event is constrained to an agent owned by the same user after the
tenant-hardening migration. Live project linkage, RLS inspection, and browser
smoke evidence are still required before a production GO decision.

## Hybrid tenancy contract (2026-08)

`20260805000000_hybrid_tenancy.sql` is the canonical ownership boundary for
new deployments. It is deliberately additive: the existing `user_id` and
`team_id` columns remain for compatibility, while every customer-owned
resource also carries an immutable `tenant_id`.

### Tenant and membership semantics

- A personal tenant uses the user's UUID as its `tenants.id` and has one
  `tenant_members` owner row.
- A team tenant uses the same UUID for `teams.id` and `teams.tenant_id`.
  Legacy `team_members` writes are mirrored into `tenant_members`.
- Entitlements/seats are keyed by `tenant_id`; `user_id` is retained as the
  owner/audit foreign key. This lets one person use separate personal and team
  plans without mixing seat counts.
- Roles are `owner`, `admin`, `member`, `viewer`, and time-bounded
  `support_jit`. An expired membership is not considered active by RLS.
- The request tenant is read from the verified JWT claim
  `request.jwt.claim.tenant_id`; personal users fall back to their personal
  tenant. Edge functions may accept `X-AIDR-Tenant-ID` only after checking
  membership. Clients must never be allowed to choose an arbitrary tenant.
- `tenant_id` is immutable on customer data. Events and entitlement snapshots
  use composite foreign keys to `(agents.tenant_id, agents.id)`, so a row from
  one tenant cannot reference an agent in another tenant.

### Edge-function admission rules

The following database functions are `SECURITY DEFINER` and executable only by
the service role. They are the concurrency boundary; do not reimplement their
read-then-write logic in an Edge Function:

| Function | Purpose | Idempotency/race guarantee |
| --- | --- | --- |
| `consume_enrollment_token` | Atomically consume an unexpired enrollment token | At most one successful exchange |
| `register_agent_for_ingest` | Upsert an agent and enforce included + extra seats | Tenant advisory lock prevents seat oversubscription |
| `authorize_device_session` | Attach a user to a pending device session | `authorized_at is null` compare-and-set |
| `exchange_device_session` | Claim a device code for enrollment | `exchanged_at is null` compare-and-set |
| `record_billing_webhook_event` | Record a provider event | `event_id` conflict makes duplicate delivery a no-op |

Service-role functions must return caller-safe errors and a request id. Never
log API keys, enrollment tokens, raw webhook signatures, or entitlement private
keys. Persist only SHA-256 hashes for API/enrollment secrets.

### Privilege and RLS boundary

- `service_role` has table access for Edge Functions; `anon` has no customer
  table DML and no access to security-definer helpers.
- `authenticated` receives only the table operations represented by the RLS
  policies. Every tenant read requires active membership and matching
  `app.current_tenant_id()`.
- `increment_rate_limit`, `user_id_by_email`, and the admission functions are
  not public RPC endpoints. Keep their `EXECUTE` grants restricted after every
  schema change.
- Audit logs are append-only and team deletion is restricted while audit rows
  exist. Owner removal is rejected unless an explicit service-role
  offboarding workflow is running.

### Local proof commands

Run these before opening a release PR:

```powershell
pnpm supabase:check
pnpm dlx supabase@latest db reset --local --yes
pnpm dlx supabase@latest db lint --local
pnpm exec vitest run supabase/functions/__tests__/security-flow.test.ts
```

The reset must apply every migration exactly once. A useful smoke check is to
create two local users, insert one API key per user, set
`request.jwt.claim.sub` under the `authenticated` role, and verify that each
user sees one key and zero rows from the other tenant. Also exercise one
successful and one duplicate call for each admission function.

### Live-project prerequisites (GO gate)

Before enabling customer traffic, the project owner must attach evidence for
all of the following:

1. Reconcile the hosted migration history with the renamed legacy files; take
   a backup and run the tenant backfill in staging first.
2. Confirm `tenants`, `tenant_members`, every `tenant_id` NOT NULL constraint,
   composite FKs, RLS policies, and restricted routine grants in the hosted
   database (not only local Docker).
3. Configure the JWT tenant claim or the server-side tenant-selection header;
   test two users and one shared team with negative cross-tenant reads/writes.
4. Deploy Edge Functions together with `SUPABASE_SERVICE_ROLE_KEY`, entitlement/
   revocation signing keys, pack master key, rate-limit settings, and an explicit
   `AIDR_ALLOWED_ORIGINS` list containing the deployed dashboard origin. The
   dashboard-facing device, pilot, key, enrollment, and billing functions reject
   browser origins that are not on this allowlist and answer `OPTIONS` preflight
   requests before any auth or database work. Direct-GA
   billing is invoice/order based; keep the legacy Paddle/Lemon checkout and
   portal paths disabled unless a separately approved commercial decision enables
   them with `AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING=true`. Rotate keys through
   a reviewed runbook.
5. Run a staging replay: device start → verify → poll → enroll → ingest;
   concurrent poll/enroll/ingest calls must produce one exchange, one token,
   and no seat oversubscription. Reconcile one signed enterprise order into an
   entitlement, exercise private-registry access, then revoke/offboard it and
   confirm all access is removed. Legacy checkout replay is out of scope for the
   direct-GA release.
6. Enable backups, PITR, alerting, request-id correlation, webhook failure
   alerts, and a tested restore. Do not call the system production-ready
   without browser and agent smoke evidence from the actual hosted endpoint.
