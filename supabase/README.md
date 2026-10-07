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
- Billing/entitlement primitives (enterprise invoice reconciliation plus disabled legacy self-service checkout/webhook endpoints)
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
   - Legacy billing functions (do not deploy or advertise for direct GA): `supabase/functions/billing-checkout`, `supabase/functions/paddle-webhook`, `supabase/functions/stripe-webhook`
   - Optional reputation: `supabase/functions/url-check`, `supabase/functions/file-check`
   - Optional premium intel delivery: `supabase/functions/packs-manifest`, `supabase/functions/packs-download`
   - Optional revocations feed: `supabase/functions/revocations`
4. Set `control_plane.endpoint` to `https://YOUR_PROJECT.supabase.co/functions` and set `auth.api_key` in the agent config.

The edge function requires (provided automatically in the Supabase Edge Functions runtime):

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

### Configuration is validated, not assumed

Every Edge Function resolves these through `supabase/functions/_shared/config.ts`
and validates them at the start of the request, before any authentication,
database or network work. A missing variable is a **fail-closed** server
configuration error, not an empty credential:

```json
HTTP/1.1 500
{ "error": "server_misconfigured", "missing": ["SUPABASE_SERVICE_ROLE_KEY"] }
```

The response names the missing *variable*; a configured value is never echoed
into a response or a log line. The same contract covers function-specific
secrets: `AIDR_PADDLE_WEBHOOK_SECRET` (legacy paddle-webhook). The disabled-by-default
Stripe `billing-checkout` path requires `STRIPE_SECRET_KEY`,
`AIDR_STRIPE_EXTRA_AGENT_PRICE_ID`, and `AIDR_DASHBOARD_URL` when enabled;
its yearly option additionally uses `AIDR_STRIPE_EXTRA_AGENT_YEARLY_PRICE_ID`.
`stripe-webhook` keeps its own documented
fail-closed path for an unprovisioned `STRIPE_WEBHOOK_SECRET`: `400`
`invalid_signature` with no writes, because Stripe must not retry a delivery
that could never be verified.

A *half*-configured secret pair (a `*_KEY_ID` without its
`*_PRIVATE_KEY_PKCS8_B64`, or an AutoSecOps endpoint without its token) is also
reported instead of silently degrading to an unsigned or "not configured"
answer. Variables with documented defaults (`AIDR_PACKS_BUCKET`,
`AIDR_*_TTL_HOURS`, `AIDR_*_RL_PER_MIN`, `AIDR_ALLOWED_ORIGINS`, ...) stay
optional.

Commercial v1 (managed-first) requires additional secrets for signing and premium pack key derivation:

- `AIDR_ENTITLEMENT_SIGNING_KEY_ID`
- `AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64`
  - Base64 of the Ed25519 private key (PKCS8 DER bytes).
- `AIDR_POLICY_SIGNING_KEY_ID`
- `AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64`
  - Optional Ed25519 key (PKCS8 DER base64) that signs the `policy` function's `policy_signed` envelope.
    Set both or neither; a half-configured pair returns `503 policy_signing_unavailable`. When unset, the
    entitlement key above is reused; with neither the policy is served unsigned, and connectors that hold
    policy public keys reject it. A dedicated key is recommended.
- `AIDR_POLICY_SIGNATURE_TTL_HOURS` (default `24`; `1..720`)
- `AIDR_PACK_MASTER_KEY_B64`
  - Base64 of a 32-byte master key used to derive per-tenant AES-256-GCM pack keys (HKDF-SHA256).
- `AIDR_REVOCATION_SIGNING_KEY_ID`
- `AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64`
  - Required for `GET /revocations`: without a usable key the feed answers
    `503 revocation_signing_unavailable` (never a `200` with `revocations_signed: null`). The signed
    payload is schema 2 and carries `tenant_id` (and `agent_id` for agent-bound keys); runtimes accept
    a list only when its signed `tenant_id` equals the tenant of their verified entitlement. Unbound
    schema-1 lists are rejected with no compatibility window, so upgrade the control plane before (or
    together with) runtimes: an older runtime cannot verify a schema-2 list and keeps running without
    revocations until it is upgraded.
- `AIDR_REVOCATION_EPOCH` (default `1`)
- `AIDR_REVOCATION_TTL_HOURS` (default `24`)
- `AIDR_ENTITLEMENT_TTL_HOURS` (default `168`)
- `AIDR_ENTITLEMENT_GRACE_HOURS` (default `72`)
- `AIDR_RUNTIME_CAPABILITIES_BY_TENANT` (default `{}`): deployment/operator-only
  JSON mapping exact tenant IDs to `runtime_detectors` and optionally
  `behavioral_learning_v1`. Learning requires both names; wildcards and other
  module names are rejected. Maximum 64 KiB, 256 tenants, two unique capabilities
  per tenant. Missing or malformed maps grant no runtime capabilities.
  `enroll` and every `ingest` refresh require an active, finite licensed admission
  for the same tenant and the existing Ed25519 signer before adding these grants;
  trial/pilot access and browser/request flags cannot mint them. Snapshots retain
  the existing licensed/provider expiration cap.
- `AIDR_PACK_URL_TTL_SECONDS` (default `600`; clamped to `60..3600`)
- `AIDR_PACK_DOWNLOAD_GRANT_SECRET` (required by `packs-manifest` and `packs-download`; use an independently generated random secret of at least 32 bytes and set the same value on both functions)
- `AIDR_PUBLIC_API_ORIGIN` (the customer/agent-reachable API origin for pack grant links; required when `SUPABASE_URL` is an internal HTTP service name; HTTPS except for explicit loopback development)

The canonical migrations create a private `aidr-packs` Storage bucket; publish pack bytes through a service-role-only process. Pack manifests return at most 50 pack versions per request. Each `download_url` is a short-lived scoped AIDR URL, not a Storage URL; the Edge Function rechecks key, membership, entitlement and pack expiry on each GET/HEAD, then streams the object with range support. Treat the URL as a temporary bearer capability and redact its `grant` query parameter from any application/proxy logs. It contains neither the API key nor a Storage signed URL.
SCIM collection pages contain at most 200 resources, and a group request or response contains at most 1,000 member references.

Operationally:

- Rotate signing keys by rolling `*_KEY_ID` and updating client `licensing.public_keys_pem` / `intel_packs.trusted_keys_path`.
- Treat `AIDR_PACK_MASTER_KEY_B64` as a crown-jewel secret; leaking it effectively leaks premium pack encryption for all tenants.
- For an explicitly authorized tenant, set the same server-only
  `AIDR_RUNTIME_CAPABILITIES_BY_TENANT={"TENANT_ID":["runtime_detectors","behavioral_learning_v1"]}`
  on both `enroll` and `ingest`; keep the mapping in the operator change record.
  Removing a tenant or its capabilities takes effect on the next signed
  enrollment/ingest refresh; existing offline snapshots retain their bounded
  expiry/grace until then. Use existing revocation controls for immediate
  revocation. Enrollment audit detail records the issued runtime capabilities.
  Grants alone do not activate learning: the tenant publisher must also install
  a compatible signed detector policy with explicit learning consent and separate
  execution/approval authority public keys. Private authority keys stay in their
  separate operator custody.

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
| `record_billing_webhook_event` | Record a provider event (`paddle`, `stripe`) | `event_id` conflict makes duplicate delivery a no-op |
| `register_audit_export_object` | Reserve the stored bytes of one private export object against the tenant budget | Tenant advisory lock serializes the usage read and the reservation insert |
| `queue_bounded_fleet_response_command` | Queue a fleet response command under the per-tenant live-command ceiling | Tenant advisory lock serializes the depth count and the insert; the unbounded `queue_fleet_response_command` is no longer an RPC |

The per-tenant byte budget for stored audit exports is
`AIDR_AUDIT_EXPORT_TENANT_BYTES` (default 512 MiB, hard ceiling 1 TiB enforced by
the database). It is a configured plan figure, not a claim about any provider
quota.

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
  schema change. `increment_rate_limit` only accepts a key inside the reviewed
  scope allowlist (`20260913000005_tenant_storage_queue_quotas.sql`): a new
  caller scope is a migration, not a caller-side string.
- Audit logs are append-only and team deletion is restricted while audit rows
  exist. Owner removal is rejected unless an explicit service-role
  offboarding workflow is running.

### Local proof commands

Run these before opening a release PR:

```powershell
pnpm supabase:check
pnpm dlx supabase@latest db reset --local --yes
pnpm dlx supabase@2.114.0 db lint --local --fail-on error
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
   allowlist accepts normalized HTTPS origins only; wildcard, malformed, and
   path-bearing values are ignored. `AIDR_DEVELOPMENT_MODE=true` permits exact
   loopback HTTP origins solely for the generated local `--development` stack.
   dashboard-facing device, pilot, key, enrollment, and billing functions reject
   browser origins that are not on this allowlist and answer `OPTIONS` preflight
   requests before any auth or database work. Direct-GA
   billing is invoice/order based; keep the legacy Paddle checkout/portal and the
   Paddle/Stripe webhook endpoints disabled unless a separately approved
   commercial decision enables them with
   `AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING=true` and
   `AIDR_BILLING_PROVIDER=stripe`. The Lemon Squeezy webhook was
   removed (it performed no signature verification) and replaced by
   `supabase/functions/stripe-webhook`, which verifies the raw-body
   `Stripe-Signature` in constant time inside a replay window, deduplicates event
   ids before writing, and gates entitlements on the subscription status and the
   configured extra-agent price. Stripe is implemented and unit-tested only: it
   is not deployed, `STRIPE_WEBHOOK_SECRET` is not provisioned, and it has not
   been verified against a live Stripe account. Rotate keys through a reviewed
   runbook.
5. Run a staging replay: device start → verify → poll → enroll → ingest;
   concurrent poll/enroll/ingest calls must produce one exchange, one token,
   and no seat oversubscription. Reconcile one signed enterprise order into an
   entitlement, exercise private-registry access, then revoke/offboard it and
   confirm all access is removed. Legacy checkout replay is out of scope for the
   direct-GA release.
6. Enable backups, PITR, alerting, request-id correlation, webhook failure
   alerts, and a tested restore. Do not call the system production-ready
   without browser and agent smoke evidence from the actual hosted endpoint.

## Abuse limits and database hardening (2026-10-05)

- Public endpoints apply fixed one-minute windows through `increment_rate_limit` (shared helper `functions/_shared/rate-limit.ts`) and fail closed (429/503 with `Retry-After`). `device-poll`: `AIDR_DEVICE_POLL_RL_PER_MIN` (per device-code hash, default 60), `AIDR_DEVICE_POLL_CLIENT_RL_PER_MIN` (per trusted-ingress client IP, default 120) and `AIDR_DEVICE_POLL_GLOBAL_RL_PER_MIN` (aggregate, default 6000). `scim`: `AIDR_SCIM_TOKEN_RL_PER_MIN` (per SCIM token, default 600) and `AIDR_SCIM_GLOBAL_RL_PER_MIN` (deployment-wide budget of failed bearer authentications, counted only after a token is rejected so it never throttles a valid tenant token; default 6000). `enroll`: `AIDR_ENROLL_UNRESOLVED_RL_PER_MIN` (deployment-wide budget of bearer values that resolve to no enrollment token, checked before the lookup, default 300). Machine API-key endpoints (`ingest`, `file-check`, `url-check`, `policy`, `policy-ack`, `packs-manifest`, `packs-download`, `GET revocations`): `AIDR_UNRESOLVED_API_KEY_RL_PER_MIN` (per-endpoint, deployment-wide budget of bearer values that resolve to no API key, read before the credential lookup and charged only on a miss, so valid keys never consume it; default 6000, `1..1000000`, an invalid value answers 503). `packs-download` additionally limits each API key to 120 requests per minute (3000 per tenant) across both grant minting and byte streaming. Invalid values answer 500/503. Raw caller IP headers are never trusted. When `AIDR_DEVICE_START_INGRESS_SECRET` is set, `device-poll` and the public `identity-security` recovery actions also accept the trusted-ingress HMAC proof (`device-poll:v1` / `identity-security:v1` contexts, signed by `deploy/cloudflare/worker.mjs`; `oidc-sso` uses `oidc-sso:v1` for its public start/callback/break-glass actions): an attested client IP is limited by its own bucket first and then a signed aggregate, while unsigned callers share a separate unsigned aggregate, so a direct caller cannot exhaust the budget of clients arriving through the ingress. A distributed attacker with many real IPs can still exhaust an aggregate budget, which is the documented availability trade-off. `pnpm verify:endpoint-auth` fails a public route that does not call the limiter.
- `waitlist-signup` is insert-only and answers a duplicate email exactly like a first signup.
- Every SECURITY DEFINER function in `public`/`app` pins `search_path` with an explicit `pg_temp` (migration `20261005101001`; guarded by `pnpm supabase:check` for new migrations and `pnpm verify:security-definer` against a real PostgreSQL). `app.tenant_admission_config` has deny-by-default RLS.
- Migration `20261007120000_security_review_hardening.sql` (static contract `scripts/security-review-hardening.test.mjs`, run by `pnpm supabase:check`): functions created by `postgres` no longer receive PUBLIC EXECUTE through the global default privileges, and every function created after `20260922000002` must carry an explicit revoke from PUBLIC; `tenant_identity_access_allowed` returns no tenant identity-policy metadata to a caller without a membership row; the `aidr-audit-exports` bucket is forced private; `create_team_tenant` limits each user to `app.team_creation_quota.max_per_day` new workspaces per rolling 24 hours (default 10, `1..1000`; operators change it with SQL, e.g. `update app.team_creation_quota set max_per_day = 25;`), answering SQLSTATE `54000` when exceeded; tenant membership helpers resolve `pg_catalog, public, pg_temp`; audit export objects are readable only by an active owner/admin of the tenant in the object path, behind the identity barrier.
