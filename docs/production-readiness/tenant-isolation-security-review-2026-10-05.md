# Tenant isolation and auth security review — 5 October 2026

Scope: `supabase/migrations`, `supabase/functions`, `packages/dashboard/supabase/functions`. Method: source reading plus the existing vitest contract suites (`supabase/functions/__tests__`, about 75 suites) and targeted new tests. **This is an internal review, not the independent assessment required by SEC-EXT-001.** Postgres/RLS behaviour was reviewed from migrations; the SQL integration scripts (`scripts/*-postgres*.mjs`, `supabase/tests`) need a database and were not run.

Result: **no critical or high issue found; two medium issues fixed with regression tests; four low items documented with owners.**

## Findings

| Sev | Finding | Status |
|---|---|---|
| MEDIUM | `packages/dashboard/supabase/functions/auth-callback/index.ts`: the signed OAuth `state` (`{tenant_id, redirect_uri}` + HMAC) had no expiry, so a captured value stayed valid indefinitely; request body was read with unbounded `req.json()`; the tenant-membership check ignored `expires_at` (an expired member passed); the `supabase-js` import was unpinned (`@2`). | **Fixed.** `verifyState` now requires an integer `exp`, rejects expired values and values more than 1 hour out (checked after the HMAC); body capped at 16 KiB (Content-Length and text length); expired memberships rejected; import pinned to `@2.116.0`. Tests: `packages/dashboard/supabase/functions/auth-callback/index.test.ts` (6 pass). Breaking for any state minter: none exists in the repo; the function is not listed in `supabase/config.toml` and the dashboard calls `oauth-callback` instead. If a minter exists elsewhere it must add `exp`. |
| MEDIUM | `supabase/functions/autosecops-runtime/index.ts`: no rate limit. Any tenant member could trigger unlimited outbound provider calls on the shared provider credential, each holding a 5 s request open. | **Fixed.** `consumeTenantRateLimit` before the provider call: 120/min per user, 600/min per tenant; fails closed with 503 when the counter store is unavailable; 429 carries `Retry-After` and makes no provider call. Tests: `supabase/functions/__tests__/autosecops-runtime-contract.test.ts` (27 pass). |
| LOW | `device-poll` (unauthenticated) and `scim` have no application-level rate limit. `device-poll` does a cheap indexed hash lookup and device codes carry 256 random bits; SCIM is bearer-token gated. | Open. **Owner: Operations/Engineering** apply a gateway/WAF limit, or reuse the `device-start` signed-ingress limiter (needs `readDeviceCode` shape-test changes). |
| LOW | `waitlist-signup` upserts on `email_lower`: anyone knowing an address can overwrite that row's name, company and message. | Open. Needs a DB change (insert-only, or update only when empty). **Owner: Engineering.** |
| LOW | About 40 `SECURITY DEFINER` functions use `search_path = public, pg_catalog` without `pg_temp` (e.g. `scim_resolve_token`, `consume_enrollment_token`). Not reachable through PostgREST because `CREATE` on `public` is revoked from browser roles. | Open (defence in depth). A follow-up migration can set `pg_catalog, public, pg_temp`. **Owner: Engineering.** |
| LOW | `app.tenant_admission_config` has no RLS, but all privileges are revoked from every role (`20260923000034`). | Open (defence in depth only). |
| INFO | SIEM delivery has no private-IP / DNS-rebinding block (`packages/core/src/siem-delivery.ts`): HTTPS-only, no userinfo/query/fragment, `redirect:"error"`, 10 s timeout. The endpoint is operator configuration, not tenant-supplied input, so this is not a multi-tenant server-side SSRF. | Documented. Add an allow-list option if an operator wants to restrict targets. |
| INFO | CR/LF log injection in CEF/LEEF exports (also covered in the feature document). | **Fixed** (`packages/core/src/siem-export.ts`, `siem-export.test.ts`). |

## Verified, no change needed

- **RLS:** every `public` tenant table has RLS enabled; no `using (true)` / `with check (true)` on tenant data; `app.*` tables have privileges revoked. The only grant to `anon` is `aidr_readiness_probe()` (security invoker, returns `{ok:true}`). `20260922000002` resets browser-role grants to an allow-list; `20260924000002` strips browser writes on reputation tables.
- **SECURITY DEFINER functions:** all set `search_path`; spot-checked `create_team_tenant`, `list_team_members_with_email`, `visible_tenant_admission_capacity` for their own membership/role/tenant-active checks; privileged functions revoked from `public`/`anon`/`authenticated` and granted to `service_role`.
- **Service-role usage:** tenant derived from verified auth in every function reviewed: bearer-token functions use `getUser` then identity barrier plus membership/role/tenant status; API-key functions use `authenticateTenantApiKey` (SHA-256 lookup of a 256-bit key); `tenant_id`/`team_id` taken from body or header (`billing-checkout`, `policy-management`, `audit-export`, `delegated-credentials`, `identity-security`, `pilot-apply`, `scim-admin`) is UUID-validated then membership-checked or checked in an RPC; webhooks derive the tenant from signed payloads (Stripe and Paddle are legacy and disabled for direct GA).
- **PostgREST filter injection:** every `.or()` interpolation is constrained (HMAC-verified/regex-checked cursors in `audit-export` and `scim-admin`; auth-derived or UUID-validated ids in `packs-manifest` and `revocations`; server-generated timestamp in `autosecops-runtime`); SCIM filters use parameterised `.eq`.
- **SSRF in edge functions:** no tenant-supplied outbound destinations. Outbound calls go to Stripe, Google, or a signed storage URL (`redirect:"manual"` plus trusted-host check); the AutoSecOps URL is operator environment configuration (https-only, no userinfo, `redirect:"error"`, 5 s timeout).
- **Timing and signatures:** Stripe/Paddle/device-start HMAC use constant-time comparison; pack-grant and audit cursors use `crypto.subtle.verify`; delegated credentials verified as EdDSA with a header allow-list.
- **CORS and errors:** exact https-only origin allow-list, unknown origins 403; responses use codes rather than raw errors; recovery codes carry 160 bits and break-glass recovery is rate limited.
- **Supply chain:** `pnpm audit --prod` clean after override bumps (see gates document).

## Owner actions arising

1. Operations: gateway rate limit for `device-poll` and `scim`.
2. Engineering: waitlist insert-only change; `pg_temp` search-path migration; decide on SIEM destination allow-list option.
3. Security Lead: include this review's scope and the low items in the SEC-EXT-001 assessor brief.
4. QA: run the Postgres-backed RLS/tenant suites against a disposable database on the RC and attach logs (not run in this pass).
