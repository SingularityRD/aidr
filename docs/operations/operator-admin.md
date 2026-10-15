# Platform operator administration

The `operator-admin` Edge Function is the control-plane surface for platform
operators — the people who run an AIDR control plane, not tenant owners or admins. It covers:

| Action | CLI command | SQL wrapper | Existing RPC it calls |
|--------|-------------|-------------|---------------------------|
| `configure_admission_mode` | `mode <cloud\|onprem\|pilot>` | `operator_configure_admission_mode` | `configure_tenant_admission_mode` |
| `configure_legal_documents` | `legal …` | `operator_configure_legal_documents` | `configure_ga_legal_documents` |
| `grant_license` | `grant …` | `operator_grant_license` | `grant_licensed_tenant_admission` |
| `revoke_license` | `revoke …` | `operator_revoke_license` | `revoke_licensed_tenant_admission` |
| `list_tenants` | `tenants …` | `operator_list_tenants` | — (read, keyset paged) |
| `tenant_usage` | `usage --tenant ID` | `operator_tenant_usage` | `tenant_admission_capacity` |
| `list_license_imports` | `license-imports [--limit N]` | `operator_list_license_imports` | — (read: licenses tenant admins staged) |
| `apply_license` | `license-apply --tenant ID --license-file PATH [--import ID] [--owner ID]` | `operator_apply_license` | `operator_grant_license` -> `grant_licensed_tenant_admission` |

The CLI below and the dashboard Operator console (`/operator`) are the only clients. Browser
calls must come from an origin in `AIDR_ALLOWED_ORIGINS`; no agent or MCP tool can reach it.

## Authorization

A request succeeds only when every check below passes. If any check cannot be
completed, the request is refused (fail closed):

1. A Supabase access token. The gateway verifies the JWT (`verify_jwt = true`), and
   the handler checks it again with Auth.
2. The session revocation barrier (`checkIdentityBarrier`).
3. An active row in `public.platform_operators`: not revoked, and not past `expires_at`.
   If the lookup fails, the function returns `503 authorization_unavailable`.
4. Assurance level `aal2`. The operator must have completed TOTP MFA in this session
   (`403 mfa_required` otherwise).
5. A bounded (16 KiB) JSON body. The handler validates each field before any SQL runs.
6. Inside the SQL transaction, the wrapper checks the operator row again under a
   share lock. It then calls the existing RPC unchanged, and writes an
   `admin_audit_logs` receipt with `actor_user_id` set to the operator. If the RPC
   or the receipt fails, the whole change rolls back.

Licensed grants and revocations also keep the separation-of-duty rules in
`grant_licensed_tenant_admission` / `revoke_licensed_tenant_admission`. The same
user must have an unexpired `public.admission_operators` row for that tenant,
and must not be a member of it (see [admission-operators.md](admission-operators.md)).
Platform-operator status alone never admits a tenant.

### Provisioning a platform operator

`public.platform_operators` has no browser grants. The service role can only
`SELECT` from it. Add rows only through the database-administrator change process,
and put the change ticket in `change_reference`:

```sql
insert into public.platform_operators (user_id, change_reference, expires_at)
values ('<auth user id>', 'CHG-1234', now() + interval '30 days');
```

If you omit `expires_at`, the default is 30 days. Review the table weekly. To
withdraw access, set `revoked_at = now()`, and renew only after a fresh review.
The operator account must enroll a TOTP factor before the function accepts it.

## Audit receipts

Each successful action writes one actor-attributed row to `public.admin_audit_logs`:

| `action` | `tenant_id` | `detail` |
|----------|-------------|----------|
| `operator.admission_mode_configured` | — | `mode`, `status` (`configured` / `already_configured`) |
| `operator.legal_documents_configured` | — | terms/privacy `version`, `sha256`, `url`, `approval_reference` |
| `operator.license_granted` | tenant | `plan_id`, `seats`, `expires_at`, `reference` |
| `operator.license_revoked` | tenant | `status` (`revoked` / `not_active`), `reason` |
| `operator.tenants_listed` | — | `limit`, `after`, `count` |
| `operator.tenant_usage_read` | tenant | `{}` |
| `license.applied` | tenant | `import_id`, `source`, `license_id`, `key_id`, `seats`, `plan_id`, `expires_at`, `grace_ends_at`, `canonical_sha256` |

The underlying RPCs still write their own receipts (`admission.mode_configured`,
`admission.ga_legal_configured`, `admission.licensed_granted`,
`admission.licensed_revoked`) in the same transaction.

## CLI: `scripts/operator-admin.mjs`

The CLI reads credentials only from the environment. It never accepts them as
arguments, and it never prints a token.

| Variable | Purpose |
|----------|---------|
| `AIDR_SUPABASE_URL` (or `SUPABASE_URL`) | Project URL. Must be `https`; `http` is allowed only for `localhost`. A path prefix, such as a self-hosted gateway, is kept. |
| `SUPABASE_ANON_KEY` | Project anon key, sent as `apikey`. Required for password sign-in. |
| `AIDR_OPERATOR_ACCESS_TOKEN` | An AAL2 access token. When set, the CLI uses it as is. |
| `AIDR_OPERATOR_EMAIL`, `AIDR_OPERATOR_PASSWORD`, `AIDR_OPERATOR_TOTP_CODE` | Otherwise, the CLI signs in with a password and steps up with the current TOTP code. |
| `AIDR_OPERATOR_TOTP_FACTOR_ID` | Needed only when the account has more than one verified TOTP factor. |

```bash
# Fix the deployment admission mode (one-way; replaying the same mode is a no-op).
node scripts/operator-admin.mjs mode cloud

# Record approved legal documents. Digests come from the exact published files;
# --verify-remote downloads each URL and refuses a digest mismatch before sending.
node scripts/operator-admin.mjs legal \
  --terms-version 2026.09 --terms-url https://aidr.example/legal/terms --terms-file ./terms.html \
  --privacy-version 2026.09 --privacy-url https://aidr.example/legal/privacy --privacy-file ./privacy.html \
  --approval-reference LEGAL-2026-09 --verify-remote

# Grant a license (the owner is inferred when the tenant has exactly one owner).
node scripts/operator-admin.mjs grant --tenant <tenant-uuid> --plan business --seats 30 \
  --expires-at 2027-09-30T23:59:59Z --reference PO-2026-001 [--owner <owner-uuid>]

node scripts/operator-admin.mjs revoke --tenant <tenant-uuid> --reason "contract ended"
node scripts/operator-admin.mjs tenants --limit 100 [--after <tenant-uuid>] [--all]
node scripts/operator-admin.mjs usage --tenant <tenant-uuid>

# Signed licenses (docs/operations/licensing.md): list what workspace admins
# staged, then apply a vendor-signed file. The CLI verifies the file against
# deploy/onprem/license-public-keys.json (or --public-keys) before sending it;
# the function verifies it again against AIDR_LICENSE_PUBLIC_KEYS_B64.
node scripts/operator-admin.mjs license-imports
node scripts/operator-admin.mjs license-apply --tenant <tenant-uuid> \
  --license-file aidr-license.json [--import <import-uuid>]
```

Add `--dry-run` to any command to print the request body without sending it.
The exit code is `0` on success, `1` when the service refuses or fails (its
JSON error is printed), and `2` for a usage or local validation error.

### Plans

`plan_id` must be an active id in `public.plans` when the commercial catalog
table exists. Until then, it must be one of `free`, `team`, `business` or
`enterprise`. The plan is stored in `tenant_admissions.plan_id`, and
`list_tenants` and `tenant_usage` report it. Seats and expiry come from the
contract, not from the plan.

### Error codes

| HTTP | `error` | Meaning |
|------|---------|---------|
| 400 | `invalid_action`, `invalid_mode`, `invalid_legal_documents`, `invalid_tenant`, `invalid_plan`, `invalid_seats`, `invalid_expiry`, `invalid_reference`, `invalid_owner`, `invalid_reason`, `invalid_page`, `invalid_grant`, `owner_required` | Input rejected; nothing changed. |
| 401 | `missing_access_token`, `invalid_access_token`, `session_revoked` | Sign in again. |
| 403 | `forbidden` | No active platform-operator row. |
| 403 | `mfa_required` | The session is not AAL2. |
| 403 | `admission_operator_required` | No unexpired `admission_operators` row for this tenant, or the operator is a member of it. |
| 404 | `tenant_not_found` | Unknown tenant id. |
| 409 | `admission_mode_immutable` | The mode is already fixed to a different value. |
| 409 | `admission_mode_not_licensed` | Licensed grants need `cloud` or `onprem` mode. |
| 409 | `owner_not_eligible`, `tenant_closed` | The tenant is not active, or the owner is not a current owner. |
| 400 | `invalid_license`, `invalid_import` | `apply_license` without a license document object, or a malformed import id. |
| 422 | `license_rejected` (`reason`: `bad_signature`, `unknown_key`, `revoked_key`, `key_window`, `expired`, `not_yet_valid`, `customer_mismatch`, …) | Signature verification refused the license; nothing changed. |
| 409 | `license_import_not_pending`, `license_import_mismatch`, `license_bound_to_other_tenant` | The staged import was already handled or differs, or the license id already admits another tenant. |
| 503 | `license_registry_unavailable`, `license_registry_empty`, `license_registry_invalid` | `AIDR_LICENSE_PUBLIC_KEYS_B64` is unset, holds no keys or is malformed. |
| 503 | `authorization_unavailable`, `assurance_unavailable`, `operator_action_unavailable` | A dependency failed, or the RPC returned an unexpected result. Retry after checking the logs. |

## Auth hardening in `supabase/config.toml`

- `[auth.email] enable_confirmations = true`: email sign-ups must confirm
  their address. Local confirmation mail goes to Inbucket at
  `http://localhost:54324`, so local development needs no SMTP provider.
- `[auth.captcha]`: Cloudflare Turnstile. It is off by default, so local
  development works without a Turnstile account. To turn it on for a deployed
  project, set `SUPABASE_AUTH_CAPTCHA_ENABLED=true` and
  `SUPABASE_AUTH_CAPTCHA_SECRET=<secret>` when you run `supabase config push`.
  Or enable Bot Protection with the same secret in the hosted project's Auth
  settings. Then build the dashboard with the matching `VITE_TURNSTILE_SITE_KEY`.
  Once the captcha is on, Auth rejects any request that has no valid
  `captchaToken`.

`supabase/functions/__tests__/config-contract.test.ts` enforces these settings.

## Verification

- `pnpm exec vitest run supabase/functions/__tests__/operator-admin-contract.test.ts`
  runs the handler contract tests: authorization order, validation, RPC arguments,
  error mapping, and drifted-result rejection.
- `node --test scripts/operator-admin.test.mjs` runs the CLI tests.
- `AIDR_POSTGRES_DOCKER_CONTAINER=<container> node --test scripts/operator-admin-postgres.test.mjs`
  runs the SQL wrapper regression against a disposable database with all
  migrations applied. It rolls back every change.
