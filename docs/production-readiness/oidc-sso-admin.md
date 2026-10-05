# OIDC single sign-on (Microsoft Entra ID, Okta, generic) — design and admin guide

Tenant OIDC SSO sits next to SAML. It is optional per tenant and changes nothing for a tenant that never configures it: `tenant_identity_policies.required_oidc_provider_id` is `NULL` by default, exactly like `required_saml_provider_id`.

**Acceptance boundary.** The local suites below prove the protocol, tenant isolation and database contracts. They are not live Entra or Okta acceptance: the 24 September 2026 scope decision in [scim-directory-admin.md](scim-directory-admin.md) still applies. A customer that requires SSO continuity needs the two-provider cutover and rollback evidence collected against a deployed release candidate (see [Owner acceptance checklist](#owner-acceptance-checklist)).

## What it does

```
Browser                    oidc-sso Edge function                 IdP (Entra / Okta / generic)
  | start(email|provider, sha256(binding)) |                                 |
  |--------------------------------------->| state, nonce, PKCE verifier      |
  |<--- authorization URL (S256, state) ---| (only hashes + verifier stored)  |
  |----------------- redirect --------------------------------------------->|
  |<---------------- /auth/oidc/callback?code&state ------------------------|
  | callback(code, state, binding secret)  |                                  |
  |--------------------------------------->| consume state (single use)       |
  |                                        | binding secret == hash? (CSRF)   |
  |                                        |-- code + PKCE verifier ---------->| token endpoint
  |                                        |<-- id_token ---------------------|
  |                                        | verify signature (JWKS), iss, aud, azp, exp, nbf,
  |                                        | iat, nonce; email domain verified for THIS tenant;
  |                                        | groups claim (optional); SCIM-provisioned subject
  |<-- one-time magic-link hash + ticket --|
  | verifyOtp(hash) -> Supabase session    |
  | bind_session(ticket) with that session |  oidc_sso_sessions(session_id, provider, tenant)
```

Supabase Auth has no generic enterprise OIDC provider, so after verifying the ID token the function mints a one-time Supabase magic-link session for the provider-qualified identity. That session carries no `sso/saml` AMR, so proof of SSO is a **server-side binding keyed by the JWT `session_id`**. When a tenant enforces OIDC, both the service-role barrier (`checkIdentityBarrier`) and the restrictive RLS predicate (`tenant_identity_access_allowed`) require a live, unrevoked, unexpired binding for the enforced provider. A password, email-link, SAML or un-bound session is refused.

### Security properties and where they are enforced

| Property | Enforcement | Test |
|---|---|---|
| Authorization code flow with PKCE S256 | `oidc.ts` `buildAuthorizationUrl`, `pkceChallenge`; discovery without S256 is rejected | `oidc-sso-protocol.test.ts`, handler test asserts the token request's verifier matches the URL's challenge |
| `state` is single-use and hashed | `oidc_auth_requests` + one atomic `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now()` | replayed / expired / forged state tests |
| `nonce` binding | only `sha256(nonce)` stored; compared in constant time with the token's nonce | nonce mismatch / missing tests |
| Login CSRF | per-tab binding secret, only its hash is registered at `start` | wrong-browser test |
| Signature verification | WebCrypto against the configured JWKS; keys come only from the provider's `jwks_uri`; `jku`/`jwk`/`x5u` are ignored; `crit` rejected | tamper, forged, rogue-key, header-injection tests |
| Algorithm allow-list | exact match against the provider's list (`RS256`, `PS256`, `ES256` only); `none`, any case, and every HMAC algorithm refused | `alg=none`, HS256 key-confusion, allow-list tests |
| Claims | `iss` exact, `aud` contains client id, `azp` when several audiences, `exp`/`nbf`/`iat` with clock skew (default 60 s, capped 120 s), maximum token age, `sub` present | claim tests |
| JWKS cache and rotation | per-isolate cache, 10 min TTL, one refetch on unknown `kid` rate-limited to 30 s, stale keys usable for known kids up to 1 h, bounded size | rotation, amplification, outage tests |
| SSRF-safe discovery / JWKS / token fetch | `_shared/safe-fetch.ts`: https only, no credentials, port 443, DNS names only, every A/AAAA answer must be public (port of the core MCP guard in `_shared/egress-guard.ts`, parity-tested), redirects refused, bounded size/time, JSON only | `oidc-sso-protocol.test.ts` safe-fetch + parity suites |
| Tenant-bound domain verification | asserted email domain must be a DNS-TXT-verified domain of the tenant whose provider issued the token; a verified domain belongs to one tenant | cross-tenant tests, `oidc_tenant_domains_verified_unique` |
| Identity = provider-qualified subject | `oidc_identities (provider_id, subject)`; **email never links accounts**; new users get an unroutable synthetic Auth address | identity tests, SQL contract |
| Roles consistent with SAML/SCIM | membership and roles still come from SCIM; group claims use the same exact-ID `scim_group_role_mappings`, highest of admin/member/viewer, never owner, Entra overage is "unevaluable", never "empty" | group-mapping tests |
| Enforce-SSO per tenant | `oidc_set_enforcement` (owner, AAL2, reason, change reference, audit) | handler + SQL contract |
| Audit | `admin_audit_logs` events listed below; a login that cannot be audited is denied | audit-precondition test |

### Audit events

`identity.oidc.login_succeeded`, `identity.oidc.login_failed` (internal reason in `detail`), `identity.oidc.session_bound`, `identity.oidc.identity_linked`, `identity.oidc.provider_updated`, `identity.oidc.discovery_refreshed`, `identity.oidc.domain_added`, `identity.oidc.domain_verified`, `identity.oidc.domain_removed`, `identity.oidc.enforcement_enabled`, `identity.oidc.enforcement_disabled`, `identity.oidc.break_glass_enforcement_suspended`.

## Enforcement, owners and break-glass

Enforcement is the dangerous step, so it is gated in SQL (`oidc_set_enforcement`), not only in the UI:

1. The actor is an active **owner** at **AAL2** with a **live OIDC session for this provider** (so they provably are not locking themselves out).
2. **Every active owner** has a linked identity for the provider and there are **at least two** of them.
3. No SCIM user is bound to an Auth account that lacks the matching `(provider, subject)` identity (the same stop the SAML policy guard applies to email-bound users).
4. A reason (12+ characters) and a change reference are recorded; SAML and OIDC enforcement are mutually exclusive.

Owners are not SCIM-managed (SCIM cannot grant `owner`). To migrate an existing owner or an email-bound SCIM user, the signed-in user runs **Link my account** (`start` with `mode: "link"`): the IdP login binds the subject to **their existing Auth account**, so no ownership transfer is needed. A link is refused if the subject already belongs to another account, if the user already has another subject for the provider, or if their SCIM external id differs from the subject.

**Break-glass.** SAML has no bypass (see [scim-directory-admin.md](scim-directory-admin.md)). For OIDC the existing identity-recovery design is reused with the same single-use, 160-bit, hashed owner recovery codes (`rotate_recovery_codes`, owner + AAL2, only while `break_glass_enabled`): spending one at `/auth/sso-recovery` **suspends OIDC enforcement for that tenant**, records `identity.oidc.break_glass_enforcement_suspended`, grants no session and is rate-limited per email (5 per 10 minutes). The owner then signs in with a password (and MFA when required), repairs the provider, and re-enables enforcement through the normal gated path. The power of a code over the tenant therefore equals its existing power over that owner's account. Enable break-glass **before** enforcing; the UI warns when it is off.

Not implemented (do not claim): dual approval by two distinct approvers (the dual-verified-owner precondition above is the substitute), RP-initiated or back-channel logout, and immediate revocation on IdP-side disablement. IdP disablement takes effect when SCIM deactivates the user (membership removed) or when the SSO session expires (`session_max_seconds`, default 12 h, max 24 h, enforced independently of Supabase refresh tokens).

## Deployment configuration

| Where | Setting |
|---|---|
| Supabase Edge secrets | `AIDR_OIDC_CLIENT_SECRET_<REF>` — the client secret, where `<REF>` (`A-Z0-9_`, max 40) is the "client secret reference" you type in the dashboard. Never stored in the database. Public clients (PKCE only) need none. |
| Supabase Edge secrets | `AIDR_DASHBOARD_URL` (already required) — the redirect URI is `<dashboard origin>/auth/oidc/callback`. `AIDR_ALLOWED_ORIGINS` must include the dashboard origin. |
| Dashboard runtime | `AIDR_OIDC_SSO=true` shows the "work email SSO" form on the sign-in page (Node server and Cloudflare worker). Off by default. |
| Supabase Auth | The **Email** provider must be enabled (the function creates one-time magic-link sessions; it never sends mail). |
| Migration | `20261005000001_oidc_sso.sql` (tables, enforcement column, RLS predicate, RPCs). Roll out the Edge function and dashboard together. |

The `oidc-sso` Edge function is `verify_jwt = false` because `start`, `callback` and `break_glass_suspend_enforcement` are public by design; every other action verifies the access token and runs the shared identity barrier. `scripts/verify-endpoint-auth-matrix.mjs` now enforces this split: a mixed route must declare each public action with its mechanism and mark exactly those handler cases `// public-action: <name>`; an undeclared public case, a stale declaration, or a handler with no authenticated case fails the gate.

## Admin setup — Microsoft Entra ID

Prerequisites: a global or application administrator in the customer directory; an AIDR tenant **owner**; the dashboard URL.

1. **Register the application.** Entra admin center → *Identity → Applications → App registrations → New registration*. Name it "Singularity AIDR". Supported account types: **single tenant**. Redirect URI: platform **Web**, `https://<dashboard>/auth/oidc/callback`.
2. **Record identifiers.** Copy the *Application (client) ID* and *Directory (tenant) ID*. The issuer is `https://login.microsoftonline.com/<directory-tenant-id>/v2.0`. AIDR rejects `common`, `organizations` and `consumers` because they have no fixed issuer.
3. **Create a client secret.** *Certificates & secrets → New client secret*. Copy the value now. Store it: `supabase secrets set AIDR_OIDC_CLIENT_SECRET_CONTOSO=<value>` (pick your own `<REF>`). Calendar its expiry; rotating means setting the new secret value, then deleting the old Entra secret.
4. **Claims.** *Token configuration → Add optional claim → ID → `email`*. If you want group claims: *Add groups claim → Security groups → Group ID*, and prefer "Groups assigned to the application" to stay below Entra's group-overage limit (when exceeded Entra omits the list; AIDR treats that as "cannot evaluate" and, with *Require a mapped group*, denies).
5. **Assign users.** *Enterprise applications → Singularity AIDR → Properties → Assignment required = Yes*, then *Users and groups*.
6. **Provision with SCIM** (see [scim-directory-admin.md](scim-directory-admin.md)). The SCIM `externalId` must equal the OIDC subject. Use subject claim **`oid`** (the AIDR Entra default) and map the SCIM `externalId` attribute to **objectId** (the gallery default is often `mailNickname`, which will not match).
7. **Configure AIDR.** Dashboard → *Single sign-on*: Provider type *Microsoft Entra ID*, the issuer, client ID, secret reference, then **Save and validate** (AIDR fetches and validates the discovery document through the SSRF guard). Add your email domain(s), publish the shown TXT record `_aidr-sso.<domain>` = `aidr-sso-verification=<token>`, and **Verify**.
8. **Test before enforcing.** Enable sign-in and sign in from the login page with a provisioned test user while enforcement is off. A user who is not yet provisioned signs in but sees no tenant data.
9. **Link owners, then enforce.** Each owner clicks **Link my account**; once every active owner is linked (two or more), enter a reason and change reference and **Enforce single sign-on**. Keep break-glass enabled and recovery codes issued.

## Admin setup — Okta

1. **Create the app.** Okta Admin Console → *Applications → Applications → Create App Integration* → **OIDC - OpenID Connect** → **Web Application**.
2. **Settings.** Grant type **Authorization Code** only. Sign-in redirect URI `https://<dashboard>/auth/oidc/callback`. Under client credentials use *Client authentication = Client secret* and enable **Require PKCE as additional verification**. Assignments: limit to the groups that should reach AIDR.
3. **Issuer.** Use the authorization server that issues the ID token: for the custom `default` server, `https://<org>.okta.com/oauth2/default` (*Security → API → Authorization Servers*), or the org server `https://<org>.okta.com`. The issuer must match the `issuer` in that server's discovery document exactly (no trailing slash differences).
4. **Secret.** Copy the client ID and secret; store the secret as `AIDR_OIDC_CLIENT_SECRET_<REF>` as above.
5. **Subject.** Okta's `sub` is the user's Okta ID. Verify (by decoding a test ID token) that the SCIM `externalId` Okta sends for the same user is exactly that value; if it is not, adjust the SCIM attribute mapping or provisioning will never bind. Use subject claim `sub`.
6. **Groups (optional).** Add a `groups` claim to the ID token (custom authorization server: *Claims → Add claim*, type ID token, value type Groups). Okta emits group **names**, whereas AIDR maps exact SCIM `Group.externalId` values. Unless those are identical, leave *Group requirement* on **Ignore groups**: SCIM remains the authority and the group claim is then only recorded in the audit event.
7. **Configure AIDR, verify the domain, test, link owners, enforce** exactly as steps 7–9 above (provider type *Okta*).

## Operations and troubleshooting

* Provider edits are blocked while enforcement is on (disable enforcement first); **refresh discovery** is allowed so a changed `jwks_uri` can be picked up.
* `sso_login_failed` reasons returned to the browser: `request_invalid` (expired/replayed state), `binding_mismatch`, `token_exchange_failed`, `token_invalid`, `domain_not_verified`, `email_claim_missing`, `not_provisioned`, `group_not_mapped`, `groups_overage`, `identity_conflict`, `provider_unavailable`, `session_unavailable`. The precise cause (for example `id_token_nonce_mismatch`, `id_token_unknown_kid`, `client_secret_not_configured`) is in the `identity.oidc.login_failed` audit detail only.
* `identity_conflict` after enforcement usually means a SCIM user was previously bound to an email-created Auth account. Have that user run **Link my account** (while signed in) before enforcing, or provision a fresh user.
* `not_provisioned`: the subject has no active SCIM user with an equal `externalId` in this tenant.

## Residual risks

* **DNS rebinding.** The Edge runtime's `fetch` resolves names again, so the guard validates every DNS answer but cannot pin the connection the way `packages/core` MCP transport does. Compensating controls: https and port 443 only, no redirects, DNS names only, the provider is owner-configured at AAL2, and the Supabase Edge network has no route to the project's internal services.
* **No IdP-initiated revocation.** See above; sessions end by SCIM deactivation or `session_max_seconds`.
* **Per-isolate JWKS cache.** Each warm isolate fetches independently; the fetch is rate-limited per URI per isolate.
* **Unauthenticated write bounds.** `start` is limited to 600 per provider per minute and `callback` to 1,200 per minute deployment-wide. These cap database writes; they are not a security control (state is 256-bit and single-use) and, like any fixed bound, could be used to starve sign-in under deliberate flooding. Put the Edge function behind the platform/WAF rate limiting for volumetric abuse.
* **Break-glass power.** Possession of an owner's unexpired recovery code can suspend enforcement. Treat codes like the password-recovery codes they are.

## Owner acceptance checklist

Run against the deployed release candidate with isolated test tenants, one per IdP, and keep redacted receipts:

- [ ] Entra and Okta apps registered as above; secrets set; discovery saved and validated.
- [ ] Domain TXT verified; sign-in works for a provisioned user with enforcement off and shows no tenant data for an unprovisioned one.
- [ ] Wrong-redirect-URI, expired-state and second-browser callbacks are refused.
- [ ] Two owners linked; enforcement enabled with reason and change reference; a password session, an email-link session and a SAML session are each refused (`sso_required`).
- [ ] SCIM deactivation removes access; an expired SSO session (`session_max_seconds`) is refused.
- [ ] Break-glass: spend a recovery code at `/auth/sso-recovery`, confirm enforcement is suspended and audited, sign in by password, repair, re-enforce.
- [ ] Audit events above appear in the audit export.

## Local verification

```bash
pnpm test -- supabase/functions/__tests__/oidc-sso-protocol.test.ts supabase/functions/__tests__/oidc-sso-handler.test.ts supabase/functions/__tests__/identity-barrier-oidc.test.ts
pnpm test -- packages/dashboard/src/__tests__/oidc-sso-client.test.tsx
node --test scripts/oidc-sso-policy.test.mjs scripts/verify-endpoint-auth-matrix.test.mjs
pnpm supabase:check && node scripts/check-supabase-edge-contracts.mjs && node scripts/verify-endpoint-auth-matrix.mjs
```
