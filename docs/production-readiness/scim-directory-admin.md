# SCIM directory setup and owner operations

`scim-admin` is the supported control-plane surface for bootstrapping an inbound SCIM connection. It requires a current Supabase user session and an active tenant `owner` membership; `admin`, `member`, and `viewer` cannot issue provisioning credentials or change group-role mappings. The shared identity revocation/MFA barrier is checked before tenant-owned SCIM data is read or changed.

This function does not connect to Microsoft Graph or read Azure token claims. Entra (or another SCIM provider) provisions users and groups into the tenant-scoped SCIM API at `/functions/v1/scim/v2`; AIDR reconciles memberships from the exact immutable `Group.externalId` value and a preconfigured role mapping. Group display names and user metadata never grant roles. Supported mapped roles are `admin`, `member`, and `viewer`; SCIM cannot grant `owner`.

SCIM provisioning alone is not SSO enforcement. By default, `required_saml_provider_id` is `NULL` and existing email Auth provisioning is unchanged. When a tenant explicitly requires one provider, SCIM users remain unbound until a verified SAML sign-in supplies that provider and a matching, opaque `NameID`/SCIM `User.externalId`; same-email accounts are never linked. The tenant RLS and Edge barriers deny email-link or password sessions for that tenant. [Supabase SAML creates a separate Auth UUID even for the same email](https://supabase.com/docs/guides/auth/enterprise-sso/auth-sso-saml#user-accounts-and-identities).

OIDC is an alternative sign-in method for the same SCIM identities. A tenant enforces **either** SAML **or** OIDC (`required_saml_provider_id` / `required_oidc_provider_id`; a database check forbids both), and `scim` treats both the same way: users stay unbound until a verified provider-qualified subject signs in. The OIDC subject (`sub` or Entra `oid`) must equal the SCIM `User.externalId`, and `groups` claims use the same exact-ID group-role mappings. See [oidc-sso-admin.md](oidc-sso-admin.md) for the design, the Entra/Okta setup guides and the break-glass procedure that SAML lacks.

## Entra and Okta SAML cutover

Product scope decision (24 September 2026): Entra and Okta test tenants/applications are not available yet, so their live SAML/SCIM acceptance is roadmap work, not an accepted sales capability. Keep `required_saml_provider_id` unset and exclude enterprise SSO continuity from any current production offer or demo claim. This does not waive the identity/SSO gate for a customer that requires it; that sale remains blocked until the two-provider cutover and rollback evidence below exists.

Use a separate provider UUID and isolated test tenant for each IdP acceptance. Supabase-hosted SAML needs Pro or higher; the Free pilot cannot prove this path. Configure each IdP to send a persistent, non-email `NameID` **exactly equal** to its SCIM `User.externalId`, plus a separate email assertion. Confirm the deployed Auth identity stores that subject in `auth.identities.provider_id` with `provider = 'sso:<provider UUID>'`. Do not use email, display name, or user-editable metadata for binding. A deployment can show multiple SAML provider choices using `AIDR_SAML_PROVIDERS` (JSON array of `{ "providerId": "<UUID>", "label": "Microsoft Entra ID" }` objects) so different tenants can use Entra or Okta without redeploying. However, one AIDR tenant still accepts exactly one required provider UUID; the second IdP cannot be treated as an alternate login for that same tenant. Supporting two IdPs for one tenant requires a provider-qualified SCIM subject/membership model and is not implemented.

Before enabling the tenant policy, issue the SCIM token and exact group-role mappings with the current owner and record the provider UUID. Sync users/groups, then verify SAML login and the exact provider-qualified subject in an isolated tenant while the policy remains off. Once an approved policy later requires that provider, the first verified dashboard bootstrap binds only the matching SCIM subject and creates its mapped membership; same-email and other-provider sessions do not inherit access. SCIM cannot grant `owner`, so owner continuity must be completed separately. Never turn on the policy merely to test whether login works: a wrong provider or missing owner path locks out the tenant by design.

An audited application operation for enabling and disabling `required_saml_provider_id` now exists (migration `20261005230000_saml_policy_administration.sql`, `identity-security` actions below, dashboard Directory sync page). It requires **two distinct current owners at AAL2**, reason/change reference, provider-qualified SAML sessions and one exact, short-lived transition. The local implementation does not change the live-acceptance stop gate above: leave the policy `NULL` for an unaccepted customer environment.

Before activation, **every active owner** must have the target provider's exact, opaque Auth identity, with at least two owners. SAML Auth UUIDs are separate from same-email password accounts. While enforcement is off, use the existing audited AAL2 owner-role operations to establish those manual SAML owners; a SCIM provisioning record or invitation email does not establish owner continuity. Keep owners outside SCIM-managed membership. Previously email-bound SCIM accounts block activation rather than being silently relinked.

### Two-owner SAML policy change

Apply the migration before deploying the updated Edge function/dashboard. Provider registration remains a deployment operator responsibility through Supabase Auth; this API does not register an IdP. Activation checks the registered `auth.sso_providers`/`auth.saml_providers` entry and refuses a disabled provider. In the pinned [GoTrue provider model](https://github.com/supabase/auth/blob/v2.196.0/internal/models/sso.go), a `NULL` disabled flag means enabled. The provider UUID must also match the authenticated SAML session, and provider-qualified owner identity rows must already exist.

1. Sign in as the first manual owner through the target SAML provider and complete MFA. On the Directory sync page, request activation with the exact provider UUID, reason and change reference. The backend derives user/session/provider/AAL proof from the verified access token; body-supplied proof or approver identity is rejected.
2. Share the returned request UUID with the second owner through the approved change process. They sign in through the same provider, complete MFA, load that exact request and review tenant, old/new provider, reason, change reference and deadline before approving.
3. The request expires **five minutes after creation, or at the requester's access-token expiry if earlier**. Approval rechecks both current owner memberships, both current Auth sessions/AAL2, revocation barriers, the target identities and SCIM compatibility after lock waits. A stale policy, expired/revoked session, self-approval or consumed request is refused. Approval, policy change and the `identity.saml.policy_change_applied` audit event commit together. A failed transaction leaves the policy/request unconsumed. Concurrent owner changes return `saml_policy_policy_conflict` for retry instead of waiting while holding membership rows; once SAML is enforced, unqualified owner insertion/promotion is refused. This path uses the deployment's normal READ COMMITTED transaction isolation.
4. For normal disable/rollback, request `new_provider_id: null` and repeat the second-owner review. Both owners must still have valid current-provider SAML sessions at AAL2. The old provider is captured from the current database policy; callers cannot supply or alter it.
5. Only `NULL → provider` and `provider → NULL` are supported. Direct provider A→B changes are refused. Switching providers requires a separately reviewed disable, new owner/SCIM compatibility preparation and new activation. OIDC enforcement must be off; the existing SAML/OIDC mutual exclusion remains.

All requests use `POST /functions/v1/identity-security` with the current owner access token as `Authorization: Bearer …`; a conflicting tenant header is rejected. Exact JSON bodies:

```json
{
  "action": "request_saml_policy_change",
  "tenant_id": "<tenant UUID>",
  "new_provider_id": "<registered SAML provider UUID>",
  "reason": "<12–500 character approved reason>",
  "change_ref": "<1–200 character change reference>"
}
```

```json
{
  "action": "get_saml_policy_change",
  "tenant_id": "<tenant UUID>",
  "request_id": "<request UUID>"
}
```

Use the second body with `action: "approve_saml_policy_change"` to approve as the distinct second owner. Successful responses are `{ "ok": true, "request": { ... } }` with request/tenant IDs, requester, old/new provider, reason, change reference, creation/deadline and approver/application timestamps. They never return bearer tokens or stored session proof. `identity-security/status` exposes the current required SAML/OIDC provider IDs. Up to ten unexpired pending requests per tenant are allowed; expired requests remain security-audit evidence. The proof ledger is linked to its immutable request audit row and is erased through the existing legal-hold-aware audit offboarding phase, rather than an independent cleanup path.

**Outage recovery remains OPEN.** Password recovery/break-glass still does not bypass required SAML. If the IdP is unavailable and the required SAML sessions have expired, the normal disable operation deliberately refuses access; this change supplies no emergency bypass. A separately reviewed recovery and session-revocation procedure, and deployed Entra/Okta cutover/rollback evidence, are still required before offering SSO continuity. Normal disable does not delete membership or revoke all existing sessions, and IdP-side owner disablement is not an immediate AIDR-session revocation guarantee.

**Local verification (6 October 2026).** The focused identity tests passed 129 cases; the dashboard SAML panel's focused tests passed 31 cases and its TypeScript check passed. `node --test scripts/saml-administration-postgres.test.mjs` passed 13 tests against all 135 canonical migrations through `20261005233000_fleet_response_effective_state.sql` in its own disposable, network-disabled PostgreSQL container. It verifies real owner/Auth-delete/revocation/expiry races, distinct approvals, policy CAS/replay denial, audit rollback, hold-protected proof and actual offboarding cascade with neighbor isolation. The Auth deletion deadlock was reproduced before the parent-first lock fix and passed afterward. The native fixture supplies GoTrue tables, not a running Auth server; these checks are not live Entra/Okta or production acceptance.

Provider activation rejects previously email-bound SCIM users. Inventory them and stop; do not silently relink or delete accounts. Use a separately reviewed migration/owner-transfer plan or a fresh test tenant, then rerun same-email, wrong-provider, unmapped-NameID, manual-membership, deactivation, and token-rotation tests. The local PostgreSQL regression is not live Entra/Okta acceptance. Keep the SSO policy off and do not claim SAML+SCIM is sale-ready until both IdPs pass on the signed release candidate with redacted receipts.

## Provisioning credentials

If Auth account creation succeeds but the following SCIM bind fails transiently, retries recover only an account carrying server-owned markers for that exact tenant and SCIM user. Email alone is never sufficient. Before rollout, inventory any older `aidr_scim_provisioned` Auth accounts that have no matching `scim_users.auth_user_id`; review those individually and do not attach them by email.

Send owner-management requests to `/functions/v1/scim-admin` with the owner’s Supabase access token as `Authorization: Bearer …`. For writes, include `tenant_id` in the JSON body. A conflicting `X-AIDR-Tenant-ID` header is rejected. For the metadata listing, use `GET` with `X-AIDR-Tenant-ID: <tenant UUID>`.

Create a credential:

```json
{
  "action": "create_token",
  "tenant_id": "<tenant UUID>",
  "label": "Entra production",
  "directory_id": "entra-production",
  "expires_at": "<optional RFC 3339 timestamp, within 365 days>"
}
```

`directory_id` is required and names the identity directory the credential provisions from (1–128 characters: letters, digits, `.`, `_`, `:`, `-`, starting with a letter or digit). It is stored on the credential, cannot be changed, and is inherited by rotations. A legacy credential issued before this field existed has no directory; bind it by passing `directory_id` on its `rotate_token`.

The `201` response contains `scim_token` once and its `expires_at`. Copy the secret directly into the approved secret manager and configure the SCIM provider with that value; do not save it in project files, evidence, logs, or shell history. The database stores only its SHA-256 hash. Omitting `expires_at` gives a new credential a 90-day lifetime; an explicit expiry must be in the future and within 365 days. Explicit `null` is rejected. Record the expiry and schedule rotation before it; an expired token cannot provision users.

For overlap rotation, submit `action: "rotate_token"` with the active old `token_id`, a new label, and optional expiry. The new token has the same 90-day default and 365-day maximum. The old token remains valid so the provider can be changed without downtime. Verify provisioning with the new secret, then explicitly revoke the old `token_id` using `action: "revoke_token"`. Revocation is tenant-scoped and permanent. There is no automatic overlap cutoff, so the operator must complete this last step.

Pre-existing credentials with no expiry are **not** silently disabled by this change. Inventory them through `GET`, rotate each through the owner action, verify the provider on the replacement, and revoke each old ID. Do not treat an indefinite legacy token as production-accepted until that rotation is complete.

`GET` returns token IDs, labels, rotation links, timestamps and revocation state, but never the raw token or stored hash. Results are bounded to 100 tokens and 500 mappings per request. Use each returned keyset cursor independently to fetch later pages; a `null` next cursor means that list is complete:

```http
GET /functions/v1/scim-admin
X-AIDR-Tenant-ID: <tenant UUID>
```

For the next request, pass `next_token_cursor.created_at` as `token_after_created_at`, `next_token_cursor.id` as `token_after_id`, and/or `next_mapping_cursor` as `mapping_after_external_group_id`. Omit a cursor to restart that list from its beginning. Token pages use `(created_at DESC, id ASC)` and mapping pages use `external_group_id ASC`, so concurrent additions before a cursor do not shift rows into the next page.

## Group-role mapping

After SCIM has provisioned the provider’s group, bind its exact immutable external ID to one allowed role:

```json
{
  "action": "set_group_mapping",
  "tenant_id": "<tenant UUID>",
  "external_group_id": "<exact SCIM Group.externalId>",
  "role": "viewer"
}
```

IDs are preserved byte-for-byte after validation: whitespace, control characters, display-name substitutions, and unsupported roles are rejected. Updating a mapping replaces the old immutable row transactionally. If that would take over a manual team membership, the operation fails with `409 mapping_conflicts_with_manual_membership`; resolve the existing manual membership explicitly first. Removing a mapping uses `action: "remove_group_mapping"` with the same tenant and exact ID. Existing AIDR-managed access is then reconciled immediately; any remaining mapped group can still grant the user its own role.

All successful token operations and mapping changes are recorded in `admin_audit_logs` with the tenant and actor. Mapping changes that reconcile existing groups and their audit events are in the same database transaction.

## Directory-authoritative membership (TEN-04)

By default (off) any tenant membership grants access: manual invitations, owner-added members, and memberships provisioned through any directory's credential. An owner can make one directory authoritative (`20261007000000_scim_directory_authoritative.sql`). While on:

- A membership grants access only when an active SCIM-managed membership from that directory backs it **with the same role**, or the member is a designated break-glass owner. SCIM never grants owner, so every owner is a manual account.
- This is enforced on write by deferred constraint triggers on `tenant_members`, `scim_managed_memberships`, `scim_users` and the break-glass table, so invitations, manual inserts, role escalations, and directory users deactivated without reconciliation are refused at commit (`directory_authority_membership_required`). Every reader that consults `tenant_members` (RLS helpers, definer RPCs, service-role Edge Functions) therefore observes it; `app.is_tenant_member*` re-check it on read.
- Only the configured directory's credentials resolve, and no credential for another directory can be issued.
- Owners cannot be added, removed or demoted. Turn the mode off, make the owner change, then turn it on again.

Enable (requires an AAL2 owner session; audited as `scim.directory_authority.enabled`):

```json
{
  "action": "enable_directory_authority",
  "tenant_id": "<tenant UUID>",
  "directory_id": "entra-production",
  "break_glass_user_ids": ["<every active owner, one or two>"],
  "adopt_existing_memberships": false,
  "remove_unmanaged_members": false
}
```

The database refuses unless: the tenant is an active team workspace not being offboarded; the directory holds an active credential and no other directory (including an unbound legacy credential) does; `break_glass_user_ids` equals the set of active owners (one or two, live, not SCIM-managed); and at least one owner or admin keeps access. `adopt_existing_memberships` asserts that existing SCIM-managed memberships came from this directory and is refused if a credential for any other known directory ever existed. Members the directory does not provision cause `409 directory_authority_unmanaged_members` with a count and no change, unless `remove_unmanaged_members` is `true`; each removal then runs the normal audited removal path (API keys, enrollments and delegations revoked). Owners are never removed by enabling.

Break-glass: the designated owners keep access through a directory outage or mass deprovisioning, and the last one cannot be removed, demoted or deleted while the mode is on. If the tenant also enforces SAML, the existing dual-operator SAML outage recovery still applies to them. Disable with `{"action": "disable_directory_authority", "tenant_id": "<tenant UUID>"}` (AAL2 owner; audited as `scim.directory_authority.disabled`). Disabling only relaxes the rule; it grants nothing by itself. The setting is erased by tenant offboarding (phase 57, `identity_membership`).

## Acceptance boundary

Local contract tests cover owner-only access, tenant scoping, MFA/session barriers, exact-ID and role validation, one-time secret handling, hash-only persistence, bounded token expiry, token overlap/revocation, mapping reconciliation conflicts, malformed member references, and resource discovery URLs. They do not prove a live Entra or Okta tenant is configured. Production acceptance still requires an operator to deploy the migrations/function, configure the provider's provisioning application and secret, verify user/group create-update-deactivate and membership removal against the deployed candidate, test expiry and immediate revocation with the provider, rotate legacy indefinite credentials, and retain redacted evidence bound to that candidate.
