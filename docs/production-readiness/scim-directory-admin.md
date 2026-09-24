# SCIM directory setup and owner operations

`scim-admin` is the supported control-plane surface for bootstrapping an inbound SCIM connection. It requires a current Supabase user session and an active tenant `owner` membership; `admin`, `member`, and `viewer` cannot issue provisioning credentials or change group-role mappings. The shared identity revocation/MFA barrier is checked before tenant-owned SCIM data is read or changed.

This function does not connect to Microsoft Graph or read Azure token claims. Entra (or another SCIM provider) provisions users and groups into the tenant-scoped SCIM API at `/functions/v1/scim/v2`; AIDR reconciles memberships from the exact immutable `Group.externalId` value and a preconfigured role mapping. Group display names and user metadata never grant roles. Supported mapped roles are `admin`, `member`, and `viewer`; SCIM cannot grant `owner`.

SCIM provisioning alone is not SSO enforcement. By default, `required_saml_provider_id` is `NULL` and existing email Auth provisioning is unchanged. When a tenant explicitly requires one provider, SCIM users remain unbound until a verified SAML sign-in supplies that provider and a matching, opaque `NameID`/SCIM `User.externalId`; same-email accounts are never linked. The tenant RLS and Edge barriers deny email-link or password sessions for that tenant. [Supabase SAML creates a separate Auth UUID even for the same email](https://supabase.com/docs/guides/auth/enterprise-sso/auth-sso-saml#user-accounts-and-identities).

## Entra and Okta SAML cutover

Product scope decision (24 September 2026): Entra and Okta test tenants/applications are not available yet, so their live SAML/SCIM acceptance is roadmap work, not an accepted sales capability. Keep `required_saml_provider_id` unset and exclude enterprise SSO continuity from any current production offer or demo claim. This does not waive the identity/SSO gate for a customer that requires it; that sale remains blocked until the two-provider cutover and rollback evidence below exists.

Use a separate provider UUID and isolated test tenant for each IdP acceptance. Supabase-hosted SAML needs Pro or higher; the Free pilot cannot prove this path. Configure each IdP to send a persistent, non-email `NameID` **exactly equal** to its SCIM `User.externalId`, plus a separate email assertion. Confirm the deployed Auth identity stores that subject in `auth.identities.provider_id` with `provider = 'sso:<provider UUID>'`. Do not use email, display name, or user-editable metadata for binding. A deployment can show multiple SAML provider choices using `AIDR_SAML_PROVIDERS` (JSON array of `{ "providerId": "<UUID>", "label": "Microsoft Entra ID" }` objects) so different tenants can use Entra or Okta without redeploying. However, one AIDR tenant still accepts exactly one required provider UUID; the second IdP cannot be treated as an alternate login for that same tenant. Supporting two IdPs for one tenant requires a provider-qualified SCIM subject/membership model and is not implemented.

Before enabling the tenant policy, issue the SCIM token and exact group-role mappings with the current owner and record the provider UUID. Sync users/groups, then verify SAML login and the exact provider-qualified subject in an isolated tenant while the policy remains off. Once an approved policy later requires that provider, the first verified dashboard bootstrap binds only the matching SCIM subject and creates its mapped membership; same-email and other-provider sessions do not inherit access. SCIM cannot grant `owner`, so owner continuity must be completed separately. Never turn on the policy merely to test whether login works: a wrong provider or missing owner path locks out the tenant by design.

**SSO activation is currently a stop gate, not an operator instruction.** There is no audited application operation for setting or clearing `required_saml_provider_id`; a direct service-role update would not provide a reviewed cutover or recovery receipt. Before a real tenant cutover, implement and test an atomic policy-change operation with two distinct authorized approvals, reason/change ticket, old/new provider, and an append-only audit event. Require two provider-verified SAML owners to sign in and access the tenant before activation; verify each exact Auth UUID and SAML provider identity, not just an invitation email. Owner changes must be made by an active owner using AAL2 and produce an atomic audit event. Keep SSO owners outside SCIM-managed membership until an explicit lifecycle design exists: the SCIM binder refuses to take over manual owner membership, and disabling such an owner at the IdP is not presently an immediate AIDR-session revocation guarantee. Password recovery/break-glass does not bypass required SAML. A tested, dual-approved disable/rollback and session-revocation procedure is needed for IdP outages. Until these are implemented and exercised with both Entra and Okta against the release candidate, leave the policy `NULL` and do not claim GA SSO continuity.

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
  "expires_at": "<optional RFC 3339 timestamp, within 365 days>"
}
```

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

## Acceptance boundary

Local contract tests cover owner-only access, tenant scoping, MFA/session barriers, exact-ID and role validation, one-time secret handling, hash-only persistence, bounded token expiry, token overlap/revocation, mapping reconciliation conflicts, malformed member references, and resource discovery URLs. They do not prove a live Entra or Okta tenant is configured. Production acceptance still requires an operator to deploy the migrations/function, configure the provider's provisioning application and secret, verify user/group create-update-deactivate and membership removal against the deployed candidate, test expiry and immediate revocation with the provider, rotate legacy indefinite credentials, and retain redacted evidence bound to that candidate.
