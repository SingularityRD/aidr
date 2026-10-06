# Delegated credential broker

This Edge Function issues Ed25519-signed, short-lived credentials for one exact
`user -> tenant -> agent -> MCP server/tool -> resource -> audience -> scopes`
lineage. The maximum lifetime is 15 minutes and the installer provisions a
dedicated signing key which is separate from entitlement signing.

All requests are `POST`. `grant`, `issue`, and `revoke_grant` use a Supabase
access token. `introspect` and `redelegate` use the delegated credential in the
Bearer header because the Supabase gateway JWT check is disabled for this mixed
credential endpoint; the function verifies either credential before doing any
authorization work.

All Supabase-session actions (`grant`, `issue`, `revoke_grant`, and `lineage`)
also check session revocation and the tenant's MFA policy before any privileged
service-role RPC. A missing or unreadable identity state fails closed.

Grant creation and issuance obtain private evidence from the authenticated Auth
session: session ID, JWT issuance/expiry, current assurance and SAML provider.
Neither request can supply this evidence. Grant creation rechecks the issuer's
current session and identity policy inside the locked transaction and after its
audit write; evidence is stripped before the original grant operation. Issuance
stores it on the existing receipt, outside the signed credential and responses.
Children inherit the parent's exact evidence. Broker issuance, finalization,
introspection and redelegation recheck
the current tenant MFA/SAML/OIDC policy, live Auth/OIDC session and global
revocation barrier. Historical receipts and trusted service grant calls without
this evidence are denied when any identity enforcement is enabled. Updated Edge
grant and issue requests always require the live evidence. Apply
`20261006007000_delegated_session_policy_binding.sql` before deploying this route.

An owner or admin first creates a grant:

```json
{
  "action": "grant",
  "tenant_id": "...",
  "subject_user_id": "...",
  "agent_id": "...",
  "tool_server_id": "github-mcp",
  "tool_name": "repository.write",
  "resource_type": "repository",
  "resource_id": "acme/payments",
  "audience": "github-mcp.internal",
  "scopes": ["contents:read", "contents:write"],
  "max_ttl_seconds": 300,
  "max_delegation_depth": 1,
  "grant_expires_in_seconds": 3600
}
```

The subject can then issue a narrower credential with the returned `grant_id`.
A child credential is requested with `action: "redelegate"`, a strict subset
of the parent scopes, and the parent credential in the Bearer header. A child
cannot change the subject, tenant, agent, tool, resource, audience, extend the
expiry, or exceed the grant's depth.

An audience authorizes a request with `action: "introspect"` and the exact
current context:

```json
{
  "action": "introspect",
  "context": {
    "tenant_id": "...",
    "subject_user_id": "...",
    "agent_id": "...",
    "audience": "github-mcp.internal",
    "tool": { "server_id": "github-mcp", "name": "repository.write" },
    "resource": { "type": "repository", "id": "acme/payments" },
    "required_scopes": ["contents:write"]
  }
}
```

Introspection is the authoritative online authorization check: it binds the
expected tenant, subject and agent to the signed lineage, rejects an expired or
revoked grant, and immediately rejects a subject whose tenant membership expired
or was removed. Removing membership permanently revokes its existing grants and
receipts; restoring the member requires a new grant and credential. Current
provider enforcement also applies to the original issuing session, so retaining
membership does not keep an old password or other-provider credential active.
An audience requiring current policy and revocation must introspect before each
protected action and deny an unavailable check. Core signature verification provides the
cryptographic and context-binding check for offline consumers, but it cannot
observe later membership, provider-policy or session changes; offline authority ends at the
signed expiry. Do not log, persist, or expose the returned `access_token` to an
agent or model.

This is Supabase Auth session evidence. It does not establish a selected Clerk
directory grant or correlate a Clerk actor with a Supabase provider subject.

For incident investigation, an owner, admin, or non-expired `support_jit`
member can submit `{"action":"lineage","tenant_id":"...","token_id":"..."}`
with a Supabase access token. The result walks from the observed token back to
the root grant and includes the signed tool/resource/audience/scope context.
Every lineage read is itself written to the service-only administrator audit
log.
