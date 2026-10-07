# Control Plane (Auth, Dashboard, Licensing)

The control plane is the managed layer for:

- User authentication (dashboard login)
- Centralized agent inventory (installations)
- Telemetry-backed dashboards (verdict/event timeline)
- Incidents view derived from telemetry events (see `docs/incidents.md`)
- Agent-seat licensing (1 free agent, paid per additional agent)

For commercial builds, Singularity AIDR is **managed-first**: enrollment is required before protection is activated.

## Single sign-on

Tenants can require SAML or OpenID Connect (Entra ID, Okta, generic) sign-in; see [OIDC SSO](production-readiness/oidc-sso-admin.md) and [SCIM directory setup](production-readiness/scim-directory-admin.md). Both are optional and off by default.

## Enrollment (recommended)

The primary onboarding flow is **device authorization**:

1. Install the connector (Claude Code / Cursor / VS Code / OpenClaw / OpenCode).
2. Start the agent once.
3. Singularity AIDR prints a short verification code and a verification URL.
4. Open the URL, sign in, and approve.
5. Restart the agent (or rerun the enable-protection command).

See [Device Auth](device-auth.md).

## API keys (fallback)

For advanced or support scenarios, you can still use API keys:

1. Sign in to the dashboard.
2. Create an API key.
3. Set `auth.api_key` in `~/.singularity-aidr/config.json` and enable `control_plane.enabled`.

## Licensing model (recommended)

- **1 free agent per user**: first unique installation id (`iid`) that phones home under a given API key.
- **Paid per additional agent**: each additional unique `iid` requires an entitlement.

Enforcement is intended to be **server-side**:

- If the control plane sees a new `iid` over the entitlement limit, it should reject ingest (`402`/`403`) and optionally return a machine-readable error.
- The client should keep running local protections and simply disable cloud-only features (fail-open).

## Signed runtime policy (Ed25519)

`GET /v1/policy` returns the tenant policy with a `policy_sha256` digest (SHA-256 of the
canonical `runtime_policy`) and, when the control plane has a policy signing key, a
`policy_signed` block:

```json
"policy_signed": {
  "alg": "ed25519",
  "key_id": "policy-2026-10",
  "sig_b64": "...",
  "envelope": {
    "schema_version": 1, "key_id": "policy-2026-10",
    "policy_version": "pol_20261005120000", "policy_sha256": "<hex>",
    "sequence": 1791201600000, "issued_at": "...Z", "expires_at": "...Z", "tenant_id": "..."
  }
}
```

The signature is Ed25519 over `canonicalJson(envelope)` (recursively key-sorted JSON, the same
form as signed entitlements). The legacy `policy_signature` HMAC field is an
operator-side value that connectors cannot verify and is ignored by them.

**Connector configuration.** Trust anchors are `control_plane.policy_public_keys_pem`
(Ed25519 public keys, PEM or base64 SPKI). If empty, `licensing.public_keys_pem` is used. If
neither is set, signature checking is off and only the digest over TLS applies.

When at least one key is configured, a policy is applied only if all of these hold:

- the signature verifies against one configured key (several keys may be listed for rotation);
- `key_id` (signed inside the envelope) is not in the signed revocation feed's `key_ids`
  (`licensing.revocations_cache_path`, the same feed that revokes entitlement and pack keys; the
  feed is used only when its signed `tenant_id` matches the tenant of the verified entitlement);
- the envelope's `policy_sha256` and `policy_version` equal the delivered ones, and the digest
  matches the delivered `runtime_policy`;
- `issued_at` is not in the future (5 minute skew) and `expires_at` has not passed;
- `sequence` is not lower than the highest accepted for this endpoint and token, and an equal
  sequence carries the same digest (rollback and replay protection, persisted in the policy cache).

Unsigned, tampered, wrong-signer, expired, revoked-key and rolled-back policies are rejected.
With `control_plane.remote_policy_required` the connector then fails closed (no policy applies
and the call is blocked); otherwise the response is ignored and local policy stays in force.
The last good signed policy is still cached and may be used inside the offline grace window, but
never beyond its signed `expires_at`, and it is re-verified on every load, so a tampered cache
file is rejected.

**Landing control plane.** Provision the signing key with `AIDR_POLICY_SIGNING_KEY_ID` and
`AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64` (Ed25519, PKCS#8 DER base64; set both or neither,
a half-configured pair returns 503 `policy_signing_unavailable`), validity with
`AIDR_POLICY_SIGNATURE_TTL_HOURS` (default 24, 1 to 720). A dedicated key is recommended; when
unset the entitlement signing key is reused (matching the connector's fallback to
`licensing.public_keys_pem`), and with neither the policy is served unsigned. The sequence is the
policy publish time in epoch milliseconds (or an explicit `runtime_policy_sequence`). Generate a key pair:

```bash
node -e "const c=require('crypto');const k=c.generateKeyPairSync('ed25519');console.log('AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64='+k.privateKey.export({type:'pkcs8',format:'der'}).toString('base64'));console.log('public (connector policy_public_keys_pem):\n'+k.publicKey.export({type:'spki',format:'pem'}))"
```

**Supabase Edge Function.** `supabase/functions/policy` emits the identical envelope (canonicalisation
copied into `_shared/policy-signature.ts`, held to `packages/core` by `policy-signature.test.ts`, which
runs the real `verifySignedPolicy` over the function output). It uses the same variables as the landing
control plane: `AIDR_POLICY_SIGNING_KEY_ID` + `AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64`
(both or neither), `AIDR_POLICY_SIGNATURE_TTL_HOURS` (default 24, 1 to 720), falling back to
`AIDR_ENTITLEMENT_SIGNING_KEY_ID` / `AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64`. A half-configured
pair, an invalid TTL, an unusable key or a missing publish time answers 503 `policy_signing_unavailable`
(before authentication); with no key configured the policy is served unsigned, which connectors holding
policy public keys reject. The sequence is the publish time in epoch milliseconds
(`tenant_runtime_policies.updated_at`; for an agent-bound policy the later of the revision `created_at` and
the assignment `assigned_at`). Limitation: removing an agent's assignment so it returns to the tenant policy
can yield a lower sequence than the staged revision it left; connectors then refuse it as rollback until the
tenant policy is re-published (which advances the sequence).

Rotate by adding the new public key to connectors, switching the landing key id and private key,
then revoking the old `key_id` in the signed revocation feed.
