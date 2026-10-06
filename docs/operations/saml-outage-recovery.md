# Full SAML outage recovery

Use this controlled operator procedure when the tenant's configured SAML provider is unavailable and no owner can reach tenant administration. It disables the tenant's currently configured SAML provider requirement after verifying one named, existing recovery owner. It does not create a user, password, email link or Auth session. The owner's existing configured Auth recovery procedure and MFA remain necessary. The tenant's `require_mfa` setting and session validation barriers remain unchanged.

The selected recovery owner must already have active, manual owner membership in the active tenant, with an existing unbanned, nondeleted Auth user. A SCIM-managed membership is not a recovery owner. Confirm the exact tenant, current provider, eligible owner and incident/change reference through the customer's approved identity verification process before preparing the request.

## Enroll and separate operator keys before an outage

A database administrator enrolls two independent operators through privileged, offline SQL in `app.tenant_saml_recovery_operator_keys`. Each row binds `tenant_id`, `key_id`, `operator_id`, a cryptographically generated 32-byte `secret` (`bytea`), `enabled`, and finite `not_before` / `not_after` bounds. Use different operator IDs and different secrets. Record the enrollment, approval, expiry and any revocation in the privileged database change log. There is no browser or service-role enrollment API, and those roles cannot read or write this key table.

Each operator separately retains their own custody file, outside the repository, deployment artifact, incident ticket and service credential store:

```json
{
  "key_id": "<enrolled key UUID>",
  "tenant_id": "<tenant UUID>",
  "operator_id": "<independent operator UUID>",
  "secret_hex": "<the enrolled 32-byte secret as 64 lowercase hex characters>"
}
```

Keep each file on that operator's private workstation or approved custody volume. On POSIX it must be owned by the current operator with mode `0600` or `0400`; on Windows its ACL must allow only the current owner, SYSTEM and Administrators. The signer checks native permissions, refuses linked files, and never prints the secret. Protect the containing directory and backups through the same custody process. Never place both keys on the apply host or let one operator sign twice. Two UUIDs establish distinct enrolled identities; external custody and the organization's approval process establish two independent humans.

This is shared-secret HMAC authorization. The database administrator can read the stored secrets and can change the database itself. It is a full-trust boundary, not a cryptographic defense against a compromised database administrator. The service credential alone cannot enroll an operator, read a recovery key or forge the two enrolled MACs.

Key records are immutable except for revocation (`enabled = false`). Revoke the existing key before enrolling a new key ID with a new random secret for the same operator. Retain revoked records until the tenant's credential erasure phase permits deletion. The tenant offboarding request immediately revokes all its operator keys; an active legal hold preserves the records and recovery audit evidence.

## Prepare, independently sign, then apply

Use Node.js from the reviewed release. Work in a restricted incident directory; synchronize operator and database clocks. The request expires five minutes after preparation. Generate a fresh request and obtain both fresh approvals if it expires. The payload is compact deterministic JSON with no trailing newline; review it without editing or reformatting its bytes.

```sh
node scripts/saml-outage-recovery.mjs prepare \
  --tenant <tenant-uuid> \
  --current-provider <configured-saml-provider-uuid> \
  --recovery-owner <existing-owner-auth-user-uuid> \
  --change-ref INC-12345 \
  --reason "Both approved SAML access routes are unavailable; recover the verified tenant owner." \
  --out payload.json
```

Each operator must independently review the same exact `payload.json`, including the tenant, current provider, recovery owner, action (`new_provider_id: null`), reason, incident reference, nonce and expiry. On their separate custody machine, each signs using only their own key:

```sh
node scripts/saml-outage-recovery.mjs sign \
  --payload payload.json --key-file /private/operator-key.json \
  --out operator-approval.json
```

Transfer the unchanged payload and the two approval files to the restricted apply host. Keep private keys with their operators. The apply host requires the existing service credential in `SERVICE_ROLE_KEY` through the approved secret-injection process; do not put its value in the command line, browser, ticket or log. Supply the exact Supabase origin explicitly:

```sh
node scripts/saml-outage-recovery.mjs apply \
  --payload payload.json \
  --approval operator-one-approval.json \
  --approval operator-two-approval.json \
  --supabase-url https://api.customer.example
```

The tool refuses expired requests, altered payload bytes, mismatched receipt digests, duplicate keys/operators and insecure endpoints before network access. It sends the exact signed text and only the two `{key_id, mac_hex}` approvals to the service-only `recover_tenant_saml_outage` RPC. Only the database authenticates MACs and the enrolled operators, rechecks current provider/owner state, consumes the nonce and records the recovery audit atomically. Do not treat local receipt metadata as proof of a valid signature.

For an isolated development rehearsal only, `--development` permits an explicitly supplied `http://localhost`, `http://127.0.0.1` or `http://[::1]` origin. Production requires HTTPS. Redirects are refused.

## Verify and close the incident

A successful result binds `status: recovered`, `method: dual_operator_hmac`, the nonce, tenant, old provider, recovery owner, incident reference, both operator IDs, durable audit log ID and application timestamp. The helper checks those bindings before printing the result. Retain the reviewed payload, both approvals, result and database audit receipt as incident evidence; none contains the custody secret.

An active legal hold preserves recovery audit evidence and does not block this approved access recovery. The tenant offboarding process revokes/deletes operator key material through its credential retention phase; do not attempt recovery for an inactive or closing tenant.

If a timeout or invalid response leaves application uncertain, reconcile the existing nonce and audit receipt through the privileged operator process before creating another request. A repeated nonce cannot authorize another recovery. Do not infer success from a network timeout, a locally signed file or an Auth email being sent.

After recovery, the verified owner must complete the existing Auth recovery and MFA flow, repair/reconfigure SAML through normal owner administration, confirm a new SAML session, and review the incident's credential custody. Restore the customer-approved provider policy explicitly; this procedure does not restore it automatically.

Local regression check:

```sh
node --test scripts/saml-outage-recovery.test.mjs
```
