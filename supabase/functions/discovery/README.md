# Managed discovery collector authentication

`discovery` accepts two independent bearer types. Human requests use a Supabase
access token and pass the tenant membership, session-revocation and MFA policy
barriers. A collector uses a 256-bit `aidr_dc_…` credential and can call only
`ingest` or `cursor` for the tenant and collector named when it was issued. The
Supabase gateway must have `verify_jwt = false` for this function; the handler
and its service-role RPCs authenticate each request. Deploy it behind TLS. A
public gateway `apikey`, when required, is not collector authentication.

An active tenant owner or admin with AAL2 issues or rotates a credential:

```json
{"action":"issue_credential","tenant_id":"<tenant UUID>","collector_id":"site-1","expires_in_days":30}
```

The response contains `credential` **once**, plus `credential_id`,
`expires_at`, and `next_sequence`. The lifetime defaults to 30 days and is
limited to 90 days. Store the bearer in the collector's protected secret store,
never in command history, logs or the discovery payload. Reissuing for the same
tenant and collector immediately invalidates the old bearer. Human owners and
admins can call `revoke_credential` with `tenant_id` and `collector_id`; that
action also requires AAL2. A removed or demoted issuer makes its collector
credential unusable until another owner/admin rotates it.

The collector first calls `cursor` with only `tenant_id` and `collector_id`.
The response contains its own `last_sequence` and `next_sequence`, with no
targets, observations or other inventory. It then submits the existing bounded
origin-only `ingest` payload at `next_sequence`. Replayed or out-of-order
sequences return HTTP 409; retry by fetching a new cursor and producing a new
cycle UUID. The tenant and credential are rechecked inside the ingest
transaction, so a rotation or revocation between cursor and ingest denies the
write. Both actions consume tenant and per-credential rate limits.

Only human access tokens can call `read` and `summary`. All credentials are
stored as SHA-256 digests, not raw bearers. Tenant deactivation revokes keys;
offboarding removes their metadata at the endpoint-identity phase. This local
contract still needs a customer-bound TLS, secret-store, scheduler and network
failure drill before production acceptance.
