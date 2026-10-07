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
targets, observations or other inventory. It then submits the bounded
`ingest` payload at `next_sequence`.

Target addresses never reach the panel. Each item's `target` is a keyed,
tenant-scoped pseudonym, `tid1_<hex HMAC-SHA256(key, "aidr-discovery-target-v1\0"
+ tenant_id + "\0" + origin)>`, where the 32-byte key is generated once per
collector installation at `~/.singularity-aidr/discovery-target-key` and never
leaves it. The handler and `ingest_tenant_discovery_cycle` accept only that
form; a raw origin returns `400 target_address_not_accepted` (older collectors
fail loudly rather than store an address). Rows stored before
`20261007000000_discovery_target_pseudonyms.sql` keep their origin, are returned
with `target_kind: "legacy_origin"`, and are removed by that collector's next
complete cycle (outside a legal hold). Operators map an id back to an address
with the local `panel_id` printed by `aidr collect`.

Follow-up (not implemented): there is no panel ingest path for infrastructure
CVE findings. When one is added it must carry only CVE id, severity, component,
version and rule id, keyed to the target pseudonym, and stay opt-in. Replayed or out-of-order
sequences return HTTP 409; retry by fetching a new cursor and producing a new
cycle UUID. The tenant and credential are rechecked inside the ingest
transaction, so a rotation or revocation between cursor and ingest denies the
write. Both actions consume tenant and per-credential rate limits.

Only human access tokens can call `read`, `list`, and `summary`. `list` returns
a bounded, cursor-paginated set of collector status rows for the authenticated
tenant; it never accepts a tenant selector other than the already-authorized
`tenant_id`, and labels its scope `reported_collectors_only`. `read` then returns
the selected collector's bounded target page with current `freshness` and
`alert_state`. These APIs report only collectors that have submitted data and
must not be presented as complete cloud, MDM, or tenant-estate discovery.

All credentials are stored as SHA-256 digests, not raw bearers. Tenant
deactivation revokes keys; offboarding removes their metadata at the
endpoint-identity phase. The local contract still needs customer-bound TLS,
protected secret storage, an activated customer schedule, provider/tool
acceptance and live alert-routing acceptance before production acceptance.
