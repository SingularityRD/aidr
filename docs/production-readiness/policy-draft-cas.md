# Exact-source policy draft saves

The dashboard submits `save_document_draft` to `policy-management` with the exact
YAML string and the revision loaded when editing began:

```json
{
  "action": "save_document_draft",
  "tenant_id": "<tenant UUID>",
  "content": "<exact YAML text>",
  "expected_document": {
    "id": "<document UUID>",
    "version": 1,
    "source_sha256": "<64 lowercase hexadecimal characters>"
  }
}
```

A confirmed absent document uses `expected_document: null`. An omitted or malformed
precondition is not treated as permission to create/overwrite. A stale document
ID, version, hash, or first-save expectation returns HTTP 409
`policy_document_conflict`; reload and reconcile rather than retrying with a fresh
precondition automatically.

The handler retains authentication, session revocation, tenant membership/expiry,
active-tenant, MFA and rate-limit checks. Owners, admins and members may save a
draft; runtime publication remains owner/admin-only and is otherwise unchanged.
The existing stored-document compile/publish actions remain available. The optional
`compile_document_draft` action accepts the same content and simulation without a
save or revision precondition.

## Write boundary

The shared draft compiler bounds UTF-8 source to 65,536 bytes, parses with the
existing pinned strict YAML parser (no duplicate keys/alias expansion), validates
supported compiler/runtime semantics, and hashes the original bytes using SHA-256.
The entire JSON request retains its existing 65,536-byte limit, so JSON escaping
and metadata reduce the practical maximum source size. Invalid parsing, unsupported
fields, compiler validation or simulation errors never reach the policy write RPC.

The service-only `save_policy_document_draft` database function takes the exact
compiled source, its hash and the loaded precondition. One tenant transaction lock
serializes first saves and updates. The transaction rechecks active membership,
compares document ID/version/hash, checks the submitted source hash independently,
and returns the written revision. The Edge handler and browser reject an absent,
malformed or mismatched acknowledgement. No browser insert/update/delete or
compensating rollback participates in a save. A lost response after a committed
write is reported as failure/uncertain, never as confirmed success; reload before
retrying, since the old precondition will conflict.

## Deployment and validation boundary

1. Apply `20260916000003_policy_document_draft_cas.sql`.
2. Deploy the updated `policy-management` function and shared compiler.
3. Deploy the dashboard bundle together with the new action contract.

The migration preserves all legacy rows and timestamps, adds revision/hash
metadata, and revokes browser INSERT/UPDATE grants so older clients cannot bypass
the compile-before-write boundary. Legacy TRUNCATE/TRIGGER/REFERENCES grants are
also removed (TRUNCATE is not protected by row-level security). Existing
SELECT/DELETE policies and runtime
policy tables/RPCs are unchanged. Until the function/dashboard are deployed,
older draft editors fail closed instead of writing. Existing legacy documents are
not retroactively compiled by the migration.

Handler tests execute the real handler, YAML parser and compiler against an
in-memory database boundary. Dashboard tests exercise the actual editor with
mocked Edge responses. The isolated PostgreSQL fixture under
`supabase/tests/policy-draft-validate.mjs` exercises the actual migration and CAS;
it is not a full Supabase deployment, production RLS/MFA end-to-end verification,
or an acknowledgement that any hosted database/function has been upgraded.
Run the database fixture with `node supabase/tests/policy-draft-validate.mjs`
(Node + Docker, cached `postgres:17-alpine`). It creates a dedicated no-network,
no-host-port, tmpfs PostgreSQL container, stops it in `finally`, and retains the
stopped container. It applies this migration to a minimal prerequisite schema,
not the entire Supabase migration chain. Concurrency checks use PostgreSQL's
normal READ COMMITTED isolation, matching the intended PostgREST RPC path.
No DLP backend is introduced by this change.
