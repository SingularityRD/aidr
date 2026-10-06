# License exception register template

Status: **OPEN / LOCAL TEMPLATE**

The 6 October current prefill identifies two review-required declarations:
certifi 2026.7.22 (MPL-2.0) and pure psycopg 3.2.10 (LGPLv3).
The binary wheel was removed from the current locks; its 14-library record is
[historical evidence](./evidence/native-library-inventory-2026-10-06.json),
not an approved exception. The [current review pack](./bridge-notice-review-pack-2026-10-06.md)
contains actual wheel and scoped distro notice materials.
Each is an OPEN dependency-policy review request with actual owner, approver,
approval date and expiry unknown. Legal may resolve a review through ordinary
compliance, a reviewed replacement/removal or an actual scoped exception; the
presence of this request does not establish that an exception is necessary or
granted. The 17 system-libpq dependency paths have captured copyright materials;
exact candidate/full-image scope, source obligations and Legal disposition remain open.

The register is [`license-exception-register.json`](./license-exception-register.json), with the required shape in [`license-exception-register.schema.json`](./license-exception-register.schema.json). Validate both local compliance artifacts from the repository root:

```sh
pnpm verify:commercial-compliance
```

## Required entry fields

Every entry must identify the exact component and version, declared license, exception type, scope, reason, risk, mitigations, owner, approver, evidence, status, and `expires_at` date. Use the literal `unknown` when a value is not available. Empty strings and informal placeholders such as `TBD` are rejected.

An entry with status `approved` must have known owner, approver, approval date, evidence, and a future expiry date. An entry whose expiry has passed must be marked `expired` or `revoked`; the validator never renews an entry automatically. The register itself remains `open` while these inputs are unresolved.

This artifact records a local workflow and expiry check. It does not grant distribution permission or establish provenance, ownership, or an external decision.
