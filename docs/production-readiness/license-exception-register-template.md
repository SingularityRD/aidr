# License exception register template

Status: **OPEN / LOCAL TEMPLATE**

The register is [`license-exception-register.json`](./license-exception-register.json), with the required shape in [`license-exception-register.schema.json`](./license-exception-register.schema.json). Validate both local compliance artifacts from the repository root:

```sh
pnpm verify:commercial-compliance
```

## Required entry fields

Every entry must identify the exact component and version, declared license, exception type, scope, reason, risk, mitigations, owner, approver, evidence, status, and `expires_at` date. Use the literal `unknown` when a value is not available. Empty strings and informal placeholders such as `TBD` are rejected.

An entry with status `approved` must have known owner, approver, approval date, evidence, and a future expiry date. An entry whose expiry has passed must be marked `expired` or `revoked`; the validator never renews an entry automatically. The register itself remains `open` while these inputs are unresolved.

This artifact records a local workflow and expiry check. It does not grant distribution permission or establish provenance, ownership, or an external decision.
