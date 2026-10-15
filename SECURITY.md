# Security Policy

## Reporting Vulnerabilities

The private repository advertises a [GitHub Security Advisories route](https://github.com/SingularityRD/aidr/security/advisories/new) for authorized collaborators. Do not open public issues for security bugs. External reporters cannot rely on that private-repository link; an approved, monitored external security-contact route is required before supported customer use.

Include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

Acknowledgement, update, and remediation targets are not yet approved or staffed. A customer-specific security response commitment must be established in an approved support schedule before sale; see [support operations](docs/runbooks/support-v7.md). The draft [vulnerability disclosure policy](docs/security/vulnerability-disclosure-policy.md) and [`security.txt` template](docs/security/security.txt.template) describe the external route once it is staffed; they are not in force yet.

## Supported Versions

Supported and security-only version ranges, maintenance end dates, and notice periods have not yet been approved. Do not infer support from the presence of a release; the versioned policy and customer agreement must specify it. The proposal under review is the [supported versions policy draft](docs/security/supported-versions.md).

## Scope

This policy covers:

- The Singularity AIDR source code (`packages/`)
- Threat detection rules (`threats/`)
- Build and distribution artifacts (VSIX, SEA binaries)

Third-party dependencies are managed via `pnpm audit` and updated regularly.

## Telemetry and audit-data boundary

The detector evaluates tool calls locally. Optional managed telemetry is sent
only when managed mode, control-plane sync and credentials are configured. The
control-plane client applies a mandatory credential scrub at the final outbound
boundary; the default `control_plane.redact_mode` is `hash`, while `full` is
recommended for high-sensitivity environments. A `none` setting still removes
bearer credentials, API keys, JWTs, URL credentials and secret query values,
but can retain ordinary command/URL text and is not a production default.

Sentry is opt-in. Sentry events, exception values/stacks, request URLs/query
strings, context and user PII are scrubbed before send. Keep `SENTRY_DSN` unset
for an offline deployment.

Local JSONL audit records are sensitive and must be protected by filesystem
permissions and an approved retention policy. For tamper-evident response
actions, construct `ResponseAuditor` with `{ signEntries: true }`; it creates an
Ed25519-signed SHA-256 hash chain, a `<audit-file>.head` checkpoint and a
signed retention-deletion manifest. Integrity verification fails closed for
malformed lines, invalid signatures, missing checkpoints and tail deletion.
This local mechanism is not an independent immutable archive: production
deployments must export signed records and checkpoints to an append-only store
with controlled key custody and test restore/deletion procedures. See
[`docs/privacy.md`](docs/privacy.md) for the data-flow and retention matrix.

Before customer use, document each enabled destination's region, retention,
access controls, subprocessors/DPA, key rotation and DSAR/deletion process.
