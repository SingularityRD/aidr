# Security Policy

## Reporting Vulnerabilities

Please report security vulnerabilities privately via [GitHub Security Advisories](https://github.com/singularityrd/aidr/security/advisories/new). Do not open public issues for security bugs.

Include:

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

We will acknowledge receipt within 10 business days and aim to provide a fix or mitigation plan within 30 days.

## Supported Versions

Only the latest release receives security updates.

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

Sentry and OpenTelemetry are opt-in. Sentry events, exception values/stacks,
request URLs/query strings, context and user PII are scrubbed before send.
OTLP span attributes/events/exceptions are scrubbed and endpoint credentials,
queries and fragments are removed. Keep `SENTRY_DSN` unset and
`TRACE_ENABLED=false` for an offline deployment.

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
