# Integrity Verification (Commercial Builds)

Singularity AIDR connectors can perform a **best-effort integrity check at startup** to detect tampering in packaged (closed-source) distributions.

## What it does

- Looks for a signed artifact manifest next to the connector’s runtime files (typically under `dist/`).
- Verifies the signature using Ed25519 public keys.
- If verification fails, the connector **fails open** (protection continues) but logs a local `incident` entry to the audit log.

## How connectors enable it

Connectors call an integrity helper from `@singularityrd/aidr-core` (when present) during startup.

## Key distribution

Commercial builds should configure integrity verification in AIDR config:

- `integrity.enabled: true`
- `integrity.verify_on_start: true`
- `integrity.public_keys_pem: [...]` (Ed25519 public keys in PEM)

## Notes

- This is designed to be **edge-first** and work offline.
- Missing manifests are treated as “not enforced” (no breakage) in developer builds.
