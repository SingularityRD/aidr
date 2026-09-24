# Integrity verification for commercial builds

Commercial AIDR builds require a successful integrity check before protected
connector behavior can start. A missing or invalid manifest, signature, trusted
key, or covered file is a startup failure—not a warning or a best-effort check.

## What is verified

- Connectors verify the signed artifact manifest beside their runtime files
  (typically under `dist/`) with Ed25519 public keys.
- The Claude Code endpoint installer additionally verifies the signed package
  manifest covering `package.json`, `dist/`, and `resources/` before copying
  package files and again after copying them.
- The Claude plugin archive must come from a publisher-verified release bundle.
  That bundle also authenticates plugin metadata and hook registration files
  which are outside the endpoint package manifest.
- Commercial integrity failures enter degraded safe mode and throw an
  integrity error. The connector must not register hooks or claim protection is
  active. Incident logging is best-effort and does not alter this decision.

## Key distribution

The endpoint's independently provisioned configuration must contain:

- `integrity.enabled: true`
- `integrity.verify_on_start: true`
- `integrity.public_keys_pem: [...]` (trusted Ed25519 public keys in PEM)

The public key is a trust input and must arrive through a channel independent
of the package. Never package or distribute the signing private key with an
endpoint. Provision the key before registering a commercial connector.

Verification is designed to work offline after the signed artifacts and public
key are provisioned. Developer builds may skip checks when verification is not
enabled and may tolerate missing developer release metadata; these exceptions
do not apply to commercial builds.
