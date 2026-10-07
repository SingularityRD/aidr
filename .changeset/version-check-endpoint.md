---
"@singularityrd/aidr-core": minor
---

Version checks now have a server: the `version-check` Edge Function answers `/v1/version-check` with the latest release from an Ed25519-verified release manifest or a configured version, rate limited and without storing request fields. Managed installs with a control plane endpoint ask that control plane (`versionCheckEndpoint()`); `checkForUpdate()` takes an optional endpoint.
