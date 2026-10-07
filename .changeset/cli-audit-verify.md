---
"@singularityrd/aidr-cli": minor
"@singularityrd/aidr-core": minor
---

`aidr audit verify [path]` verifies the Ed25519-signed response-action chain offline and reports the first broken link (line, entry id, reason). It exits 1 when the chain is broken and 2 when it cannot be verified (log or signing key missing); it never creates a signing key. Core exposes `ResponseAuditor.verifyChain()` with the detailed result.
