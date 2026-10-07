---
"@singularityrd/aidr-core": minor
---

The AI governance overlay (MCP bans/restrictions) is now bound by the signed runtime-policy envelope (`governance_sha256`). `verifySignedPolicy` refuses a policy whose overlay was stripped, swapped or injected (`governance_mismatch`); an overlay from a legacy signer that does not bind it is still applied (it can only tighten) and logged as not signature-bound.
