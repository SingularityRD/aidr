---
"@singularityrd/aidr-cli": patch
---

`aidr doctor` reports the effective DLP source (signed managed bundle or the local unsigned `dlp-policy.json`) instead of claiming "local mode has no DLP" while a local policy is enforcing. An invalid local policy is reported as not enforced, and a local file in managed mode as ignored.
