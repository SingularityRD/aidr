---
"@singularityrd/aidr-core": minor
"@singularityrd/aidr-cli": minor
"@singularityrd/aidr-claude-code": patch
"@singularityrd/aidr-codex": patch
"@singularityrd/aidr-openclaw": patch
"@singularityrd/aidr-mcp-gateway": patch
---

Per-customer builds for on-prem customers. Licenses can carry a signed
`customer_id`, and a vendor-signed customer packet (`aidr-customer-packet-v1`)
carries the license, company address, sensitivity preset and display name into
per-customer Windows (MSI, optional setup EXE) and Linux (deb, rpm, tar.gz)
installers. `aidr setup` verifies and applies the packet; `aidr status` and
`aidr doctor` show the customer, the license state and the date updates run
until. New rule/intel update packs are accepted only within the license term
and only for the customers they name, compared on signed times. Installed rules
and packs never stop enforcing because of license state, pack expiry or a
clock. Release bundles are minified.
