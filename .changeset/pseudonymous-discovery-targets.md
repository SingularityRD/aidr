---
"@singularityrd/aidr-core": minor
"@singularityrd/aidr-cli": minor
---

Managed discovery no longer uploads target addresses.

`aidr collect` with a discovery upload configured now sends each target as a
keyed, tenant-scoped pseudonym (`tid1_` + HMAC-SHA256) instead of its origin.
The HMAC key is created once per installation at
`~/.singularity-aidr/discovery-target-key` and never leaves the device; a
missing or malformed key stops the upload instead of falling back to the
address. Local output shows each target's `panel_id` so operators can match
dashboard rows to addresses. The discovery endpoint and database now reject raw
origins (`target_address_not_accepted`), so collectors older than this release
must be upgraded before their next upload. Origin rows stored earlier remain
readable as `legacy_origin` until the collector's next complete cycle replaces
them. `aidr discover` additionally reports AIG MCP categories (mcp-01..mcp-14)
and the location of hardcoded secrets in MCP server configs, never their values.
