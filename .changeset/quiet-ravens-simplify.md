---
"@singularityrd/aidr-core": major
"@singularityrd/aidr-claude-code": major
"aidr-cursor": major
"@singularityrd/aidr-openclaw": major
"@singularityrd/aidr-opencode": major
"@singularityrd/aidr-cli": major
"@singularityrd/aidr-sdk": major
"@singularityrd/aidr-dashboard": major
"@singularityrd/aidr-codex": major
"@singularityrd/aidr-mcp-gateway": major
---

Breaking compatibility update for the GA candidate. All Node packages now require Node.js 22.12 or newer. Upgrade the host runtime before installing.

The SDK removes the LangChain, LlamaIndex, AutoGen, and CrewAI adapters, freemium, referral, and team-dashboard helpers, and the `aidr-sdk` executable. Replace adapter imports with `createGenericMiddleware`, the framework-neutral `createMiddleware` surface, or standalone output guards. Remove `aidr-sdk` invocations; use the supported `aidr` CLI for setup and local diagnostics, and the control plane for entitlements.

SDK URL reputation lookups are now off by default. A `fetch` check that local rules find nothing in is allowed and labelled `reputation_not_checked` in `metadata.category` (never reported as clean), matching core `url_check.unchecked_action: allow`; set `urlReputationUncheckedAction: "ask"` to hold every such fetch for review. An enabled reputation leg that cannot answer returns an indeterminate `ask`. Set `urlReputationEnabled: true` to opt in to reputation requests; set `includeUrlQueryParameters: true` separately if the provider must receive query parameters. Review approval handling before upgrading an SDK consumer.

The `aidr` CLI now prompts for secret configuration values instead of accepting them as command-line arguments: change `aidr config -s <secret-key> <value>` to `aidr config -s <secret-key>` and enter the value at the hidden prompt. `aidr scan` now exits with code 1 if any target could not be scanned, and code 2 for high or critical findings; update scripts that interpret its exit status.
