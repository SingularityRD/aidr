---
"@singularityrd/aidr-core": patch
"@singularityrd/aidr-claude-code": patch
"aidr-cursor": patch
"@singularityrd/aidr-openclaw": patch
"@singularityrd/aidr-opencode": patch
"@singularityrd/aidr-cli": patch
"@singularityrd/aidr-sdk": patch
"@singularityrd/aidr-dashboard": patch
"@singularityrd/aidr-codex": patch
"@singularityrd/aidr-mcp-gateway": patch
---

GA readiness hardening (rides the 1.0.0 major release).

Detection and enforcement: local detection keeps enforcing when a managed entitlement is missing, invalid or expired (only managed features switch off, and every verdict says so). With no reputation service configured, fetches and installs that local rules find nothing in are allowed and labelled `reputation_not_checked` instead of held; set `url_check.unchecked_action` / `package_check.unchecked_action` (SDK: `urlReputationUncheckedAction`) to `ask` for the old behaviour. New rules cover script content an agent writes (pipe-to-shell, reverse shells, encoded execution in `.sh`, Dockerfile, CI workflow, git hook, `package.json` scripts), credential reads that avoid the literal path, JavaScript/Perl/PHP one-liners and decode-and-exec through command substitution (519 rules in 31 files). Self-defense denies disabling or uninstalling AIDR through host CLIs, editing its files, and turning it off in host settings; `AIDR_*_DIR` rule overrides are ignored in commercial builds. MCP/unknown tools with argv-shaped commands are inspected like shell calls.

Connectors and CLI: Codex registers PreToolUse for `^(Bash|apply_patch|mcp__.+)$`, UserPromptSubmit and PostToolUse. `aidr setup` installs or updates the connector of every detected host and needs no credential in local mode; `aidr uninstall` removes every connector, the local data and the AIDR vault items (`--hooks-only` keeps the old behaviour). Operator approvals work on hosts without an OS vault through a machine-bound encrypted store (`key_storage: auto`; `os-vault` keeps the strict behaviour). `aidr simulate` defaults to `--min-score 90`. Messages, `aidr --help`, status/pending/approve, the extension and the dashboard shell are available in Turkish (`AIDR_LOCALE=tr`, config `locale`, or a Turkish shell locale).

MCP gateway: approvals are Ed25519-signed by an operator key and only `aidr-mcp-approve` can write them; the importable library no longer contains an approval writer. Signed manifests have a bounded lifetime and expiry warnings.

Control plane: API keys expire (default 365 days, `expires_in_days` 1–730 or explicit `null`), separation of duties on approvals (required by default on Business/Enterprise), two-step device verification with device details, validated revocation feed timing, and separate signed/unsigned version-check rate limits. Apply the new migrations before upgrading the control plane.
