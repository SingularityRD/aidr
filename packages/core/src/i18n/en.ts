/**
 * English message catalog: the default and the reference set of keys.
 *
 * Every value here is the exact text the connectors showed before the catalog
 * existed, so an install without a Turkish locale sees no change. `{name}`
 * marks a parameter; product, rule and command names stay untranslated in
 * every locale.
 */
export const en = {
	// Severity labels (shown next to a rule id; the raw value is used when unknown).
	"severity.critical": "critical",
	"severity.high": "high",
	"severity.medium": "medium",
	"severity.low": "low",
	"severity.info": "info",
	"severity.warning": "warning",
	"common.unknown": "unknown",
	"common.none": "none",

	// Block / ask messages: one shape on every connector. What was stopped, why
	// in plain words, what the user does now, then one line for the agent. The
	// agent line never offers it a way to approve: approval is the user's own
	// terminal command or the dashboard.
	"block.deny.headline": "🛡️ Singularity AIDR blocked this action.",
	"block.ask.headline": "🛡️ Singularity AIDR stopped this action until you approve it.",
	"block.line.stopped": "Stopped: {what}",
	"block.line.why": "Why: {reason} ({details}).",
	"block.line.also": "Also found: {reasons}.",
	"block.detail.rule": "rule {rule}",
	"block.more": "{what} (+{count} more)",
	"block.artifact.command": "command",
	"block.artifact.url": "URL",
	"block.artifact.file_path": "file",
	"block.artifact.content": "content",
	"block.line.response": "What Singularity AIDR did: {response}",
	"block.response.failed": "response action(s) failed: {failures} - nothing was preserved",
	"block.response.rollback": "rollback: restored {target} from snapshot {snapshot}",
	"block.response.preserved": "{action}: preserved a copy of {target} at {where}",
	"block.response.snapshot": "snapshot {snapshot}",
	"block.response.vault": "(vault)",
	"block.response.unknownSnapshot": "(unknown)",
	"block.deny.next":
		"What you can do: if you think this is a false positive, report rule {rule} to your IT or security team; they can allow it with a time-limited exception. Details: `aidr audit tail`.",
	"block.deny.nextNoRule":
		"What you can do: if you think this is a false positive, report it to your IT or security team. Details: `aidr audit tail`.",
	"block.ask.cli":
		"To allow it once, run this in your own terminal (valid for 15 minutes), then ask the agent to try again:\n  {command}",
	"block.ask.notRecorded":
		"This request could not be saved for approval, so it cannot be allowed from the terminal. Run `aidr doctor` in your own terminal to see why.",
	"block.ask.dashboardOnly":
		"Only an administrator can allow it, in the Singularity AIDR dashboard.",
	"block.ask.hostDialog": "Choose Yes to allow it once, or No to keep it blocked.",
	"block.ask.next":
		"Details: `aidr pending`. If you think this is a false positive, report rule {rule} to your IT or security team.",
	"block.ask.nextNoRule":
		"Details: `aidr pending`. If you think this is a false positive, report it to your IT or security team.",
	"block.ask.reference": "Approval reference: {actionId}",
	"block.agent.deny": "For the AI agent: do not retry this call or try to work around the block.",
	"block.agent.ask":
		"For the AI agent: you cannot approve this action and no tool available to you can. Tell the user what was stopped and how they can allow it, then stop: do not retry this call or try to work around the block.",
	"block.agent.short":
		"🛡️ Singularity AIDR blocked this action: {reason}. Do not retry it or try to work around the block; the user has been shown the details.",
	"block.agent.askShort":
		"🛡️ Singularity AIDR stopped this action until the user approves it: {reason}. You cannot approve it and no tool available to you can; do not retry it or try to work around the block. The user has been shown how to allow it.",
	"codex.dlpRewrite":
		"This tool call contains sensitive data that must be masked first, and Codex cannot safely change a tool call's input, so it was blocked. Remove the sensitive values and try again.",
	"block.configUnreadable":
		"Singularity AIDR could not read its configuration, so this action was blocked instead of being offered for approval.",
	"dashboard.requested":
		"Approval requested in the AIDR dashboard: {requestId}\n(For the user: an AIDR administrator must approve this request in the dashboard; the\napproval then covers one retry of this exact call.)",
	"dashboard.denied":
		"The AIDR dashboard approval request {requestId} was denied; the action stays blocked.",
	"dashboard.expired":
		"The AIDR dashboard approval request {requestId} expired; the action stays blocked.",
	"dashboard.rejected":
		"The AIDR dashboard approval for request {requestId} could not be verified ({reason}); the action stays blocked.",
	"dashboard.requestFailed":
		"The approval request could not be sent to the AIDR dashboard ({reason}); the action stays blocked.",
	"dashboard.unavailable":
		"AIDR dashboard approvals are unavailable ({reason}); the action stays blocked.",

	// Claude Code hook banner and decision reasons.
	"hook.timeout.message":
		"Singularity AIDR could not finish inspecting this tool call in time, so it was blocked. Try again; if this keeps happening, run `aidr doctor` in your own terminal.",
	"hook.timeout.reason": "Singularity AIDR inspection timed out",
	"hook.inspectionFailed.message":
		"Singularity AIDR could not inspect this tool call, so it was blocked. Try again; if this keeps happening, run `aidr doctor` in your own terminal.",
	"hook.inspectionFailed.reason": "Singularity AIDR inspection unavailable",
	"hook.tooLarge.message":
		"Singularity AIDR could not inspect this tool call because its input is larger than the {bytes}-byte inspection limit, so it was blocked. Split the work into smaller steps.",
	"hook.tooLarge.reason": "Singularity AIDR input too large to inspect",
	"hook.malformed.message":
		"Singularity AIDR blocked this command: it is malformed (not a string or argv, or it contains NUL or invalid UTF-8 text) and cannot be inspected reliably.",
	"hook.malformed.reason": "Singularity AIDR malformed command",
	"hook.releaseKeyMissing.message":
		"Singularity AIDR blocked this tool call: the release key that proves its installed files are genuine is not set up, so it cannot trust its own rules. Every tool call is blocked until it is. Run 'aidr setup' once (or 'aidr setup --release-key <file.pem>' for a manual install).",
	"hook.redacted":
		"🛡️ Singularity AIDR redacted sensitive data from this tool call before it ran. {reason}",
	"hook.sessionScanTimeout":
		"Singularity AIDR could not finish scanning installed plugins in time; the plugin scan result is unavailable. Tool calls are still inspected.",
	"hook.sessionStartFailed":
		"Singularity AIDR protection failed to start; the session is not protected.",
	"hook.sessionStartIntegrity":
		"Singularity AIDR cannot verify its own installation ({cause}), so every tool call in this session is blocked until it is fixed. Ask your IT admin to run `aidr doctor`.",
	"hook.sessionStartNoKey":
		"Singularity AIDR cannot verify its own installation (release verification key missing), so every tool call in this session is blocked until it is fixed. Ask your IT admin to run: aidr setup --release-key <key.pem> (details: aidr doctor)",

	// Release integrity failures: the connector blocks every call until an
	// administrator fixes the installation.
	"integrity.noKey.message":
		"Singularity AIDR blocked this action because it cannot verify its own installation (release verification key missing). Nothing runs until this is fixed. Ask your IT admin to run: aidr setup --release-key <key.pem> (details: aidr doctor)",
	"integrity.failed.message":
		"Singularity AIDR blocked this action because it cannot verify its own installation ({cause}). Nothing runs until this is fixed. Ask your IT admin to reinstall Singularity AIDR from a signed release (details: aidr doctor)",
	"integrity.reason":
		"Singularity AIDR cannot verify its own installation; every action is blocked",
	"integrity.agent": "For the AI agent: do not try to fix this yourself; tell the user.",
	"integrity.cause.revoked": "this version was withdrawn by your organisation",
	"integrity.cause.signature": "its release signature is missing or invalid",
	"integrity.cause.files": "its files were changed or are missing",
	"integrity.cause.io": "its files could not be read",
	"init.failed.message":
		"Singularity AIDR could not start ({code}), so every tool call is blocked until this is fixed. Ask your IT admin to run `aidr doctor`.",
	"prompt.notSent.uninspected":
		"🛡️ Singularity AIDR could not inspect this prompt for secrets, so it was not sent. Try again; if this persists, run `aidr status`.",
	"prompt.sent.uninspected":
		"Singularity AIDR could not inspect this prompt for secrets; it was sent without prompt protection.",
	"prompt.notSent.timeout":
		"🛡️ Singularity AIDR could not finish inspecting this prompt in time, so it was not sent. Shorten the prompt or split it up and try again.",
	"prompt.sent.timeout":
		"Singularity AIDR could not finish inspecting this prompt in time; it was sent without being fully inspected for secrets or personal data.",
	"prompt.notSent.policy":
		"🛡️ Singularity AIDR could not verify your organization's data-loss prevention policy, so this prompt was not sent.",

	// Session-start banners (core format).
	"session.updateAvailable":
		"⬆️  Update available: v{current} → v{latest} (https://github.com/singularityrd/aidr)",
	"session.updateAvailableInstaller":
		"⬆️  Singularity AIDR v{latest} is available (you have v{current}). To install it, run: aidr update",
	"session.updateInstalling":
		"⬆️  Singularity AIDR v{latest} is available (you have v{current}) and is being installed in the background. Check with: aidr update --check",
	"session.policy.cached": "{policy} cached, {seconds}s left",
	"session.policy.expired": "{policy} cache expired",
	"session.policy.expiredAge": "{policy} cache expired, {seconds}s old",
	"session.policy.invalid": "cache invalid",
	"session.policy.defaultName": "policy",
	"session.clean": "🛡️ Singularity AIDR v{version} ✅ No threats found",
	"session.disabled": "Singularity AIDR v{version} - Disabled ({reason})",
	"session.localOnly":
		"Singularity AIDR v{version} - Local protection ACTIVE (managed features unavailable: {reason})",
	"session.label.policy": "Policy",
	"session.label.plugin": "Plugin",
	"session.label.threat": "Threat",
	"session.label.severity": "Severity",
	"session.label.artifact": "Artifact",
	"session.label.source": "Source",
	"session.label.finding": "Finding",
	"session.label.reason": "Reason",
	"session.label.open": "Open",
	"session.label.code": "Code",
	"session.label.expires": "Expires",
	"session.header.threatDetected": "Threat Detected",
	"session.header.reviewRequired": "Review Required",
	"session.header": "🛡️ Singularity AIDR v{version} — {label}",
	"session.finding.block": "Block recommendation; review or disable this plugin",
	"session.finding.review": "Review recommended",
	"session.moreFindings": "   ... and {count} more findings",
	"session.rulesIncompleteBanner":
		"⚠️ Threat rules incomplete — protection degraded ({count} rule file(s) missing or unverified).",
	"session.check.urlReputation": "URL reputation",
	"session.check.fileReputation": "File reputation",
	"session.check.pluginFiles": "Plugin file inspection",
	"session.check.incompletePaths": "⚠️ {label} was incomplete for {count} path(s).",
	"session.check.unverifiedItems": "⚠️ {label} was not verified for {count} item(s).",
	"session.mcp.unusableServers": "{count} server entries were unusable",
	"session.mcp.unreadableSources": "{count} source(s) could not be read at all",
	"session.mcp.coverageWarning": " Inventory coverage is {coverage}, not complete.",
	"session.mcp.inventory":
		"MCP inventory: {servers} configured, {risky} with risk indicators, {invalid} unreadable sources, {unverified} with unverified tool manifests.{coverageWarning}{gapNote} Configuration discovery does not verify server trust.",
	"session.mcp.coverageGaps": "MCP tool-manifest coverage gaps:",
	"session.mcp.moreGaps": "  ... and {count} more coverage gaps",
	"session.rulesIncomplete": "⚠️ Threat {message}. {reason}",
	"session.infrastructure": "AI infrastructure policy assessment: {assessment}.",
	"session.enrollmentRepair":
		"Enrollment could not be confirmed locally. An operator must settle the enrollment outcome and revoke any affected key in the control plane, then start fresh pairing and approve it in the browser. Preserve the installation ID and tenant; do not reuse the previous authorization code.",
	"session.activate": "To activate Singularity AIDR:",
} as const;

export type MessageKey = keyof typeof en;
