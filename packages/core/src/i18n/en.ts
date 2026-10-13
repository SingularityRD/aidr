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

	// Block / ask messages handed to the host (core guard).
	"block.deny.headline": "Singularity AIDR blocked this action.",
	"block.line.severity": "Severity: {severity}",
	"block.line.rule": "Rule: {rule}",
	"block.line.category": "Category: {category}",
	"block.line.reason": "Reason: {reason}",
	"block.line.artifacts": "Artifacts: {artifacts}",
	"block.line.response": "Response: {response}",
	"block.response.failed": "response action(s) failed: {failures} - nothing was preserved",
	"block.response.rollback": "rollback: restored {target} from snapshot {snapshot}",
	"block.response.preserved": "{action}: preserved a copy of {target} at {where}",
	"block.response.snapshot": "snapshot {snapshot}",
	"block.response.vault": "(vault)",
	"block.response.unknownSnapshot": "(unknown)",
	"block.configUnreadable":
		"Singularity AIDR could not read its configuration, so this action was blocked instead of being offered for approval.",
	"ask.headline":
		"Singularity AIDR flagged this action and blocked it pending explicit user approval.",
	"ask.reference": 'Approval reference: actionId: "{actionId}"',
	"ask.agentInstructions":
		"You cannot approve this action yourself and no tool available to you can approve it.\nApproval is an out-of-band, human-only action. Report the reference above to the user and\nstop here: do NOT retry this tool call and do NOT try to work around the block. The action\nstays blocked until the user approves it out of band or permanently allowlists the artifact.",
	"ask.user.dashboardOnly": "(For the user: only an AIDR dashboard approval can release it.)",
	"ask.user.notRecorded":
		"(For the user: this ask could NOT be recorded for operator approval — operator approvals\nare disabled or the approval store is unavailable, so `aidr approve` cannot release it.\nRun `aidr doctor` in your own terminal to see why.)",
	"ask.user.cli":
		"(For the user: review it with `aidr pending` and approve it with `aidr approve <actionId>`\nin your own terminal; the approval covers one retry of this exact call for 15 minutes.)",
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
	"hook.label.threat": "Threat",
	"hook.label.severity": "Severity",
	"hook.label.rule": "Rule",
	"hook.label.artifact": "Artifact",
	"hook.label.source": "Source",
	"hook.label.action": "Action",
	"hook.action.blocked": "Blocked",
	"hook.action.requiresConfirmation": "Requires confirmation",
	"hook.ask.header": "🛡️ Singularity AIDR: Suspicious Activity Detected",
	"hook.reason.threatBlocked": "🛡️ Singularity AIDR: Threat Blocked",
	"hook.reason.profileBlocked": "🛡️ Singularity AIDR: Blocked by agent permission profile",
	"hook.reason.operatorHold": "🛡️ Singularity AIDR: blocked pending operator approval",
	"hook.reason.dashboardRequired": "🛡️ Singularity AIDR: approval required in the AIDR dashboard",
	"hook.dashboardOnlyNotice": "Only an AIDR dashboard approval can release this action.",
	"hook.timeout.message":
		"Singularity AIDR could not finish inspecting this tool call in time. The action was blocked.",
	"hook.timeout.reason": "Singularity AIDR inspection timed out",
	"hook.inspectionFailed.message":
		"Singularity AIDR could not inspect this tool call. The action was blocked.",
	"hook.inspectionFailed.reason": "Singularity AIDR inspection unavailable",
	"hook.tooLarge.message":
		"Singularity AIDR could not inspect this tool call: its input exceeded the {bytes}-byte inspection limit. The action was blocked.",
	"hook.tooLarge.reason": "Singularity AIDR input too large to inspect",
	"hook.malformed.message":
		"Singularity AIDR blocked this command: it is malformed (not a string or argv, or it contains NUL or invalid UTF-8 text) and cannot be inspected reliably.",
	"hook.malformed.reason": "Singularity AIDR malformed command",
	"hook.redacted":
		"🛡️ Singularity AIDR redacted sensitive data from this tool call before it ran. {reason}",
	"hook.sessionScanTimeout":
		"Singularity AIDR could not finish scanning installed plugins in time; the plugin scan result is unavailable. Tool calls are still inspected.",
	"hook.sessionStartFailed":
		"Singularity AIDR protection failed to start; the session is not protected.",
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
