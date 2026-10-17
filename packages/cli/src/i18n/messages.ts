/**
 * CLI output catalog (en/tr) for the commands an administrator runs first:
 * `aidr setup`, `aidr status`, `aidr doctor`, `aidr verify`, `aidr pending`,
 * `aidr approve` and `aidr simulate`. `{name}` marks a parameter.
 *
 * Turkish says "yapay zekâ aracı" for an agent host (Claude Code, Codex, …),
 * never "ajan ana makinesi", and avoids internal terms.
 *
 * Field labels such as `actionId:` and the confirmation word `approve` stay
 * English in every locale: users copy them, and scripts parse them.
 */
export const CLI_EN = {
	"status.title": "Singularity AIDR — installation diagnostics",
	"status.passed": "passed",
	"status.failed": "FAILED",
	"status.detection": "Detection self-test: {result}; {rules} rules{detail}.",
	"status.configuration": "Configuration: {state}; mode: {mode}{note}",
	"status.configValid": "valid",
	"status.configDefaults": "defaults",
	"status.configInvalid": "INVALID (a restrictive fallback is enforced)",
	"status.registrationDetected": "registration/package detected",
	"status.managedInactive":
		"Managed: inactive (mode: {mode}); enforcement is local and no control plane is used.",
	"status.managedEnabled": "enabled",
	"status.managedDisabled": "disabled",
	"status.endpointConfigured": "configured",
	"status.endpointMissing": "missing",
	"status.managed":
		"Managed: {state}; endpoint {endpoint}. Connectivity and fleet adoption have not been checked.",
	"status.notEnrolled":
		"! This device is NOT enrolled: local protection is on, but it receives no company policy and reports nothing. Run `aidr assistant` and connect to your company (or ask IT for an enrollment code).",
	"status.telemetry":
		"Telemetry queue: {state}; {pending} event(s) undelivered, {lost} lost{oldest}{suffix}",
	"status.telemetryOldest": ", oldest {seconds}s",
	"status.telemetryUnreadable": " — at least one queue could not be read.",
	"status.telemetryEnd": ".",
	"status.audit":
		"Audit log: {failures} append(s) could not be written, {drops} rotation(s) dropped the oldest file.",
	"status.auditUnknownDrops": "an unknown number of",
	"status.auditLastError": " Last error: {error}.",
	"status.ready":
		"Local installation checks passed. Confirm that your AI tools really run the hooks with: aidr verify",
	"status.attention":
		"Installation requires attention: see the lines above, or run 'aidr doctor' for one line per problem.",
	"status.disclaimer": "A package or hook registration does not prove that the host executes it.",
	"status.verdictPrefix": "Verdict:",
	"status.verdictProtected": "protected: {hosts}",
	"status.verdictRestart": "restart if open before {since}: {hosts}",
	"status.verdictManual": "needs a manual step: {steps}",
	"status.verdictNone":
		"no supported AI tool is registered; install Claude Code, Cursor, VS Code, Codex, OpenCode or OpenClaw, then run 'aidr setup'",
	"status.verdictVerify": "then run 'aidr verify'",
	"verify.title":
		"Singularity AIDR — host hook canary (the canary is passed as data and never executed)",
	"verify.pass": "PASS",
	"verify.fail": "FAIL",
	"verify.skip": "SKIP",
	"verify.notRegistered": "not registered",
	"verify.summaryPass": "Every exercised AIDR hook denied the canary ({count}).",
	"verify.summaryFail":
		"{count} AIDR hook(s) did NOT deny the canary: tool calls of that host may run uninspected.",
	"verify.summaryNone":
		"No AIDR hook entry point could be exercised from here. Run 'aidr status' for the next step.",
	"verify.inProcess":
		"in-process plugin; it runs only inside the host. Restart it, then ask the agent to run a harmless command such as 'echo aidr-canary' to confirm it loads.",
	"verify.pluginOnly":
		"registered as a Claude Code plugin; its hooks run only inside Claude Code (check /plugin).",
	"verify.noEntry": "registered, but no AIDR hook command was found to exercise in {file}.",
	"releaseKey.added": "✓ Release key {fingerprint} set up (from {source}).",
	"releaseKey.present": "✓ Release key {fingerprint} already set up.",
	"releaseKey.replaced":
		"✓ Release key {fingerprint} set up (from {source}); it replaced {previous}.",
	"releaseKey.wouldAdd": "Would set up the release key {fingerprint} (from {source}).",
	"releaseKey.kept":
		"⚠ A different release key is already set up ({previous}); it was kept. The key from {source} ({fingerprint}) was NOT added. If the operator trusts it, rerun: aidr setup --force",
	"releaseKey.missing":
		"⚠ No release key is set up. This release build blocks every tool call until one is. Run: aidr setup --release-key <file.pem> (the release public key from your Singularity AIDR administrator).",
	"releaseKey.invalid": "The release key was refused: {reason}",
	"releaseKey.confirm": "  Release key: {file} ({fingerprint})",

	"approvals.artifactsTruncated":
		"artifacts:  showing {shown} of {total} (truncated); the approval covers all {total}",
	"approvals.asked": "asked:      {createdAt} (approvable until {expiresAt})",
	"approvals.integrityFailed": "integrity:  FAILED — this record cannot be approved",
	"approvals.hostDialogConnector":
		"connector:  {connector}   tool: {tool}   (answered in the host's own dialog)",
	"approvals.disabled": "Operator approvals are disabled.",
	"approvals.none": "No Singularity AIDR asks are waiting for approval.",
	"approvals.waiting": "{count} ask(s) waiting for an operator decision (newest first):",
	"approvals.howToApprove":
		"Approve one retry with: aidr approve <id>  (the first 8 characters of the id are enough)",
	"approvals.howToPick":
		"Or run 'aidr approve' alone in your terminal to choose from a numbered list.",
	"approvals.hostDialogHeader":
		"{count} recent ask(s) answered in the host's own dialog (informational; not approvable here):",
	"approvals.hostDialogRoute":
		'To route these through `aidr approve` instead, set operator_approvals.mode to "operator".',
	"approvals.storeUnreadable": "Could not read the approval store: {error}",
	"approvals.answeredInHost":
		"This ask was answered in the host's own confirmation dialog (operator_approvals.mode: host_dialog). It is listed for information only and cannot be approved here.",
	"approvals.notFound":
		"No pending Singularity AIDR ask has this id (it may have expired or already been approved). Run `aidr pending` to list open asks.",
	"approvals.integrityRejected":
		"This pending ask failed integrity verification (the record was edited or the approval key changed). It was not approved; have the agent retry to record a fresh ask.",
	"approvals.badTtl": "--ttl must be a whole number of minutes (1-1440).",
	"approvals.notApproved": "Not approved: {reason}",
	"approvals.notApprovedCode": "Not approved ({code}): {reason}",
	"approvals.allowlistPermitted":
		"The agent will also be allowed to add these artifacts to the permanent allowlist once.",
	"approvals.allowlistNotPermitted": "The approval does not allow the agent to allowlist anything.",
	"approvals.promptTitle": "Singularity AIDR — approve a blocked agent action",
	"approvals.promptScope": "This allows ONE retry of exactly this call within {minutes} minute(s).",
	"approvals.approved": "Approved. Ask the agent to retry within {minutes} minutes.",
	"approvals.approvedDetail":
		"(id {actionId}…, valid until {expiresAt}; one retry of the same call only)",
	"approvals.badId":
		"Give the id shown by 'aidr pending', or at least its first 8 characters (0-9, a-f).",
	"approvals.ambiguous":
		"{count} waiting actions start with {prefix}; type more characters of the id.",
	"approvals.fullIdForYes":
		"--yes needs the full 64-character id; a short id is accepted only when you confirm in a terminal.",
	"approvals.idRequired":
		"Name the action to approve: aidr approve <id> (see 'aidr pending'). Picking from a list needs an interactive terminal.",
	"approvals.pickTitle": "Waiting for your decision (newest first):",
	"approvals.pickPrompt": "Number to review (1-{count}), or Enter to cancel: ",
	"approvals.pickNone": "Not approved: no action was chosen.",

	"confirm.type": 'Type "{word}" to confirm: ',
	"confirm.notConfirmed": "Not confirmed; nothing was changed.",
	"confirm.inputEnded": "Confirmation input ended.",
	"confirm.protectionLocked":
		"Refused: your organisation's machine policy locks Singularity AIDR protection (protection_locked), so local allowlist entries, exceptions, weakening settings and removal are not available here. Ask your IT or security team.",
	"confirm.yesNeedsEnv":
		"--yes is honoured only when {env} is also set by the operator. Run the command in an interactive terminal to confirm it by hand.",
	"confirm.needsTerminal":
		"This operator-only command needs an interactive terminal for confirmation. For operator automation pass --yes with {env}.",
	"confirm.nonInteractive": "Confirmed non-interactively (--yes).",

	"mode.local": "local",
	"mode.managed": "managed",
	"mode.releaseBuildNote": "release build: always managed",

	"integrity.fixCommand": "aidr setup --release-key <file.pem>",
	"integrity.ok": "Release verification key: {count} key(s) configured; signatures are checked.",
	"integrity.missing":
		"Release verification key MISSING: Singularity AIDR cannot verify its own installation and may block every tool call. Fix: {fix}",
	"integrity.invalid":
		"Release verification key unusable ({invalid} of {total} is not a public key). Fix: {fix}",
	"integrity.digestsOnly":
		"Release verification key not set: file digests are checked, signatures are not (development build).",
	"integrity.off": "Release signature check: off (development build).",
	"integrity.missingWhy":
		"Without the key a release build cannot prove its connector files are the signed release; an unsigned or unverifiable bundle is blocked rather than trusted. Ask your IT admin for the key file and run: {fix}",

	"doctor.title": "Singularity AIDR doctor",
	"doctor.version": "Singularity AIDR core {version}.",
	"doctor.configFile": "Configuration file: {path}",
	"doctor.configDefaults": "No configuration file; local defaults apply.",
	"doctor.configInvalid": "Configuration is invalid; a restrictive fallback is enforced.",
	"doctor.configManagedIncomplete": "Mode is managed, but no control-plane endpoint is enabled.",
	"doctor.configMode": "Mode: {mode}.",
	"doctor.detectionOk": "{rules} threat rules loaded; detection self-test passed.",
	"doctor.detectionFailed": "Detection self-test failed: {reason} ({rules} rules).",
	"doctor.detectionCrashed": "Detection self-test crashed: {error}",
	"doctor.connectorsOk": "Hooks registered for: {hosts}.",
	"doctor.connectorsBroken": "Connector problems: {hosts}.",
	"doctor.connectorsUnprotected":
		"AI tools found ({hosts}) but no AIDR hook is registered. Run `aidr setup`.",
	"doctor.connectorsNone": "No supported AI tool and no AIDR hook was found.",
	"doctor.connectorsPartial":
		"Hooks registered for: {hosts}. Also found without AIDR: {unprotected}. Run `aidr setup` to protect them.",
	"doctor.dlpInvalid":
		"Detector (DLP) policy invalid for {runtimes}; those connectors block every call.",
	"doctor.dlpEnabled": "DLP enabled for {runtimes}.",
	"doctor.dlpItemLocal": "{runtime} (local {path})",
	"doctor.dlpItemSigned": "{runtime} (signed managed bundle)",
	"doctor.dlpLocalPending":
		"DLP policy loaded from local dlp-policy.json (unsigned); it applies once a connector hook is registered.",
	"doctor.dlpLocalFile": "Local DLP policy file: {path}",
	"doctor.dlpLocalInvalid": "DLP is not active: the local DLP policy is INVALID and NOT enforced.",
	"doctor.dlpLocalInvalidNote":
		"Local DLP policy {path} is INVALID ({reason}) and is NOT enforced.",
	"doctor.dlpLocalIgnored":
		"Local DLP policy {path} is ignored in {mode} mode; only signed bundles apply.",
	"doctor.dlpNoneLocal":
		"DLP is not active: no signed detector policy is installed and no local DLP policy was found.",
	"doctor.dlpNoneManaged":
		"DLP is not active: managed mode requires a signed detector policy from the control plane.",
	"doctor.profilesLocalInvalid":
		"Local agent profiles are invalid and were NOT loaded; run `aidr profile validate`.",
	"doctor.profilesLocalInvalidNote": "{path}: {reason}",
	"doctor.profilesManagedInvalid":
		"Managed agent profiles are invalid for {runtimes}; those connectors deny every call.",
	"doctor.profilesLocalCount": "{count} local profile(s)",
	"doctor.profilesManagedFor": "managed profiles for {runtimes}",
	"doctor.profilesSummary": "Agent permission profiles: {parts}{diagnostics}.",
	"doctor.profilesDiagnostics": " ({count} diagnostic(s); see `aidr profile list`)",
	"doctor.profilesNone": "No agent permission profiles configured (threat detection only).",
	"doctor.keyNotCreated": "not created yet",
	"doctor.keyOsVault": "in the OS vault ({store})",
	"doctor.keyEncryptedFile": "in the machine-bound encrypted file store",
	"doctor.keyPlainFile": "in a PLAIN FILE (any program of this user can read it)",
	"doctor.keyPlainFileWarning":
		"The approval key is a plain file (explicit key_storage=file opt-in). Any process of this user, including a compromised agent with shell access, can read it and forge approvals, and the single-use ledger is a file too. Prefer the OS credential vault (remove the opt-in).",
	"doctor.keyEncryptedFileNote":
		"No OS credential vault answers on this host, so the approval key and single-use ledger are AES-256-GCM sealed in owner-only files under ~/.singularity-aidr/sealed with a machine-bound key. Like libsecret, this does not stop code running as the same user; run the agent under a separate account for that (docs/configuration.md#key-custody).",
	"doctor.approvalsPending": "{count} ask(s) pending operator approval{unverified}",
	"doctor.approvalsUnverified": ", {count} failing integrity verification",
	"doctor.approvalsSummary": "{pending}; approval key {where}.",
	"doctor.approvalsDisabled":
		"Approvals DISABLED: blocked actions stay blocked and cannot be approved ({pending}).",
	"doctor.approvalsUnusable":
		"Approval store unusable; blocked actions cannot be approved until it is repaired.",
	"doctor.storePath": "Approval store: {path}",
	"doctor.environmentUnchecked":
		"AI tool settings could not be checked. This is not a clean result.",
	"doctor.environmentClean":
		"AI tool settings: no unsafe autonomy setting or exposure found by the static checks.",
	"doctor.environmentFindings":
		"AI tool settings: {count} finding(s), {serious} high or critical ({ids}). Run `aidr discover --agents`.",
	"doctor.environmentUnreadable": "{count} configuration file(s) could not be parsed.",
	"doctor.auditDisabled": "Audit logging is disabled in the configuration.",
	"doctor.noVerdict": "No verdict recorded yet; run `aidr verify` to confirm enforcement.",
	"doctor.amsiAvailable": "AMSI malware scanning: available ({backend}).",
	"doctor.amsiSlowFallback":
		"AMSI malware scanning runs on the PowerShell fallback (about 0.3 to 0.5 s per tool call): the native koffi backend is missing from this installation. Reinstall with the official Windows installer.",
	"doctor.amsiUnavailable":
		"AMSI malware scanning cannot run on this computer, so content is NOT scanned by AMSI (local threat rules still apply). See --verbose for the reason.",
	"doctor.lastVerdict": "Last verdict: {verdict} for {tool} at {time}.",
	"doctor.auditUnreadable": "Audit log unreadable.",
	"doctor.clockOk": "Clock: within {seconds} s of the control plane.",
	"doctor.clockDrift":
		"Clock is {seconds} s {direction} the control plane. Enable time synchronisation (NTP / Windows Time).",
	"doctor.clockSkewed":
		"Clock is {seconds} s {direction} the control plane: signed licences, approvals and enrollment tokens can be rejected. Synchronise the clock (NTP / Windows Time) now.",
	"doctor.clockAhead": "ahead of",
	"doctor.clockBehind": "behind",
	"doctor.clockUnchecked":
		"Clock: not compared; the control plane did not answer with a time ({reason}). This is not a clean result.",
	"doctor.clockWhy":
		"Licence expiry and grace, approval tokens, enrollment codes, device sessions and TLS certificates are all checked against this machine's clock. Keep every endpoint and the control-plane host on the same NTP source (docs/operations/onprem-runbook.md#time-synchronisation).",
	"doctor.footerOk":
		"No blocking problems found. Confirm that your AI tools really run the hooks with: aidr verify",
	"doctor.footerFail": "Problems found (✗). Fix them and re-run `aidr doctor`.",
	"doctor.verboseHint": "Details for each line: aidr doctor --verbose",

	"setup.title": "Singularity AIDR setup",
	"setup.titleDryRun": " (dry run — nothing will be changed)",
	"setup.nothingChanged": "Nothing was changed.",
	"setup.detecting": "Looking for AI tools...",
	"setup.hostsFound": "AI tools found: {hosts}",
	"setup.noHosts":
		"No supported AI tool found in this home directory (Claude Code, Cursor, VS Code, Codex, OpenCode, OpenClaw).",
	"setup.skipConfig": "Skipping config creation (dry run).",
	"setup.creatingConfig": "Creating config...",
	"setup.configReused": "Configuration already in place — no changes were needed: {path}",
	"setup.configCreated": "Config: {path}",
	"setup.loadingRules": "Loading threat rules...",
	"setup.noRules":
		"No threat rules could be loaded. Detection would not be active - refusing to report success.",
	"setup.selfTestFailed": "Detection self-test failed: {reason}",
	"setup.detectionOk": "Detection works: {rules} rules loaded, self-test passed.",
	"setup.noInstallDone": "Setup finished (connector install skipped: --no-install).",
	"setup.nextSteps": "Next steps:",
	"setup.noInstallStep1":
		"Install the connector below — until you do, tool calls are NOT inspected",
	"setup.noInstallStep2": "Then check: aidr status   and   aidr verify",
	"setup.planning": "Planning connector installs...",
	"setup.installing": "Installing connectors...",
	"setup.connectors": "Connectors:",
	"setup.action.alreadyInstalled": "already installed",
	"setup.action.installed": "installed",
	"setup.action.updated": "updated",
	"setup.action.wouldInstall": "would install",
	"setup.action.wouldUpdate": "would update",
	"setup.action.manual": "manual step needed",
	"setup.action.failed": "FAILED",
	"setup.action.notDetected": "not detected",
	"setup.dryRunDone": "Dry run: no file was written and no host command was run.",
	"setup.company.confirmTitle": "Singularity AIDR — connect this computer to your company",
	"setup.company.confirmAddress": "Company address: {endpoint}",
	"setup.company.withCode": "Enrollment code: entered in the installer",
	"setup.company.withoutCode":
		"Enrollment code: none (approve this computer in your company's Singularity AIDR console when an AI tool starts)",
	"setup.company.confirmEffect":
		"This computer will send its protection events to that address and follow your company's policy. Protection on this computer stays on either way.",
	"setup.company.applied":
		"Connected to your company ({endpoint}). The connection completes the next time an AI tool starts.",
	"setup.company.appliedApprove":
		"Company address set ({endpoint}). The next time an AI tool starts, it shows a code and a link: approve this computer there.",
	"setup.company.alreadyConnected":
		"This computer is already connected to {endpoint}. The company details from the installer were not used and have been deleted.",
	"setup.company.notConfirmed":
		"The company connection from the installer was not applied: {reason} It stays saved; run aidr setup in a terminal to apply it.",
	"setup.company.invalid":
		"The company connection saved by the installer could not be used ({reason}) and was deleted. Install again with the details from your IT team.",
	"setup.company.expired":
		"The company connection saved by the installer is older than 3 days and was deleted. Ask your IT team for a new enrollment code.",
	"setup.company.failed":
		"The company connection could not be saved: {reason}. Protection on this computer is not affected.",
	"setup.company.notDeleted":
		"The installer's company connection file could not be deleted ({reason}). Delete installer-enrollment.json in the .singularity-aidr folder of your user folder.",
	"setup.company.fromPacket": "Set by the installer for {customer}",
	"setup.packet.applied": "Customer: {customer} ({id}). License {state}; updates until {date}.",
	"setup.packet.wouldApply":
		"Would apply the customer packet for {customer} ({id}); license {state}, updates until {date}.",
	"setup.packet.refused":
		"The customer packet {path} was refused ({reason}) and was not used. Local detection is installed anyway. Ask Singularity R&D for a new installer.",
	"setup.packet.recordFailed":
		"The customer license could not be saved ({reason}). New update packs cannot be checked against it; local detection is not affected.",
	"setup.packet.expired":
		"The license has ended: new updates stopped on {date}. Local detection keeps working with the rules already installed.",
	"setup.packet.notYetValid":
		"The license starts on {date}; updates are accepted from then on. Local detection works now.",
	"setup.packet.sensitivity": "Sensitivity set to {level} by the customer packet.",
	"setup.packet.licensingKeys":
		"Your company's deployment signing keys from the customer packet are trusted ({count}).",
	"setup.machinePolicy.found": "Machine policy set by your administrator: {source}",
	"setup.machinePolicy.refused":
		"The machine policy {source} was refused ({reason}) and was not used. Local protection continues; tell your IT team.",
	"setup.machinePolicy.connected":
		"Connected to your company ({endpoint}) by the machine policy. The connection completes the next time an AI tool starts.",
	"setup.machinePolicy.connectedApprove":
		"Company address set by the machine policy ({endpoint}). The next time an AI tool starts, it shows a code and a link: approve this computer there.",
	"setup.machinePolicy.wouldConnect": "Would connect to {endpoint} as the machine policy says.",
	"setup.machinePolicy.alreadyConnected": "Connected to {endpoint} as the machine policy says.",
	"setup.machinePolicy.handoffIgnored":
		"The company connection saved by the installer was not used: the machine policy decides the company connection on this computer.",
	"setup.machinePolicy.offline.keep_enforcing_local":
		"If the company server cannot be reached, protection on this computer keeps working locally.",
	"setup.machinePolicy.offline.block_after_grace":
		"If the company server cannot be reached for longer than the offline grace period, AI tool calls on this computer are blocked.",
	"customer.state.active": "active",
	"customer.state.grace": "in its grace period",
	"customer.state.expired": "ended",
	"customer.state.not_yet_valid": "not started yet",
	"customer.status": "Customer: {customer} ({id}); license {state}. Updates until {date}.",
	"customer.statusExpired":
		"Customer: {customer} ({id}); license ended. Updates stopped on {date}; detection continues with the rules already installed.",
	"customer.statusRefused":
		"Customer packet: refused ({reason}); not used. Local detection is not affected. Ask Singularity R&D for a new installer.",
	"setup.complete": "✅ Setup complete!",
	"setup.registeredFor": "Registered for: {hosts} (not yet verified inside the AI tool).",
	"setup.incomplete": "⚠ Setup finished, but protection is NOT yet active for every AI tool:",
	"setup.incompleteDetail":
		"tool calls of an AI tool without a registered connector are NOT inspected.",
	"setup.unprotected": "Not protected: {hosts}",
	"setup.dryRunNext": "Run without --dry-run to apply.",
	"setup.verifyNext": "Next: restart your AI tools, then run: aidr verify",

	"simulate.title": "Singularity AIDR — Attack Simulation Self-Test",
	"simulate.modeLine": "Mode: {mode}   Sensitivity: {sensitivity}",
	"simulate.colCategory": "Category",
	"simulate.colDetected": "Detected",
	"simulate.colRate": "Rate",
	"simulate.colBenignFp": "Benign FP",
	"simulate.total": "TOTAL",
	"simulate.na": "n/a",
	"simulate.score": "Overall detection score: {score}%",
	"simulate.fpRate": "Benign false-positive rate: {rate}%",
	"simulate.notCounted": "Not counted (uninspected / disabled): {count}",
	"simulate.missesTitle":
		"Misses (malicious fixtures the product did not flag to the expected level):",
	"simulate.missLine": "expected >= {expected}, got {actual}",
	"simulate.fpTitle": "Benign twins that were incorrectly flagged:",
	"simulate.fpLine": "flagged as {actual}",
	"simulate.abortedTitle": "Uninspected / not scored:",
	"simulate.verdictNone": "FAIL — no fixture could be scored, so nothing was verified",
	"simulate.verdictPass": "PASS — score {score}% >= minimum {min}%",
	"simulate.verdictFail": "FAIL — score {score}% < minimum {min}%",
	"simulate.pass": "PASS",
	"simulate.fail": "FAIL",
	"simulate.category.injection": "Prompt injection",
	"simulate.category.exfiltration": "Data exfiltration",
	"simulate.category.destructive": "Destructive commands",
	"simulate.category.encoding": "Obfuscation / encoding",
	"simulate.category.supplyChain": "Supply chain",
	"simulate.category.mcp": "MCP tool poisoning",
	"simulate.category.selfDefense": "Self-defense",
	"simulate.category.privacy": "Personal data / secrets",
	"simulate.badFormat": "Unknown --format: {format}. Use table, json or html.",
	"simulate.failed": "aidr simulate failed: {error}",
	"simulate.wrote": "Wrote {format} report to {path}",
	"simulate.html.title": "AIDR Attack Simulation Report",
	"simulate.html.heading": "AI Agent Security — Attack Simulation Report",
	"simulate.html.sub":
		"Defensive self-test of the local detection engine. Generated {generated} · mode: {mode} · sensitivity: {sensitivity}",
	"simulate.html.scoreCard": "Detection score",
	"simulate.html.fpCard": "Benign false positives",
	"simulate.html.result": "Result",
	"simulate.html.misses": "Misses",
	"simulate.html.fps": "False positives",
	"simulate.html.noMisses":
		"No misses: every counted fixture was flagged to at least its expected level.",
	"simulate.html.noFp": "No false positives: every benign twin was allowed.",
	"simulate.html.case": "Case",
	"simulate.html.expected": "Expected",
	"simulate.html.actual": "Actual",
	"simulate.html.flaggedAs": "Flagged as",
	"simulate.html.description": "Description",
	"simulate.html.footer":
		"This report reflects locally shipped detection rules evaluated against defanged test fixtures. No commands were executed and no network requests were made during the self-test.",
	"status.unprotectedNone": "AI tools without Singularity AIDR protection: none found.",
	"status.unprotected":
		"! AI tools without Singularity AIDR protection (their commands, file changes and web requests are NOT inspected): {tools}",
	"coverage.unprotected":
		"AI tools found on this computer that Singularity AIDR does not protect: {tools}. The coverage above does not apply to them.",
	"coverage.unprotectedNone":
		"No AI tools without a Singularity AIDR connector were found on this computer.",
	"approvals.dashboardHeader": "Approval requests in the Singularity AIDR dashboard ({count}):",
	"approvals.dashboardLine": "  {requestId}  {status}  tool: {tool}  expires: {expiresAt}",
	"approvals.dashboardLink": "    {url}",
	"approvals.dashboardStatus.pending": "waiting for an administrator",
	"approvals.dashboardStatus.approved": "approved: ask the agent to run the same action again",
	"approvals.dashboardStatus.denied": "denied",
	"approvals.dashboardStatus.expired": "expired",
	"approvals.dashboardStatus.unknown": "status unknown (the dashboard could not be reached)",
	"reportFp.invalidId":
		"Give the id from the block message (8 to 64 hexadecimal characters), for example: aidr report-fp 1a2b3c4d",
	"reportFp.invalidReason": 'Unknown reason "{reason}". Use one of: {reasons}.',
	"reportFp.notFound":
		"No blocked or held action with id {id} was found in the local audit log ({path}). The log may be turned off or rotated; send the block message to your IT or security team instead.",
	"reportFp.ambiguous": "The id {id} matches {count} actions; give more characters:",
	"reportFp.found": "Action {id}: {decision} by rule {rule} ({severity}), tool {tool}, at {time}.",
	"reportFp.decision.deny": "blocked",
	"reportFp.decision.ask": "held for approval",
	"reportFp.sent":
		"Reported as a false positive (report {reportId}). Your IT or security team reviews it in the Singularity AIDR console; nothing is allowed until they add an exception.",
	"reportFp.duplicate":
		"This report was already filed (report {reportId}); nothing was filed twice.",
	"reportFp.local":
		"This computer is not connected to a Singularity AIDR console, so the report was not sent. Send the line above to your IT or security team.",
	"reportFp.failed":
		"The report could not be sent ({error}). Send the line above to your IT or security team, or try again later.",
	"reportFp.support": "Your IT or security team: {url}",
	"reportFp.dryRun": "Dry run: nothing was sent.",
	"heartbeat.none": "Heartbeat: no supported AI tool was found on this device.",
	"heartbeat.line": "  {connector}: {state} ({enforcement})",
	"heartbeat.localMode":
		"Heartbeat: local mode, so nothing was sent. Hook removal alerts need a managed (enrolled) installation.",
	"heartbeat.dryRun": "Heartbeat: dry run, nothing was sent.",
	"heartbeat.sent": "Heartbeat sent for {count} AI tool(s).",
	"heartbeat.failed":
		"Heartbeat could not be sent ({error}). The control plane raises 'agent offline' when heartbeats stop.",
	"machineHooks.noBundle":
		"machine-hooks needs the installed AIDR bundle (run it as the bundle's 'aidr', or pass --bundle-root <dir>).",
	"machineHooks.needsAdmin":
		"machine-hooks writes system-wide host policy: run it as root (Linux) or from an elevated prompt (Windows).",
	"machineHooks.bundleRefused":
		"The AIDR bundle at {root} did not verify, so no system-wide hook was registered: {problems}",
	"machineHooks.installTitle": "System-wide AIDR hooks (apply to every user of this machine):",
	"machineHooks.precedenceNote":
		'Note: if Claude Code policy also comes from server-managed settings, MDM or the HKLM registry, that source wins over files; add these hooks there or set managedSourcesBehavior to "merge" (Claude Code 2.1.242+).',
	"machineHooks.editorsNote":
		"Cursor and VS Code: set protection_locked in the AIDR machine policy so the extension refuses 'Disable protection' and restores removed hooks.",
	"machineHooks.statusRegistered":
		"  {host}: registered in {path}; other hooks blocked: {locked}; admin-only file: {tamper}",
	"machineHooks.statusAbsent": "  {host}: not registered in {path}",
	"machineHooks.lockedYes": "yes",
	"machineHooks.lockedNo": "no",
	"machineHooks.tamperYes": "yes",
	"machineHooks.tamperNo": "NO (a non-administrator can change it)",
	"machineHooks.tamperUnknown": "not measured on this platform (check the file ACL)",
	"doctor.codexTrustUntrusted":
		"Codex has not trusted the AIDR hook ({events}): Codex skips an untrusted hook without warning, so these calls are not inspected.",
	"doctor.codexTrustDisabled":
		"The AIDR Codex hook is turned off in Codex ({events}); these calls are not inspected.",
	"doctor.codexTrustRecorded":
		"Codex has a trust record for the AIDR hook ({events}); AIDR cannot recompute Codex's hash, so run /hooks once if the hook changed.",
	"doctor.codexTrustManaged":
		"The AIDR Codex hook is deployed by machine policy; Codex trusts it without review.",
	"doctor.codexTrustFix":
		"Fix: open Codex, run /hooks and trust the AIDR hooks, or have an administrator run 'aidr machine-hooks install' so Codex trusts them by policy.",
	"setup.unknownHost": "Unknown host {hosts}. Valid hosts: {valid}.",
	"setup.noneGiven": "(none)",
	"setup.failed": "Setup failed: {reason}",
	"setup.action.notSelected": "detected — not selected",
	"setup.confirmRequired":
		"This needs operator confirmation: run aidr setup in an interactive terminal and type '{word}', or for automation set AIDR_OPERATOR_NONINTERACTIVE=1 and pass --yes. Nothing was changed.",
	"setup.force.title": "Singularity AIDR — forced re-setup",
	"setup.force.effect": "The existing local configuration and CLI credential will be replaced.",
	"setup.artifacts.title": "Singularity AIDR — install connector artifacts",
	"setup.artifacts.claude": "  Claude Code plugin directory: {path}",
	"setup.artifacts.cursor": "  Cursor extension: {path}",
	"setup.artifacts.vscode": "  VS Code extension: {path}",
	"setup.artifacts.verifyOnly":
		"Install only artifacts you verified against the signed release bundle.",

	"conn.unavailable": "AIDR could not read the host registration; installation state is unknown",
	"conn.unavailableRemedy": "Check the file permissions and rerun 'aidr status' as the host user",
	"conn.machinePolicy":
		"AIDR hooks deployed by machine policy in {path}{locked}; users cannot disable them; host execution unverified",
	"conn.machinePolicyLocked": " (only managed hooks run)",
	"conn.claude.installed":
		"AIDR plugin enabled or PreToolUse handler registered; host execution unverified",
	"conn.claude.present": "~/.claude/settings.json exists but does not reference AIDR",
	"conn.claude.presentRemedy":
		"Verify the publisher-signed release bundle before extracting the Claude plugin, add the extracted directory as a marketplace, then install aidr@aidr",
	"conn.claude.none": "no ~/.claude directory or ~/.claude.json found",
	"conn.claude.installedNoSettings":
		"Claude Code is installed (~/.claude) but AIDR is not registered",
	"conn.claude.noneRemedy": "Install the AIDR plugin from the Claude Code marketplace",
	"conn.editor.installed":
		"extension package found: {packages}; activation and hook execution unverified",
	"conn.editor.present": "{label} config directory exists but no AIDR extension was found",
	"conn.editor.presentRemedy":
		"Install the VSIX, then run 'Singularity AIDR: Enable protection' from the command palette",
	"conn.editor.none": "no {label} configuration directory found",
	"conn.openclaw.installed":
		"AIDR plugin enabled in ~/.openclaw/openclaw.json; host execution unverified",
	"conn.openclaw.disabled": "AIDR plugin is registered but disabled by the OpenClaw plugin policy",
	"conn.openclaw.disabledRemedy":
		"Enable aidr-openclaw in plugins.entries and permit it in the OpenClaw allow/deny policy",
	"conn.openclaw.present": "~/.openclaw/openclaw.json exists but does not list AIDR",
	"conn.openclaw.presentRemedy":
		"Install the approved version: openclaw plugins install npm:@singularityrd/aidr-openclaw@{version} ({version} matches this CLI; confirm it against the approved release record)",
	"conn.openclaw.none": "no ~/.openclaw/openclaw.json found",
	"conn.opencode.npm": "AIDR npm plugin is listed in OpenCode config; host execution unverified",
	"conn.opencode.local": "AIDR local plugin file found: {files}; host execution unverified",
	"conn.opencode.present": "OpenCode config contains no registered AIDR plugin",
	"conn.opencode.none": "no OpenCode config directory found",
	"conn.opencode.remedy":
		"Add the approved @singularityrd/aidr-opencode version to package.json and register it in opencode.json",
	"conn.codex.toml":
		"AIDR PreToolUse handler registered in ~/.codex/config.toml; host trust and execution unverified",
	"conn.codex.lowercase":
		"config.toml uses a lower-case hooks.pre_tool_use table, which Codex parses and then IGNORES - the hook will never run",
	"conn.codex.lowercaseRemedy":
		"Rename the table to [[hooks.PreToolUse]] with a nested [[hooks.PreToolUse.hooks]] handler",
	"conn.codex.json":
		"AIDR PreToolUse handler registered in ~/.codex/hooks.json; host trust and execution unverified",
	"conn.codex.programMissing":
		"AIDR hook registered in {source}, but its program {program} cannot be found; Codex runs every call uninspected (fails open)",
	"conn.codex.programMissingRemedy":
		"Reinstall @singularityrd/aidr-codex (or the standalone bundle), then rerun 'aidr setup --host codex'",
	"conn.codex.present": "Codex directory exists but registers no AIDR hook",
	"conn.codex.presentRemedy":
		"Add [[hooks.PreToolUse]] with a command handler pointing at aidr-codex-hook",
	"conn.codex.none": "no ~/.codex configuration found",
	"conn.state.unavailable": "unavailable",
	"conn.state.runtime_present_not_installed": "runtime_present_not_installed",
	"conn.state.not_detected": "not_detected",
	"conn.state.installed_but_degraded": "installed_but_degraded",

	"install.machinePolicy":
		"AIDR hooks are deployed for every user by machine policy ({path}); the user configuration was left as is.",
	"install.bundleFailed":
		"the installed AIDR bundle at {root} failed verification: {problems}. Reinstall it.",
	"install.probeDecision": "returned {decision} for the deny canary ({detail})",
	"install.probeBenign": "denied the harmless 'ls' as well ({detail})",
	"install.backedUp": "backed up {path} to {backup}",
	"install.wrote": "wrote {path}",
	"install.ran": "ran: {command}",
	"install.wouldRun": "would run: {command}",
	"install.notOnPath": "the {cli} CLI is not on PATH.",
	"install.notAFile": "{path} is not a file.",
	"install.notObject": "{path} has a '{field}' value that is not an object; it was left untouched.",
	"install.notArray": "{path} has a '{field}' value that is not an array; it was left untouched.",
	"install.codex.tomlRegistered":
		"AIDR hook already registered in ~/.codex/config.toml; left as is.",
	"install.codex.byHand":
		"  Codex: register aidr-codex-hook by hand as shown in packages/codex/README.md.",
	"install.codex.trust1":
		"  Codex: review and trust the three AIDR hooks with /hooks. Codex drops an untrusted",
	"install.codex.trust2":
		"         hook silently (fails open), so protection starts only after trust.",
	"install.codex.jsonRegistered": "AIDR hooks already registered in ~/.codex/hooks.json.",
	"install.codex.notOnPath":
		"{hook} is not on PATH, so registering it would leave Codex running a missing hook (Codex fails open).",
	"install.codex.installPackage":
		"  Codex: install @singularityrd/aidr-codex@{version} from the private registry, then rerun 'aidr setup'.",
	"install.codex.wouldRegister":
		"would register {hook} ({binary}) for PreToolUse, UserPromptSubmit and PostToolUse in {path}.",
	"install.codex.probeFailed": "the bundle's Codex hook {reason}; registration unchanged.",
	"install.codex.registered": "registered {hook} in {path}.",
	"install.codex.notSeen": "wrote {path} but Codex detection does not see the hook ({detail}).",
	"install.opencode.jsonc":
		"OpenCode is configured through opencode.jsonc, which AIDR does not rewrite (its comments would be lost).",
	"install.opencode.jsoncStep1": '  OpenCode: add "{package}" to "plugin" in opencode.jsonc and',
	"install.opencode.jsoncStep2": "            {dependencies} to {path}.",
	"install.opencode.follow1":
		"  OpenCode: it installs the package at its next start; the private registry must be reachable",
	"install.opencode.follow2":
		"            (docs/package-installation.md). Then run a host-side deny canary.",
	"install.opencode.already": "{package}@{version} already registered.",
	"install.opencode.wouldPin":
		"would pin {package}@{version} in {manifest} and list it in {config}.",
	"install.opencode.registered": "registered {package}@{version}.",
	"install.opencode.notSeen":
		"wrote the OpenCode config but detection does not see the plugin ({detail}).",
	"install.openclaw.already": "AIDR plugin already enabled in ~/.openclaw/openclaw.json.",
	"install.openclaw.enablePolicy": "enable aidr-openclaw in the OpenClaw plugin policy",
	"install.openclaw.thenCanary": "            then run a host-side deny canary.",
	"install.openclaw.installed": "installed {spec}.",
	"install.openclaw.canary": "  OpenClaw: run a host-side deny canary.",
	"install.openclaw.notRegistered": "openclaw plugins install did not register AIDR ({reason}).",
	"install.editor.enable":
		"  {label}: run 'Singularity AIDR: Enable protection' from the command palette.",
	"install.editor.passVsix": "{detail}; pass --{host}-vsix <file> to update it.",
	"install.editor.noVsix": "no verified {artifact} was given (--{host}-vsix <file>).",
	"install.editor.fromBundle":
		"  {label}: {cli} --install-extension ./{artifact} (from the verified release bundle)",
	"install.editor.installed": "installed {extension} from {path}.",
	"install.editor.notRegistered": "the extension install did not register AIDR ({reason}).",
	"install.claude.manual1":
		"  Claude Code:  verify the publisher-signed release bundle and extract aidr-claude-plugin-<version>.tar.gz,",
	"install.claude.manual2":
		"                provision the release Ed25519 public key in ~/.singularity-aidr/config.json, then run",
	"install.claude.manual3":
		"                aidr setup --claude-plugin-dir /absolute/path/to/extracted/aidr-claude-plugin",
	"install.claude.manual4":
		"                (or from the Claude Code prompt: /plugin marketplace add <dir> and /plugin install aidr@aidr).",
	"install.claude.noDir": "no verified plugin directory was given (--claude-plugin-dir <dir>).",
	"install.claude.notPlugin":
		"{dir} is not an extracted AIDR Claude Code plugin (no .claude-plugin manifest).",
	"install.claude.cmdFailed": "claude {args} failed ({reason}).",
	"install.claude.installed": "installed aidr@aidr from the verified plugin directory.",
	"install.claude.restartPlugin":
		"  Claude Code: restart it and confirm the plugin is active (/plugin).",
	"install.claude.notRegistered": "the plugin install did not register AIDR ({detail}).",
	"install.claude.disableAll": "Claude Code has disableAllHooks set, so no hook would run.",
	"install.claude.disableAllStep":
		"  Claude Code: remove \"disableAllHooks\" from ~/.claude/settings.json, then rerun 'aidr setup'.",
	"install.claude.pluginEnabled":
		"the AIDR Claude Code plugin is enabled; the standalone hooks were not added (they would inspect every call twice).",
	"install.claude.standaloneAlready": "AIDR hooks from {root} already registered.",
	"install.claude.wouldRegister": "would register the hooks of {root} in {path}.",
	"install.claude.probeFailed": "the bundle's PreToolUse hook {reason}; registration unchanged.",
	"install.claude.registered": "registered the AIDR hooks from {root} (local deny canary passed).",
	"install.claude.notSeen":
		"wrote {path} but Claude Code detection does not see the hook ({detail}).",
	"install.claude.restartHooks":
		"  Claude Code: restart it so it loads the AIDR hooks, then run 'aidr verify'.",

	"remove.codex.byHand":
		"  Codex: remove the aidr-codex-hook handlers from ~/.codex/hooks.json / config.toml by hand.",
	"remove.codex.none": "no AIDR hook registered.",
	"remove.codex.would": "would remove {count} aidr-codex-hook handler(s).",
	"remove.codex.removed": "removed {count} aidr-codex-hook handler(s).",
	"remove.codex.package":
		"  Codex: the global @singularityrd/aidr-codex package is left installed; remove it with npm uninstall --global @singularityrd/aidr-codex.",
	"remove.opencode.none": "no AIDR plugin registered.",
	"remove.opencode.byHand":
		'  OpenCode: remove "{package}" from opencode.json "plugin" and package.json by hand.',
	"remove.would": "would remove AIDR from {files}.",
	"remove.removedFrom": "removed AIDR from {files}.",
	"remove.deleted": "deleted {path}",
	"remove.stillRegistered": "AIDR is still registered after the host CLI ran{reason}.",
	"remove.hostRemoved": "the host CLI removed AIDR.",
	"remove.claude.none": "no AIDR marketplace plugin enabled.",
	"remove.claude.manual":
		"  Claude Code: /plugin uninstall aidr@aidr and /plugin marketplace remove aidr",

	"uninstall.title": "Singularity AIDR — uninstall",
	"uninstall.titleHooks": "Singularity AIDR — uninstall (managed hooks only)",
	"uninstall.targetHome": "Target home: {home}",
	"uninstall.refused": "Refused: {reason}",
	"uninstall.refusedTarget": "the target could not be verified.",
	"uninstall.refusedInstall": "the installation could not be verified.",
	"uninstall.hooksRemoved": "Claude Code managed hooks: removed {count} (backup: {backup}).",
	"uninstall.hooksRefused": "Claude Code managed hooks: NOT removed — {reason}",
	"uninstall.refusedWord": "refused",
	"uninstall.hooksWould": "Claude Code managed hooks: would remove {count}.",
	"uninstall.action.removed": "removed",
	"uninstall.action.nothingToRemove": "nothing to remove",
	"uninstall.action.wouldRemove": "would remove",
	"uninstall.data.deleted":
		"deleted {path} (configuration, allowlist, audit log, approvals, quarantine, keys)",
	"uninstall.data.kept": "kept {path}{reason}",
	"uninstall.data.wouldDelete": "would delete {path} and the AIDR vault items",
	"uninstall.data.absent": "{path} does not exist",
	"uninstall.data.failed": "FAILED to delete {path}: {reason}",
	"uninstall.unknownError": "unknown error",
	"uninstall.localData": "Local data: {line}",
	"uninstall.vaultRemoved": "Vault items removed: {items}",
	"uninstall.vaultFailed": "Vault items that could NOT be removed: {items}",
	"uninstall.byHand": "Still to do by hand:",
	"uninstall.dryRun": "Dry run: nothing was changed.",
	"uninstall.incomplete":
		"Uninstall is INCOMPLETE: see the lines above. AIDR may still inspect some agents.",
	"uninstall.removed": "AIDR was removed. Restart the agent hosts so they unload it.",
	"uninstall.browserGuard":
		"Browser Guard is a browser extension: remove it from the browser (or the enterprise policy) separately.",
	"uninstall.nothing": "Nothing to remove.",
	"uninstall.notRemoved": "{error} Nothing was removed.",
	"uninstall.receiptVerified":
		"Installation receipt verified: {path} (connector {connector}, digest {digest}…)",
	"uninstall.reasonCode": "Reason code: {code}",
	"uninstall.noConfigChanged": "No configuration was changed.",
	"uninstall.noManagedHooks":
		"No AIDR-managed hook entries found; agent settings were left untouched.",
	"uninstall.leftAlone":
		"Left alone: {entries} hook {entryWord} and {hooks} non-AIDR hook registration(s).",
	"uninstall.entry": "entry",
	"uninstall.entries": "entries",
	"uninstall.removedCount": "Removed {count} AIDR-managed hook registration(s):",
	"uninstall.noCommand": "(no command recorded)",
	"uninstall.emptyEvents": "Hook events left empty and therefore deleted: {events}",
	"uninstall.backup": "Backup of the previous settings: {path}",
	"uninstall.preserved":
		"Preserved: AIDR policy/allowlist configuration, connector files, the installation receipt and every non-AIDR hook.",
	"uninstall.credentialKept":
		"The local CLI credential and its vault item are also preserved; use 'aidr config revoke-key' to remove that credential. Managed endpoint API keys are unchanged.",
	"uninstall.notActive":
		"Protection is NOT active for this agent now: AIDR no longer inspects its tool calls.",
	"uninstall.reEnable":
		"Re-enable it with 'aidr setup' and the connector install for your agent (docs/getting-started.md).",
	"uninstall.remedy.receipt":
		"Run 'aidr status' to see what is registered. A Claude Code marketplace install has no receipt: remove it with '/plugin uninstall aidr@aidr' and '/plugin marketplace remove aidr'. If AIDR was installed by hand or by an MDM, remove it with the same tool that installed it.",
	"uninstall.remedy.settings":
		"Repair or restore your agent settings file first; it was left untouched.",
	"uninstall.remedy.default":
		"Run 'aidr status' for the measured installation state before retrying.",
	"uninstall.confirm.hooksTitle": "Singularity AIDR — uninstall the managed agent hooks",
	"uninstall.confirm.hooksEffect": "AIDR will no longer inspect this agent's tool calls.",
	"uninstall.confirm.removes":
		"  Removes the AIDR connector from every agent host and the AIDR-managed hooks.",
	"uninstall.confirm.keeps": "  Keeps ~/.singularity-aidr and the AIDR vault items (--keep-data).",
	"uninstall.confirm.deletes":
		"  DELETES ~/.singularity-aidr (configuration, allowlist, audit log, approvals,\n  quarantined files, keys) and the AIDR items in the OS credential vault.",
	"uninstall.confirm.effect": "AIDR will no longer inspect any agent's tool calls.",

	"scan.usageTitle": "AIDR infrastructure and skill scan",
	"scan.noTargets": "No targets given.",
	"scan.usage": "Usage:",
	"scan.usageFile": "  aidr scan --file targets.txt          # one URL per line",
	"scan.usageSkill":
		"  aidr scan --skill ~/.claude/skills/my-skill   # skill/plugin package (T01-T09)",
	"scan.usageCode":
		"  aidr scan --code .                     # model loading + secure-code rules, file:line",
	"scan.options": "Options:",
	"scan.optJson": "  --json             machine-readable output",
	"scan.optAllowPublic": "  --allow-public     permit non-private targets (off by default)",
	"scan.optTimeout": "  --timeout <ms>     per-request timeout (default 3000)",
	"scan.optConcurrency": "  --concurrency <n>  parallel targets (default 4)",
	"scan.optUpload":
		"  --upload           send findings to the managed control plane (enrolled API key)",
	"scan.dataset":
		"Dataset: {fingerprints} fingerprints, {cves} CVEs (compiled from AI-Infra-Guard).",

	"discover.localProcess": "local process",
	"discover.project": " (project {project})",
	"discover.noRiskHint": "No configured risk indicator; trust is not verified",
	"discover.aigCategories": "    AIG categories: {categories}",
	"discover.aigNone": "    AIG categories: none matched (not a safety verdict)",
	"discover.secret":
		"    Hardcoded secret: {location} {key} ({kind}) - move it to a secret store or an env reference",
	"discover.header": "MCP discovery: {count} configured server(s)",
	"discover.unreadable": "Unreadable or unsupported configuration: {path}",
	"discover.coverage":
		"Inventory coverage is {status}; malformed server entries not enumerated: {count}",
	"discover.agents": "Agent environment: {hosts} detected; {count} finding(s)",
	"discover.noAgentHost": "no agent host",
	"discover.unreadableAgent": "Unreadable agent configuration: {path}",
	"discover.uploaded": "Uploaded {count} MCP inventory finding(s) to the control plane.",
	"discover.uploadedAgents":
		"Uploaded {count} MCP inventory and agent environment finding(s) to the control plane.",
	"discover.uploadFailed": "Upload failed: {reason}.",
	"discover.queued": " {count} finding(s) remain queued and will be retried on the next delivery.",
	"discover.nothingUploaded": " Nothing was uploaded.",

	"privacy.unknownType": 'Unknown type "{type}". Valid types: {valid} (aliases: {aliases})',
	"privacy.typesEmpty": "--types needs at least one type",
	"privacy.badFailOn": '--fail-on must be none, any or secret (got "{value}")',
	"privacy.notFound": "File not found: {path}",
	"privacy.cannotRead": "Cannot read {path} ({code})",
	"privacy.notRegular": "Not a regular file: {path}",
	"privacy.tooLarge":
		"Input is {size}; the privacy scan reads at most {max}. Split the file and scan the parts.",
	"privacy.grew": "Input grew past {max} while reading; the privacy scan reads at most {max}.",
	"privacy.stdinTooLarge":
		"Standard input exceeds {max}; the privacy scan reads at most {max}. Split the input and scan the parts.",
	"privacy.binary":
		"Input looks binary (contains NUL bytes); the privacy scan inspects UTF-8 text only.",
	"privacy.notUtf8": "Input is not valid UTF-8 text; the privacy scan inspects UTF-8 text only.",
	"privacy.more": "(+{count} more)",
	"privacy.header": "AIDR privacy scan: {source} ({bytes} bytes, local only)",
	"privacy.noFindingsPartial": "No findings in the inspected part of the input.",
	"privacy.noFindings": "No findings for the selected detectors.",
	"privacy.colType": "TYPE",
	"privacy.colCount": "COUNT",
	"privacy.colLines": "LINES",
	"privacy.findings":
		"{count} finding(s). Values are never printed; use --mask for a redacted copy.",
	"privacy.incomplete": "INCOMPLETE: part of the input was not inspected ({reasons}).",
	"privacy.notClean": "This is not a clean result; findings above are a lower bound.",
	"privacy.noInput":
		"No input: pass a file path, or pipe text on standard input (aidr privacy scan - < file).",
	"privacy.stdinSource": "standard input",
	"privacy.refuseMask":
		"Refusing to print a masked copy: the input was not fully inspected, so unmasked values could remain.",
	"privacy.failed": "Privacy scan failed: {name}",

	"coverage.badFormat": 'Unknown format "{format}". Use one of: {formats}.',
	"coverage.noMapping":
		"No rule set with a framework mapping was found at {path}. Reinstall or rebuild the CLI (its resources/threats directory ships {mapping}).",
	"coverage.invalidMapping": "The framework mapping at {path} is invalid:\n  {errors}",
	"coverage.noRules": "No detection rules loaded from {path}; there is no coverage to report.",
	"coverage.mismatch":
		"Warning: the framework mapping does not match the installed rules ({count} problem(s)):\n  {problems}",

	"config.unreadable":
		"Local configuration could not be read. Check its permissions, JSON and credential store.",
	"config.notConfigured": "⚠️  AIDR not configured. Run 'aidr setup' first.",
	"config.notSet": "(not set)",
	"config.invalidPath": "Invalid configuration path.",
	"config.secretArg":
		"Secret values cannot be passed as command-line arguments. Rerun without the value argument to enter it at the hidden prompt.",
	"config.setUsage": "⚠️  Usage: aidr config -s <key> <value> (secret values are prompted securely)",
	"config.secretPrompt": "Secret value: ",
	"config.secretReadFailed": "Could not read secret input.",
	"config.secretInObject":
		"Secret fields cannot be supplied inside object arguments. Set each secret field through its hidden prompt.",
	"config.unknownField": "Invalid or unknown configuration field; no changes saved.",
	"config.invalid": "Invalid runtime configuration; no changes saved.",
	"config.invalidChoice": "  {key}: '{value}' is not a valid value. Valid values: {choices}.",
	"config.unknownFieldOnly": "Unknown configuration field; no changes saved.",
	"config.confirmTitle": "Singularity AIDR — change a protection setting",
	"config.confirmEffect": "This change may weaken what AIDR inspects or blocks.",
	"config.noChanges": "{error} No changes saved.",
	"config.saveFailed":
		"Configuration could not be saved. Check its permissions and credential store, then retry.",
	"config.set": "✅ Set {key} = {value}",
	"config.listTitle": "🛡️  AIDR Configuration",
	"config.usage": "Usage:",
	"config.usageGet": "  aidr config -g <key>       Get value",
	"config.usageSet": "  aidr config -s <key> <val> Set non-secret value",
	"config.usageSecret": "  aidr config -s <secret-key> Enter secret at hidden prompt",
	"config.usageList": "  aidr config -l             List all",

	"simulate.fromConfig": "(from config)",
} as const;

export type CliMessageKey = keyof typeof CLI_EN;

export const CLI_TR: Record<CliMessageKey, string> = {
	"status.title": "Singularity AIDR — kurulum tanılaması",
	"status.passed": "başarılı",
	"status.failed": "BAŞARISIZ",
	"status.detection": "Tespit öz sınaması: {result}; {rules} kural{detail}.",
	"status.configuration": "Yapılandırma: {state}; mod: {mode}{note}",
	"status.configValid": "geçerli",
	"status.configDefaults": "varsayılanlar",
	"status.configInvalid": "GEÇERSİZ (kısıtlayıcı yedek ayarlar uygulanıyor)",
	"status.registrationDetected": "kayıt/paket algılandı",
	"status.managedInactive":
		"Yönetilen mod: etkin değil (mod: {mode}); koruma yerelde uygulanıyor ve kontrol düzlemi kullanılmıyor.",
	"status.managedEnabled": "etkin",
	"status.managedDisabled": "devre dışı",
	"status.endpointConfigured": "yapılandırılmış",
	"status.endpointMissing": "eksik",
	"status.managed":
		"Yönetilen mod: {state}; uç nokta {endpoint}. Bağlantı ve filo benimsemesi denetlenmedi.",
	"status.notEnrolled":
		"! Bu cihaz KAYITLI DEĞİL: yerel koruma açık, ancak şirket politikasını almıyor ve hiçbir şey raporlamıyor. `aidr assistant` çalıştırıp şirketinize bağlanın (ya da BT'den kayıt kodu isteyin).",
	"status.telemetry":
		"Telemetri kuyruğu: {state}; {pending} olay teslim edilmedi, {lost} olay kayboldu{oldest}{suffix}",
	"status.telemetryOldest": ", en eskisi {seconds} sn",
	"status.telemetryUnreadable": " — en az bir kuyruk okunamadı.",
	"status.telemetryEnd": ".",
	"status.audit":
		"Denetim kaydı: {failures} ekleme yazılamadı, {drops} döndürme işleminde en eski dosya silindi.",
	"status.auditUnknownDrops": "bilinmeyen sayıda",
	"status.auditLastError": " Son hata: {error}.",
	"status.ready":
		"Yerel kurulum denetimleri başarılı. Yapay zekâ araçlarınızın hook'ları gerçekten çalıştırdığını şununla doğrulayın: aidr verify",
	"status.attention":
		"Kurulum ilgi gerektiriyor: yukarıdaki satırlara bakın ya da her sorunu tek satırda görmek için 'aidr doctor' çalıştırın.",
	"status.disclaimer":
		"Bir paketin ya da hook kaydının bulunması, yapay zekâ aracının onu gerçekten çalıştırdığını kanıtlamaz.",
	"status.verdictPrefix": "Sonuç:",
	"status.verdictProtected": "korunuyor: {hosts}",
	"status.verdictRestart": "{since} öncesinde açıksa yeniden başlatın: {hosts}",
	"status.verdictManual": "elle adım gerekiyor: {steps}",
	"status.verdictNone":
		"kayıtlı desteklenen yapay zekâ aracı yok; Claude Code, Cursor, VS Code, Codex, OpenCode ya da OpenClaw kurun, ardından 'aidr setup' çalıştırın",
	"status.verdictVerify": "ardından 'aidr verify' çalıştırın",
	"verify.title":
		"Singularity AIDR — yapay zekâ aracı hook canary sınaması (canary yalnızca veri olarak verilir, asla çalıştırılmaz)",
	"verify.pass": "BAŞARILI",
	"verify.fail": "BAŞARISIZ",
	"verify.skip": "ATLANDI",
	"verify.notRegistered": "kayıtlı değil",
	"verify.summaryPass": "Sınanan her AIDR hook'u canary'yi engelledi ({count}).",
	"verify.summaryFail":
		"{count} AIDR hook'u canary'yi ENGELLEMEDİ: bu yapay zekâ aracının araç çağrıları denetlenmeden çalışabilir.",
	"verify.summaryNone":
		"Buradan sınanabilecek bir AIDR hook giriş noktası bulunamadı. Sonraki adım için 'aidr status' çalıştırın.",
	"verify.inProcess":
		"süreç içi eklenti; yalnızca yapay zekâ aracının içinde çalışır. Aracı yeniden başlatın, ardından yüklendiğini doğrulamak için ondan 'echo aidr-canary' gibi zararsız bir komut çalıştırmasını isteyin.",
	"verify.pluginOnly":
		"Claude Code eklentisi olarak kayıtlı; hook'ları yalnızca Claude Code içinde çalışır (/plugin ile kontrol edin).",
	"verify.noEntry": "kayıtlı, ancak {file} içinde sınanacak bir AIDR hook komutu bulunamadı.",
	"releaseKey.added": "✓ Sürüm anahtarı {fingerprint} ayarlandı (kaynak: {source}).",
	"releaseKey.present": "✓ Sürüm anahtarı {fingerprint} zaten ayarlı.",
	"releaseKey.replaced":
		"✓ Sürüm anahtarı {fingerprint} ayarlandı (kaynak: {source}); {previous} anahtarının yerini aldı.",
	"releaseKey.wouldAdd": "Sürüm anahtarı {fingerprint} ayarlanacaktı (kaynak: {source}).",
	"releaseKey.kept":
		"⚠ Zaten farklı bir sürüm anahtarı ayarlı ({previous}); o korundu. {source} kaynağındaki anahtar ({fingerprint}) EKLENMEDİ. Yönetici bu anahtara güveniyorsa şunu yeniden çalıştırın: aidr setup --force",
	"releaseKey.missing":
		"⚠ Ayarlı bir sürüm anahtarı yok. Bu sürüm, anahtar ayarlanana kadar her araç çağrısını engeller. Şunu çalıştırın: aidr setup --release-key <dosya.pem> (Singularity AIDR yöneticinizden aldığınız sürüm ortak anahtarı).",
	"releaseKey.invalid": "Sürüm anahtarı reddedildi: {reason}",
	"releaseKey.confirm": "  Sürüm anahtarı: {file} ({fingerprint})",

	"approvals.artifactsTruncated":
		"artifacts:  {total} öğeden {shown} tanesi gösteriliyor (kısaltıldı); onay {total} öğenin tümünü kapsar",
	"approvals.asked": "asked:      {createdAt} ({expiresAt} tarihine kadar onaylanabilir)",
	"approvals.integrityFailed": "integrity:  BAŞARISIZ — bu kayıt onaylanamaz",
	"approvals.hostDialogConnector":
		"connector:  {connector}   tool: {tool}   (yapay zekâ aracının kendi onay penceresinde yanıtlandı)",
	"approvals.disabled": "Operatör onayları devre dışı.",
	"approvals.none": "Onay bekleyen bir Singularity AIDR isteği yok.",
	"approvals.waiting": "Operatör kararı bekleyen {count} istek (en yeniden başlayarak):",
	"approvals.howToApprove":
		"Tek bir yeniden denemeyi onaylamak için: aidr approve <kimlik>  (kimliğin ilk 8 karakteri yeterlidir)",
	"approvals.howToPick":
		"Ya da numaralı listeden seçmek için terminalinizde yalnızca 'aidr approve' çalıştırın.",
	"approvals.hostDialogHeader":
		"Yapay zekâ aracının kendi onay penceresinde yanıtlanan {count} yeni istek (bilgi amaçlı; buradan onaylanamaz):",
	"approvals.hostDialogRoute":
		'Bunları `aidr approve` üzerinden yönlendirmek için operator_approvals.mode değerini "operator" yapın.',
	"approvals.storeUnreadable": "Onay deposu okunamadı: {error}",
	"approvals.answeredInHost":
		"Bu istek yapay zekâ aracının kendi onay penceresinde yanıtlandı (operator_approvals.mode: host_dialog). Yalnızca bilgi amaçlı listelenir ve buradan onaylanamaz.",
	"approvals.notFound":
		"Bu kimlikle bekleyen bir Singularity AIDR isteği yok (süresi dolmuş ya da zaten onaylanmış olabilir). Açık istekleri listelemek için `aidr pending` komutunu çalıştırın.",
	"approvals.integrityRejected":
		"Bu bekleyen istek bütünlük doğrulamasından geçemedi (kayıt değiştirilmiş ya da onay anahtarı değişmiş). Onaylanmadı; yeni bir istek kaydedilmesi için yapay zekâ aracının çağrıyı yeniden denemesini sağlayın.",
	"approvals.badTtl": "--ttl tam sayı olarak dakika cinsinden olmalıdır (1-1440).",
	"approvals.notApproved": "Onaylanmadı: {reason}",
	"approvals.notApprovedCode": "Onaylanmadı ({code}): {reason}",
	"approvals.allowlistPermitted":
		"Yapay zekâ aracının bu öğeleri kalıcı izin listesine bir kez eklemesine de izin verilecek.",
	"approvals.allowlistNotPermitted":
		"Bu onay, yapay zekâ aracının izin listesine herhangi bir şey eklemesine izin vermez.",
	"approvals.promptTitle": "Singularity AIDR — engellenmiş bir yapay zekâ aracı eylemini onayla",
	"approvals.promptScope":
		"Bu onay, tam olarak bu çağrının {minutes} dakika içinde TEK bir kez yeniden denenmesine izin verir.",
	"approvals.approved":
		"Onaylandı. Yapay zekâ aracından {minutes} dakika içinde yeniden denemesini isteyin.",
	"approvals.approvedDetail":
		"(kimlik {actionId}…, {expiresAt} tarihine kadar geçerli; yalnızca aynı çağrının tek bir yeniden denemesi)",
	"approvals.badId":
		"'aidr pending' çıktısındaki kimliği ya da en az ilk 8 karakterini (0-9, a-f) girin.",
	"approvals.ambiguous":
		"Bekleyen {count} eylem {prefix} ile başlıyor; kimliğin daha fazla karakterini yazın.",
	"approvals.fullIdForYes":
		"--yes için 64 karakterlik kimliğin tamamı gerekir; kısa kimlik yalnızca terminalde onay verdiğinizde kabul edilir.",
	"approvals.idRequired":
		"Onaylanacak eylemi belirtin: aidr approve <kimlik> (bkz. 'aidr pending'). Listeden seçmek için etkileşimli bir terminal gerekir.",
	"approvals.pickTitle": "Kararınızı bekleyenler (en yeniden başlayarak):",
	"approvals.pickPrompt": "İncelenecek numara (1-{count}) ya da iptal için Enter: ",
	"approvals.pickNone": "Onaylanmadı: bir eylem seçilmedi.",

	"confirm.type": 'Onaylamak için "{word}" yazın: ',
	"confirm.notConfirmed": "Onaylanmadı; hiçbir şey değiştirilmedi.",
	"confirm.inputEnded": "Onay girişi sona erdi.",
	"confirm.protectionLocked":
		"Reddedildi: kuruluşunuzun makine politikası Singularity AIDR korumasını kilitliyor (protection_locked); bu yüzden yerel izin listesi kaydı, istisna, korumayı zayıflatan ayar ve kaldırma burada kullanılamaz. BT ya da güvenlik ekibinize başvurun.",
	"confirm.yesNeedsEnv":
		"--yes yalnızca operatör {env} değerini de ayarladığında dikkate alınır. Elle onaylamak için komutu etkileşimli bir terminalde çalıştırın.",
	"confirm.needsTerminal":
		"Bu yalnızca operatöre açık komut, onay için etkileşimli bir terminal gerektirir. Operatör otomasyonu için --yes ile birlikte {env} kullanın.",
	"confirm.nonInteractive": "Etkileşimsiz olarak onaylandı (--yes).",

	"mode.local": "yerel",
	"mode.managed": "yönetilen",
	"mode.releaseBuildNote": "sürüm derlemesi: her zaman yönetilen",

	"integrity.fixCommand": "aidr setup --release-key <anahtar.pem>",
	"integrity.ok":
		"Sürüm doğrulama anahtarı: {count} anahtar yapılandırılmış; imzalar denetleniyor.",
	"integrity.missing":
		"Sürüm doğrulama anahtarı EKSİK: Singularity AIDR kendi kurulumunu doğrulayamıyor ve her araç çağrısını engelleyebilir. Çözüm: {fix}",
	"integrity.invalid":
		"Sürüm doğrulama anahtarı kullanılamıyor ({total} anahtardan {invalid} tanesi geçerli bir açık anahtar değil). Çözüm: {fix}",
	"integrity.digestsOnly":
		"Sürüm doğrulama anahtarı ayarlanmamış: dosya özetleri denetleniyor, imzalar denetlenmiyor (geliştirme sürümü).",
	"integrity.off": "Sürüm imzası denetimi: kapalı (geliştirme sürümü).",
	"integrity.missingWhy":
		"Anahtar olmadan bir sürüm derlemesi, bağlayıcı dosyalarının imzalı sürüm olduğunu kanıtlayamaz; imzasız ya da doğrulanamayan bir paket güvenilmek yerine engellenir. BT yöneticinizden anahtar dosyasını isteyin ve şunu çalıştırın: {fix}",

	"doctor.title": "Singularity AIDR tanılama",
	"doctor.version": "Singularity AIDR çekirdeği {version}.",
	"doctor.configFile": "Yapılandırma dosyası: {path}",
	"doctor.configDefaults": "Yapılandırma dosyası yok; yerel varsayılanlar geçerli.",
	"doctor.configInvalid": "Yapılandırma geçersiz; kısıtlayıcı yedek ayarlar uygulanıyor.",
	"doctor.configManagedIncomplete":
		"Mod yönetilen, ancak etkin bir kontrol düzlemi uç noktası yok.",
	"doctor.configMode": "Mod: {mode}.",
	"doctor.detectionOk": "{rules} tehdit kuralı yüklendi; tespit öz sınaması başarılı.",
	"doctor.detectionFailed": "Tespit öz sınaması başarısız: {reason} ({rules} kural).",
	"doctor.detectionCrashed": "Tespit öz sınaması çöktü: {error}",
	"doctor.connectorsOk": "Hook kayıtlı yapay zekâ araçları: {hosts}.",
	"doctor.connectorsBroken": "Bağlayıcı sorunları: {hosts}.",
	"doctor.connectorsUnprotected":
		"Yapay zekâ araçları bulundu ({hosts}) ama hiçbirinde AIDR hook'u kayıtlı değil. `aidr setup` çalıştırın.",
	"doctor.connectorsNone": "Desteklenen bir yapay zekâ aracı ya da AIDR hook'u bulunamadı.",
	"doctor.connectorsPartial":
		"Hook kayıtlı yapay zekâ araçları: {hosts}. AIDR olmadan bulunanlar: {unprotected}. Korumak için `aidr setup` çalıştırın.",
	"doctor.dlpInvalid":
		"{runtimes} için veri sızıntısı önleme (DLP) politikası geçersiz; bu bağlayıcılar her çağrıyı engeller.",
	"doctor.dlpEnabled": "DLP etkin: {runtimes}.",
	"doctor.dlpItemLocal": "{runtime} (yerel {path})",
	"doctor.dlpItemSigned": "{runtime} (imzalı yönetilen paket)",
	"doctor.dlpLocalPending":
		"DLP politikası yerel dlp-policy.json dosyasından yüklendi (imzasız); bir bağlayıcı hook'u kaydedildiğinde uygulanır.",
	"doctor.dlpLocalFile": "Yerel DLP politika dosyası: {path}",
	"doctor.dlpLocalInvalid": "DLP etkin değil: yerel DLP politikası GEÇERSİZ ve UYGULANMIYOR.",
	"doctor.dlpLocalInvalidNote": "Yerel DLP politikası {path} GEÇERSİZ ({reason}) ve UYGULANMIYOR.",
	"doctor.dlpLocalIgnored":
		"Yerel DLP politikası {path}, {mode} modunda yok sayılır; yalnızca imzalı paketler uygulanır.",
	"doctor.dlpNoneLocal":
		"DLP etkin değil: imzalı bir algılayıcı politikası kurulu değil ve yerel DLP politikası bulunamadı.",
	"doctor.dlpNoneManaged":
		"DLP etkin değil: yönetilen mod, kontrol düzleminden imzalı bir algılayıcı politikası gerektirir.",
	"doctor.profilesLocalInvalid":
		"Yerel ajan profilleri geçersiz ve YÜKLENMEDİ; `aidr profile validate` çalıştırın.",
	"doctor.profilesLocalInvalidNote": "{path}: {reason}",
	"doctor.profilesManagedInvalid":
		"{runtimes} için yönetilen ajan profilleri geçersiz; bu bağlayıcılar her çağrıyı reddeder.",
	"doctor.profilesLocalCount": "{count} yerel profil",
	"doctor.profilesManagedFor": "{runtimes} için yönetilen profiller",
	"doctor.profilesSummary": "Ajan izin profilleri: {parts}{diagnostics}.",
	"doctor.profilesDiagnostics": " ({count} uyarı; bkz. `aidr profile list`)",
	"doctor.profilesNone": "Yapılandırılmış ajan izin profili yok (yalnızca tehdit tespiti).",
	"doctor.keyNotCreated": "henüz oluşturulmadı",
	"doctor.keyOsVault": "işletim sistemi kasasında ({store})",
	"doctor.keyEncryptedFile": "makineye bağlı şifreli dosya deposunda",
	"doctor.keyPlainFile": "DÜZ BİR DOSYADA (bu kullanıcının her programı okuyabilir)",
	"doctor.keyPlainFileWarning":
		"Onay anahtarı düz bir dosyada (açıkça key_storage=file seçilmiş). Bu kullanıcının her süreci, kabuk erişimi olan ele geçirilmiş bir yapay zekâ aracı da dahil, onu okuyup sahte onay üretebilir; tek kullanımlık kayıt defteri de bir dosyadır. İşletim sistemi kimlik bilgisi kasasını tercih edin (bu seçimi kaldırın).",
	"doctor.keyEncryptedFileNote":
		"Bu makinede yanıt veren bir işletim sistemi kimlik bilgisi kasası yok; bu yüzden onay anahtarı ve tek kullanımlık kayıt defteri, ~/.singularity-aidr/sealed altında yalnızca sahibinin okuyabildiği dosyalarda makineye bağlı bir anahtarla AES-256-GCM ile mühürlenir. libsecret gibi bu da aynı kullanıcıyla çalışan kodu durdurmaz; bunun için yapay zekâ aracını ayrı bir hesapla çalıştırın (docs/configuration.md#key-custody).",
	"doctor.approvalsPending": "Operatör onayı bekleyen {count} istek{unverified}",
	"doctor.approvalsUnverified": ", {count} tanesi bütünlük doğrulamasından geçemiyor",
	"doctor.approvalsSummary": "{pending}; onay anahtarı {where}.",
	"doctor.approvalsDisabled":
		"Onaylar DEVRE DIŞI: engellenen eylemler engelli kalır ve onaylanamaz ({pending}).",
	"doctor.approvalsUnusable":
		"Onay deposu kullanılamıyor; onarılana kadar engellenen eylemler onaylanamaz.",
	"doctor.storePath": "Onay deposu: {path}",
	"doctor.environmentUnchecked":
		"Yapay zekâ aracı ayarları denetlenemedi. Bu temiz bir sonuç değildir.",
	"doctor.environmentClean":
		"Yapay zekâ aracı ayarları: statik denetimler güvensiz bir otonomi ayarı ya da açıklık bulmadı.",
	"doctor.environmentFindings":
		"Yapay zekâ aracı ayarları: {count} bulgu, {serious} tanesi yüksek ya da kritik ({ids}). `aidr discover --agents` çalıştırın.",
	"doctor.environmentUnreadable": "{count} yapılandırma dosyası çözümlenemedi.",
	"doctor.auditDisabled": "Denetim kaydı yapılandırmada kapalı.",
	"doctor.noVerdict":
		"Henüz kayıtlı karar yok; korumanın çalıştığını doğrulamak için `aidr verify` çalıştırın.",
	"doctor.amsiAvailable": "AMSI kötü amaçlı yazılım taraması: kullanılabilir ({backend}).",
	"doctor.amsiSlowFallback":
		"AMSI kötü amaçlı yazılım taraması PowerShell yedek yolu üzerinden çalışıyor (araç çağrısı başına yaklaşık 0,3-0,5 sn): bu kurulumda yerel koffi bileşeni eksik. Resmî Windows kurulum paketiyle yeniden kurun.",
	"doctor.amsiUnavailable":
		"AMSI kötü amaçlı yazılım taraması bu bilgisayarda çalışamıyor; içerik AMSI ile TARANMIYOR (yerel tehdit kuralları yine uygulanıyor). Nedeni için --verbose kullanın.",
	"doctor.lastVerdict": "Son karar: {tool} için {verdict}, {time}.",
	"doctor.auditUnreadable": "Denetim kaydı okunamadı.",
	"doctor.clockOk": "Saat: kontrol sunucusuyla arasındaki fark {seconds} sn içinde.",
	"doctor.clockDrift":
		"Saat kontrol sunucusundan {seconds} sn {direction}. Saat eşitlemeyi (NTP / Windows Saati) açın.",
	"doctor.clockSkewed":
		"Saat kontrol sunucusundan {seconds} sn {direction}: imzalı lisanslar, onaylar ve kayıt kodları reddedilebilir. Saati hemen eşitleyin (NTP / Windows Saati).",
	"doctor.clockAhead": "ileride",
	"doctor.clockBehind": "geride",
	"doctor.clockUnchecked":
		"Saat karşılaştırılamadı; kontrol sunucusu saat bilgisi döndürmedi ({reason}). Bu temiz bir sonuç değildir.",
	"doctor.clockWhy":
		"Lisans bitişi ve ek süre, onay belirteçleri, kayıt kodları, cihaz oturumları ve TLS sertifikaları bu makinenin saatine göre denetlenir. Tüm uç noktaları ve kontrol sunucusunu aynı NTP kaynağına bağlayın (docs/operations/onprem-runbook.md#time-synchronisation).",
	"doctor.footerOk":
		"Engelleyici bir sorun bulunmadı. Yapay zekâ araçlarınızın hook'ları gerçekten çalıştırdığını şununla doğrulayın: aidr verify",
	"doctor.footerFail": "Sorunlar bulundu (✗). Düzeltip `aidr doctor` komutunu yeniden çalıştırın.",
	"doctor.verboseHint": "Her satırın ayrıntısı: aidr doctor --verbose",

	"setup.title": "Singularity AIDR kurulumu",
	"setup.titleDryRun": " (deneme — hiçbir şey değiştirilmeyecek)",
	"setup.nothingChanged": "Hiçbir şey değiştirilmedi.",
	"setup.detecting": "Yapay zekâ araçları aranıyor...",
	"setup.hostsFound": "Bulunan yapay zekâ araçları: {hosts}",
	"setup.noHosts":
		"Bu ev dizininde desteklenen bir yapay zekâ aracı bulunamadı (Claude Code, Cursor, VS Code, Codex, OpenCode, OpenClaw).",
	"setup.skipConfig": "Yapılandırma oluşturma atlandı (deneme).",
	"setup.creatingConfig": "Yapılandırma oluşturuluyor...",
	"setup.configReused": "Yapılandırma zaten hazır — değişiklik gerekmedi: {path}",
	"setup.configCreated": "Yapılandırma: {path}",
	"setup.loadingRules": "Tehdit kuralları yükleniyor...",
	"setup.noRules":
		"Hiçbir tehdit kuralı yüklenemedi. Tespit çalışmayacağı için kurulum başarılı sayılmıyor.",
	"setup.selfTestFailed": "Tespit öz sınaması başarısız: {reason}",
	"setup.detectionOk": "Tespit çalışıyor: {rules} kural yüklendi, öz sınama başarılı.",
	"setup.noInstallDone": "Kurulum bitti (bağlayıcı kurulumu atlandı: --no-install).",
	"setup.nextSteps": "Sonraki adımlar:",
	"setup.noInstallStep1": "Aşağıdaki bağlayıcıyı kurun — kurana kadar araç çağrıları DENETLENMEZ",
	"setup.noInstallStep2": "Ardından denetleyin: aidr status   ve   aidr verify",
	"setup.planning": "Bağlayıcı kurulumları planlanıyor...",
	"setup.installing": "Bağlayıcılar kuruluyor...",
	"setup.connectors": "Bağlayıcılar:",
	"setup.action.alreadyInstalled": "zaten kurulu",
	"setup.action.installed": "kuruldu",
	"setup.action.updated": "güncellendi",
	"setup.action.wouldInstall": "kurulacak",
	"setup.action.wouldUpdate": "güncellenecek",
	"setup.action.manual": "elle adım gerekiyor",
	"setup.action.failed": "BAŞARISIZ",
	"setup.action.notDetected": "bulunamadı",
	"setup.dryRunDone": "Deneme: hiçbir dosya yazılmadı ve hiçbir komut çalıştırılmadı.",
	"setup.company.confirmTitle": "Singularity AIDR — bu bilgisayarı şirketinize bağla",
	"setup.company.confirmAddress": "Şirket adresi: {endpoint}",
	"setup.company.withCode": "Kayıt kodu: yükleyicide girildi",
	"setup.company.withoutCode":
		"Kayıt kodu: yok (bir yapay zekâ aracı açıldığında bu bilgisayarı şirketinizin Singularity AIDR konsolunda onaylayın)",
	"setup.company.confirmEffect":
		"Bu bilgisayar koruma olaylarını bu adrese gönderecek ve şirketinizin politikasını uygulayacak. Bu bilgisayardaki koruma her durumda açık kalır.",
	"setup.company.applied":
		"Şirketinize bağlandı ({endpoint}). Bağlantı, bir yapay zekâ aracı bir sonraki açılışında tamamlanır.",
	"setup.company.appliedApprove":
		"Şirket adresi ayarlandı ({endpoint}). Bir yapay zekâ aracı bir sonraki açılışında bir kod ve bağlantı gösterir: bu bilgisayarı orada onaylayın.",
	"setup.company.alreadyConnected":
		"Bu bilgisayar zaten {endpoint} adresine bağlı. Yükleyicideki şirket bilgileri kullanılmadı ve silindi.",
	"setup.company.notConfirmed":
		"Yükleyicideki şirket bağlantısı uygulanmadı: {reason} Kayıtlı duruyor; uygulamak için bir terminalde aidr setup komutunu çalıştırın.",
	"setup.company.invalid":
		"Yükleyicinin kaydettiği şirket bağlantısı kullanılamadı ({reason}) ve silindi. BT ekibinizden aldığınız bilgilerle yeniden kurun.",
	"setup.company.expired":
		"Yükleyicinin kaydettiği şirket bağlantısı 3 günden eski olduğu için silindi. BT ekibinizden yeni bir kayıt kodu isteyin.",
	"setup.company.failed":
		"Şirket bağlantısı kaydedilemedi: {reason}. Bu bilgisayardaki koruma etkilenmedi.",
	"setup.company.notDeleted":
		"Yükleyicinin şirket bağlantısı dosyası silinemedi ({reason}). Kullanıcı klasörünüzdeki .singularity-aidr klasöründe bulunan installer-enrollment.json dosyasını silin.",
	"setup.company.fromPacket": "{customer} için kurulum programı tarafından ayarlandı",
	"setup.packet.applied":
		"Müşteri: {customer} ({id}). Lisans {state}; güncellemeler şu tarihe kadar: {date}.",
	"setup.packet.wouldApply":
		"{customer} ({id}) müşteri paketi uygulanacak; lisans {state}, güncellemeler şu tarihe kadar: {date}.",
	"setup.packet.refused":
		"{path} müşteri paketi reddedildi ({reason}) ve kullanılmadı. Yerel tespit yine de kuruldu. Singularity R&D'den yeni bir kurulum programı isteyin.",
	"setup.packet.recordFailed":
		"Müşteri lisansı kaydedilemedi ({reason}). Yeni güncelleme paketleri bu lisansa göre denetlenemez; yerel tespit etkilenmedi.",
	"setup.packet.expired":
		"Lisans sona erdi: yeni güncellemeler {date} tarihinde durdu. Yerel tespit, kurulu kurallarla çalışmaya devam ediyor.",
	"setup.packet.notYetValid":
		"Lisans {date} tarihinde başlıyor; güncellemeler o tarihten itibaren kabul edilir. Yerel tespit şimdiden çalışıyor.",
	"setup.packet.sensitivity": "Hassasiyet, müşteri paketi tarafından {level} olarak ayarlandı.",
	"setup.packet.licensingKeys":
		"Şirketinizin kurulum imza anahtarları müşteri paketinden alındı ve güvenilir olarak kaydedildi ({count}).",
	"setup.machinePolicy.found": "Yöneticinizin belirlediği makine politikası: {source}",
	"setup.machinePolicy.refused":
		"{source} makine politikası reddedildi ({reason}) ve kullanılmadı. Yerel koruma sürüyor; BT ekibinize haber verin.",
	"setup.machinePolicy.connected":
		"Makine politikasıyla şirketinize bağlandı ({endpoint}). Bağlantı, bir yapay zekâ aracı bir sonraki açılışında tamamlanır.",
	"setup.machinePolicy.connectedApprove":
		"Şirket adresi makine politikasıyla ayarlandı ({endpoint}). Bir yapay zekâ aracı bir sonraki açılışında bir kod ve bağlantı gösterir: bu bilgisayarı orada onaylayın.",
	"setup.machinePolicy.wouldConnect": "Makine politikası gereği {endpoint} adresine bağlanılacak.",
	"setup.machinePolicy.alreadyConnected": "Makine politikası gereği {endpoint} adresine bağlı.",
	"setup.machinePolicy.handoffIgnored":
		"Kurulum programının kaydettiği şirket bağlantısı kullanılmadı: bu bilgisayarda şirket bağlantısını makine politikası belirliyor.",
	"setup.machinePolicy.offline.keep_enforcing_local":
		"Şirket sunucusuna ulaşılamazsa bu bilgisayardaki koruma yerel olarak çalışmaya devam eder.",
	"setup.machinePolicy.offline.block_after_grace":
		"Şirket sunucusuna çevrimdışı süreden uzun ulaşılamazsa bu bilgisayarda yapay zekâ araçlarının işlemleri engellenir.",
	"customer.state.active": "etkin",
	"customer.state.grace": "ek süresinde",
	"customer.state.expired": "sona erdi",
	"customer.state.not_yet_valid": "henüz başlamadı",
	"customer.status":
		"Müşteri: {customer} ({id}); lisans {state}. Güncellemeler şu tarihe kadar: {date}.",
	"customer.statusExpired":
		"Müşteri: {customer} ({id}); lisans sona erdi. Güncellemeler {date} tarihinde durdu; tespit, kurulu kurallarla devam ediyor.",
	"customer.statusRefused":
		"Müşteri paketi: reddedildi ({reason}); kullanılmadı. Yerel tespit etkilenmedi. Singularity R&D'den yeni bir kurulum programı isteyin.",
	"setup.complete": "✅ Kurulum tamamlandı!",
	"setup.registeredFor": "Kayıtlı: {hosts} (yapay zekâ aracının içinde henüz doğrulanmadı).",
	"setup.incomplete": "⚠ Kurulum bitti, ancak koruma her yapay zekâ aracı için henüz ETKİN DEĞİL:",
	"setup.incompleteDetail":
		"kayıtlı bağlayıcısı olmayan bir yapay zekâ aracının araç çağrıları DENETLENMEZ.",
	"setup.unprotected": "Korunmayan: {hosts}",
	"setup.dryRunNext": "Uygulamak için --dry-run olmadan çalıştırın.",
	"setup.verifyNext":
		"Sonraki adım: yapay zekâ araçlarınızı yeniden başlatın, ardından şunu çalıştırın: aidr verify",

	"simulate.title": "Singularity AIDR — saldırı benzetimi öz sınaması",
	"simulate.modeLine": "Mod: {mode}   Hassasiyet: {sensitivity}",
	"simulate.colCategory": "Kategori",
	"simulate.colDetected": "Yakalanan",
	"simulate.colRate": "Oran",
	"simulate.colBenignFp": "Yanlış alarm",
	"simulate.total": "TOPLAM",
	"simulate.na": "yok",
	"simulate.score": "Genel tespit puanı: %{score}",
	"simulate.fpRate": "Zararsız örneklerde yanlış alarm oranı: %{rate}",
	"simulate.notCounted": "Sayılmayan (denetlenmedi / devre dışı): {count}",
	"simulate.missesTitle": "Kaçırılanlar (ürünün beklenen düzeyde işaretlemediği zararlı örnekler):",
	"simulate.missLine": "beklenen >= {expected}, sonuç {actual}",
	"simulate.fpTitle": "Yanlışlıkla işaretlenen zararsız ikizler:",
	"simulate.fpLine": "{actual} olarak işaretlendi",
	"simulate.abortedTitle": "Denetlenmeyen / puanlanmayan:",
	"simulate.verdictNone":
		"BAŞARISIZ — hiçbir örnek puanlanamadı, bu yüzden hiçbir şey doğrulanmadı",
	"simulate.verdictPass": "BAŞARILI — puan %{score} >= en az %{min}",
	"simulate.verdictFail": "BAŞARISIZ — puan %{score} < en az %{min}",
	"simulate.pass": "BAŞARILI",
	"simulate.fail": "BAŞARISIZ",
	"simulate.category.injection": "İstem enjeksiyonu",
	"simulate.category.exfiltration": "Veri sızdırma",
	"simulate.category.destructive": "Yıkıcı komutlar",
	"simulate.category.encoding": "Gizleme / kodlama",
	"simulate.category.supplyChain": "Tedarik zinciri",
	"simulate.category.mcp": "MCP aracı zehirleme",
	"simulate.category.selfDefense": "Öz savunma",
	"simulate.category.privacy": "Kişisel veri / gizli bilgi",
	"simulate.badFormat": "Bilinmeyen --format: {format}. table, json ya da html kullanın.",
	"simulate.failed": "aidr simulate başarısız: {error}",
	"simulate.wrote": "{format} raporu {path} dosyasına yazıldı",
	"simulate.html.title": "AIDR saldırı benzetimi raporu",
	"simulate.html.heading": "Yapay zekâ aracı güvenliği — saldırı benzetimi raporu",
	"simulate.html.sub":
		"Yerel tespit motorunun savunma amaçlı öz sınaması. Oluşturulma: {generated} · mod: {mode} · hassasiyet: {sensitivity}",
	"simulate.html.scoreCard": "Tespit puanı",
	"simulate.html.fpCard": "Zararsız örneklerde yanlış alarm",
	"simulate.html.result": "Sonuç",
	"simulate.html.misses": "Kaçırılanlar",
	"simulate.html.fps": "Yanlış alarmlar",
	"simulate.html.noMisses": "Kaçırılan yok: sayılan her örnek en az beklenen düzeyde işaretlendi.",
	"simulate.html.noFp": "Yanlış alarm yok: her zararsız ikize izin verildi.",
	"simulate.html.case": "Örnek",
	"simulate.html.expected": "Beklenen",
	"simulate.html.actual": "Sonuç",
	"simulate.html.flaggedAs": "İşaretlenme",
	"simulate.html.description": "Açıklama",
	"simulate.html.footer":
		"Bu rapor, yerelde gelen tespit kurallarının zararsızlaştırılmış test örnekleri üzerindeki sonucunu gösterir. Öz sınama sırasında hiçbir komut çalıştırılmadı ve hiçbir ağ isteği yapılmadı.",
	"status.unprotectedNone": "Singularity AIDR korumasıyla çalışmayan yapay zekâ aracı: bulunmadı.",
	"status.unprotected":
		"! Singularity AIDR korumasıyla çalışmayan yapay zekâ araçları (komutları, dosya değişiklikleri ve web istekleri İNCELENMİYOR): {tools}",
	"coverage.unprotected":
		"Bu bilgisayarda Singularity AIDR'nin korumadığı yapay zekâ araçları bulundu: {tools}. Yukarıdaki kapsam bu araçlar için geçerli değildir.",
	"coverage.unprotectedNone":
		"Bu bilgisayarda Singularity AIDR bağlayıcısı olmayan bir yapay zekâ aracı bulunmadı.",
	"approvals.dashboardHeader": "Singularity AIDR panelindeki onay istekleri ({count}):",
	"approvals.dashboardLine": "  {requestId}  {status}  araç: {tool}  bitiş: {expiresAt}",
	"approvals.dashboardLink": "    {url}",
	"approvals.dashboardStatus.pending": "bir yöneticinin kararını bekliyor",
	"approvals.dashboardStatus.approved":
		"onaylandı: yapay zekâ aracından aynı işlemi yeniden yapmasını isteyin",
	"approvals.dashboardStatus.denied": "reddedildi",
	"approvals.dashboardStatus.expired": "süresi doldu",
	"approvals.dashboardStatus.unknown": "durum bilinmiyor (panele ulaşılamadı)",
	"reportFp.invalidId":
		"Engelleme mesajındaki kimliği verin (8 ile 64 arası onaltılık karakter), örneğin: aidr report-fp 1a2b3c4d",
	"reportFp.invalidReason": 'Bilinmeyen neden "{reason}". Şunlardan birini kullanın: {reasons}.',
	"reportFp.notFound":
		"Yerel denetim kaydında ({path}) {id} kimlikli engellenmiş ya da onaya bekletilmiş bir işlem bulunamadı. Kayıt kapalı ya da döndürülmüş olabilir; bunun yerine engelleme mesajını BT veya güvenlik ekibinize iletin.",
	"reportFp.ambiguous": "{id} kimliği {count} işlemle eşleşiyor; daha fazla karakter verin:",
	"reportFp.found":
		"İşlem {id}: {rule} kuralı tarafından {decision} ({severity}), araç {tool}, zaman {time}.",
	"reportFp.decision.deny": "engellendi",
	"reportFp.decision.ask": "onaya bekletildi",
	"reportFp.sent":
		"Yanlış alarm olarak bildirildi (bildirim {reportId}). BT veya güvenlik ekibiniz bunu Singularity AIDR konsolunda inceler; bir istisna ekleyene kadar hiçbir şeye izin verilmez.",
	"reportFp.duplicate":
		"Bu bildirim zaten yapılmış (bildirim {reportId}); ikinci kez kaydedilmedi.",
	"reportFp.local":
		"Bu bilgisayar bir Singularity AIDR konsoluna bağlı değil, bu yüzden bildirim gönderilmedi. Yukarıdaki satırı BT veya güvenlik ekibinize iletin.",
	"reportFp.failed":
		"Bildirim gönderilemedi ({error}). Yukarıdaki satırı BT veya güvenlik ekibinize iletin ya da daha sonra yeniden deneyin.",
	"reportFp.support": "BT veya güvenlik ekibiniz: {url}",
	"reportFp.dryRun": "Deneme çalıştırması: hiçbir şey gönderilmedi.",
	"heartbeat.none": "Sinyal: bu cihazda desteklenen bir yapay zekâ aracı bulunamadı.",
	"heartbeat.line": "  {connector}: {state} ({enforcement})",
	"heartbeat.localMode":
		"Sinyal: yerel kip, hiçbir şey gönderilmedi. Kanca kaldırma uyarıları için yönetilen (kayıtlı) kurulum gerekir.",
	"heartbeat.dryRun": "Sinyal: deneme çalıştırması, hiçbir şey gönderilmedi.",
	"heartbeat.sent": "{count} yapay zekâ aracı için sinyal gönderildi.",
	"heartbeat.failed":
		"Sinyal gönderilemedi ({error}). Sinyaller kesilirse yönetim paneli 'ajan çevrim dışı' uyarısı verir.",
	"machineHooks.noBundle":
		"machine-hooks kurulu AIDR paketine ihtiyaç duyar (paketin 'aidr' dosyasıyla çalıştırın ya da --bundle-root <dizin> verin).",
	"machineHooks.needsAdmin":
		"machine-hooks sistem geneli araç ilkesini yazar: root olarak (Linux) ya da yönetici komut isteminden (Windows) çalıştırın.",
	"machineHooks.bundleRefused":
		"{root} konumundaki AIDR paketi doğrulanamadı; sistem geneli hiçbir kanca kaydedilmedi: {problems}",
	"machineHooks.installTitle":
		"Sistem geneli AIDR kancaları (bu makinedeki her kullanıcıya uygulanır):",
	"machineHooks.precedenceNote":
		'Not: Claude Code ilkesi ayrıca sunucu tarafı yönetilen ayarlardan, MDM\'den ya da HKLM kayıt defterinden geliyorsa o kaynak dosyalardan önce gelir; bu kancaları oraya ekleyin ya da managedSourcesBehavior değerini "merge" yapın (Claude Code 2.1.242+).',
	"machineHooks.editorsNote":
		"Cursor ve VS Code: eklentinin 'Korumayı kapat' komutunu reddetmesi ve silinen kancaları geri koyması için AIDR makine ilkesinde protection_locked değerini açın.",
	"machineHooks.statusRegistered":
		"  {host}: {path} içinde kayıtlı; diğer kancalar engelli: {locked}; yalnızca yönetici değiştirebilir: {tamper}",
	"machineHooks.statusAbsent": "  {host}: {path} içinde kayıtlı değil",
	"machineHooks.lockedYes": "evet",
	"machineHooks.lockedNo": "hayır",
	"machineHooks.tamperYes": "evet",
	"machineHooks.tamperNo": "HAYIR (yönetici olmayan biri değiştirebilir)",
	"machineHooks.tamperUnknown": "bu platformda ölçülmedi (dosya izinlerini denetleyin)",
	"doctor.codexTrustUntrusted":
		"Codex, AIDR kancasına güvenmiyor ({events}): Codex güvenilmeyen kancayı uyarmadan atlar, bu çağrılar denetlenmez.",
	"doctor.codexTrustDisabled":
		"AIDR Codex kancası Codex içinde kapatılmış ({events}); bu çağrılar denetlenmez.",
	"doctor.codexTrustRecorded":
		"Codex'te AIDR kancası için güven kaydı var ({events}); AIDR, Codex'in özetini yeniden hesaplayamaz, kanca değiştiyse /hooks komutunu bir kez çalıştırın.",
	"doctor.codexTrustManaged":
		"AIDR Codex kancası makine ilkesiyle kurulmuş; Codex ona incelemeden güvenir.",
	"doctor.codexTrustFix":
		"Çözüm: Codex'i açın, /hooks ile AIDR kancalarına güvenin ya da bir yöneticiye 'aidr machine-hooks install' komutunu çalıştırtın; Codex ilke yoluyla güvenir.",
	"setup.unknownHost": "Bilinmeyen araç: {hosts}. Geçerli araçlar: {valid}.",
	"setup.noneGiven": "(yok)",
	"setup.failed": "Kurulum başarısız: {reason}",
	"setup.action.notSelected": "bulundu — seçilmedi",
	"setup.confirmRequired":
		"Bu adım operatör onayı gerektirir: aidr setup komutunu etkileşimli bir terminalde çalıştırıp '{word}' yazın ya da otomasyon için AIDR_OPERATOR_NONINTERACTIVE=1 ayarlayıp --yes verin. Hiçbir şey değiştirilmedi.",
	"setup.force.title": "Singularity AIDR — zorunlu yeniden kurulum",
	"setup.force.effect": "Mevcut yerel yapılandırma ve CLI kimlik bilgisi değiştirilecek.",
	"setup.artifacts.title": "Singularity AIDR — bağlayıcı paketlerini kur",
	"setup.artifacts.claude": "  Claude Code eklenti dizini: {path}",
	"setup.artifacts.cursor": "  Cursor eklentisi: {path}",
	"setup.artifacts.vscode": "  VS Code eklentisi: {path}",
	"setup.artifacts.verifyOnly":
		"Yalnızca imzalı sürüm paketine göre doğruladığınız paketleri kurun.",

	"conn.unavailable": "AIDR, yapay zekâ aracındaki kaydı okuyamadı; kurulum durumu bilinmiyor",
	"conn.unavailableRemedy":
		"Dosya izinlerini denetleyin ve 'aidr status' komutunu yapay zekâ aracını çalıştıran kullanıcıyla yeniden çalıştırın",
	"conn.machinePolicy":
		"AIDR hook'ları {path} içindeki makine politikasıyla kuruldu{locked}; kullanıcılar bunları kapatamaz; yapay zekâ aracının onları çalıştırdığı doğrulanmadı",
	"conn.machinePolicyLocked": " (yalnızca yönetilen hook'lar çalışır)",
	"conn.claude.installed":
		"AIDR eklentisi etkin ya da PreToolUse işleyicisi kayıtlı; yapay zekâ aracının onu çalıştırdığı doğrulanmadı",
	"conn.claude.present": "~/.claude/settings.json var ama AIDR'ye hiç başvurmuyor",
	"conn.claude.presentRemedy":
		"Claude eklentisini çıkarmadan önce yayıncı imzalı sürüm paketini doğrulayın, çıkardığınız dizini marketplace olarak ekleyin, ardından aidr@aidr eklentisini kurun",
	"conn.claude.none": "~/.claude klasörü ya da ~/.claude.json bulunamadı",
	"conn.claude.installedNoSettings": "Claude Code kurulu (~/.claude) ama AIDR kayıtlı değil",
	"conn.claude.noneRemedy": "AIDR eklentisini Claude Code marketplace'inden kurun",
	"conn.editor.installed":
		"eklenti paketi bulundu: {packages}; etkinleşmesi ve hook'ların çalışması doğrulanmadı",
	"conn.editor.present": "{label} yapılandırma dizini var ama AIDR eklentisi bulunamadı",
	"conn.editor.presentRemedy":
		"VSIX dosyasını kurun, ardından komut paletinden 'Singularity AIDR: Enable protection' komutunu çalıştırın",
	"conn.editor.none": "{label} yapılandırma dizini bulunamadı",
	"conn.openclaw.installed":
		"AIDR eklentisi ~/.openclaw/openclaw.json içinde etkin; yapay zekâ aracının onu çalıştırdığı doğrulanmadı",
	"conn.openclaw.disabled":
		"AIDR eklentisi kayıtlı ama OpenClaw eklenti politikası onu devre dışı bırakmış",
	"conn.openclaw.disabledRemedy":
		"aidr-openclaw eklentisini plugins.entries içinde etkinleştirin ve OpenClaw allow/deny politikasında ona izin verin",
	"conn.openclaw.present": "~/.openclaw/openclaw.json var ama AIDR'yi listelemiyor",
	"conn.openclaw.presentRemedy":
		"Onaylı sürümü kurun: openclaw plugins install npm:@singularityrd/aidr-openclaw@{version} ({version} bu CLI ile eşleşir; onaylı sürüm kaydıyla karşılaştırın)",
	"conn.openclaw.none": "~/.openclaw/openclaw.json bulunamadı",
	"conn.opencode.npm":
		"AIDR npm eklentisi OpenCode yapılandırmasında listeleniyor; yapay zekâ aracının onu çalıştırdığı doğrulanmadı",
	"conn.opencode.local":
		"AIDR yerel eklenti dosyası bulundu: {files}; yapay zekâ aracının onu çalıştırdığı doğrulanmadı",
	"conn.opencode.present": "OpenCode yapılandırmasında kayıtlı bir AIDR eklentisi yok",
	"conn.opencode.none": "OpenCode yapılandırma dizini bulunamadı",
	"conn.opencode.remedy":
		"Onaylı @singularityrd/aidr-opencode sürümünü package.json dosyasına ekleyin ve opencode.json içinde kaydedin",
	"conn.codex.toml":
		"AIDR PreToolUse işleyicisi ~/.codex/config.toml içinde kayıtlı; Codex'in ona güvendiği ve onu çalıştırdığı doğrulanmadı",
	"conn.codex.lowercase":
		"config.toml küçük harfli bir hooks.pre_tool_use tablosu kullanıyor; Codex bu tabloyu okur ama YOK SAYAR - hook hiç çalışmaz",
	"conn.codex.lowercaseRemedy":
		"Tabloyu [[hooks.PreToolUse]] olarak yeniden adlandırın ve içine bir [[hooks.PreToolUse.hooks]] işleyicisi ekleyin",
	"conn.codex.json":
		"AIDR PreToolUse işleyicisi ~/.codex/hooks.json içinde kayıtlı; Codex'in ona güvendiği ve onu çalıştırdığı doğrulanmadı",
	"conn.codex.programMissing":
		"AIDR hook'u {source} içinde kayıtlı, ama programı {program} bulunamıyor; Codex her çağrıyı incelenmeden çalıştırır (fail-open)",
	"conn.codex.programMissingRemedy":
		"@singularityrd/aidr-codex paketini (ya da bağımsız paketi) yeniden kurun, ardından 'aidr setup --host codex' çalıştırın",
	"conn.codex.present": "Codex dizini var ama hiçbir AIDR hook'u kaydetmiyor",
	"conn.codex.presentRemedy":
		"aidr-codex-hook komutunu çalıştıran bir işleyiciyle [[hooks.PreToolUse]] tablosu ekleyin",
	"conn.codex.none": "~/.codex yapılandırması bulunamadı",
	"conn.state.unavailable": "bilinmiyor (okunamadı)",
	"conn.state.runtime_present_not_installed": "araç var, AIDR kurulu değil",
	"conn.state.not_detected": "bulunamadı",
	"conn.state.installed_but_degraded": "kayıtlı ama çalışmıyor",

	"install.machinePolicy":
		"AIDR hook'ları makine politikasıyla ({path}) her kullanıcı için kuruldu; kullanıcı yapılandırmasına dokunulmadı.",
	"install.bundleFailed":
		"{root} konumundaki kurulu AIDR paketi doğrulanamadı: {problems}. Paketi yeniden kurun.",
	"install.probeDecision":
		"engellenmesi gereken deneme girdisine {decision} yanıtı verdi ({detail})",
	"install.probeBenign": "zararsız 'ls' komutunu da engelledi ({detail})",
	"install.backedUp": "{path} yedeklendi: {backup}",
	"install.wrote": "yazıldı: {path}",
	"install.ran": "çalıştırıldı: {command}",
	"install.wouldRun": "çalıştırılacak: {command}",
	"install.notOnPath": "{cli} komut satırı aracı PATH üzerinde değil.",
	"install.notAFile": "{path} bir dosya değil.",
	"install.notObject": "{path} dosyasındaki '{field}' değeri bir nesne değil; dosyaya dokunulmadı.",
	"install.notArray": "{path} dosyasındaki '{field}' değeri bir dizi değil; dosyaya dokunulmadı.",
	"install.codex.tomlRegistered":
		"AIDR hook'u ~/.codex/config.toml içinde zaten kayıtlı; olduğu gibi bırakıldı.",
	"install.codex.byHand":
		"  Codex: aidr-codex-hook komutunu packages/codex/README.md dosyasında gösterildiği gibi elle kaydedin.",
	"install.codex.trust1":
		"  Codex: üç AIDR hook'unu /hooks ile inceleyip güvenilir olarak işaretleyin. Codex güvenilmeyen",
	"install.codex.trust2":
		"         bir hook'u sessizce atlar (açık kalır); bu yüzden koruma ancak onaydan sonra başlar.",
	"install.codex.jsonRegistered": "AIDR hook'ları ~/.codex/hooks.json içinde zaten kayıtlı.",
	"install.codex.notOnPath":
		"{hook} PATH üzerinde değil; kaydedilirse Codex var olmayan bir hook'u çalıştırmaya çalışır (Codex bu durumda açık kalır).",
	"install.codex.installPackage":
		"  Codex: @singularityrd/aidr-codex@{version} paketini özel kayıt deposundan kurun, ardından 'aidr setup' komutunu yeniden çalıştırın.",
	"install.codex.wouldRegister":
		"{hook} ({binary}), {path} içinde PreToolUse, UserPromptSubmit ve PostToolUse için kaydedilecek.",
	"install.codex.probeFailed": "paketin Codex hook'u {reason}; kayıt değiştirilmedi.",
	"install.codex.registered": "{hook}, {path} içinde kaydedildi.",
	"install.codex.notSeen": "{path} yazıldı ama Codex denetimi hook'u görmüyor ({detail}).",
	"install.opencode.jsonc":
		"OpenCode, opencode.jsonc ile yapılandırılmış; AIDR bu dosyayı yeniden yazmaz (içindeki yorumlar kaybolurdu).",
	"install.opencode.jsoncStep1":
		'  OpenCode: opencode.jsonc içindeki "plugin" listesine "{package}" girdisini ekleyin ve',
	"install.opencode.jsoncStep2": "            {path} dosyasına {dependencies} ekleyin.",
	"install.opencode.follow1":
		"  OpenCode: paketi bir sonraki açılışta kurar; özel kayıt deposuna erişilebilmelidir",
	"install.opencode.follow2":
		"            (docs/package-installation.md). Ardından araç tarafında bir engelleme denemesi yapın.",
	"install.opencode.already": "{package}@{version} zaten kayıtlı.",
	"install.opencode.wouldPin":
		"{package}@{version}, {manifest} dosyasına sabitlenecek ve {config} içinde listelenecek.",
	"install.opencode.registered": "{package}@{version} kaydedildi.",
	"install.opencode.notSeen":
		"OpenCode yapılandırması yazıldı ama denetim eklentiyi görmüyor ({detail}).",
	"install.openclaw.already": "AIDR eklentisi ~/.openclaw/openclaw.json içinde zaten etkin.",
	"install.openclaw.enablePolicy":
		"aidr-openclaw eklentisini OpenClaw eklenti politikasında etkinleştirin",
	"install.openclaw.thenCanary":
		"            ardından araç tarafında bir engelleme denemesi yapın.",
	"install.openclaw.installed": "{spec} kuruldu.",
	"install.openclaw.canary": "  OpenClaw: araç tarafında bir engelleme denemesi yapın.",
	"install.openclaw.notRegistered": "openclaw plugins install AIDR'yi kaydetmedi ({reason}).",
	"install.editor.enable":
		"  {label}: komut paletinden 'Singularity AIDR: Enable protection' komutunu çalıştırın.",
	"install.editor.passVsix": "{detail}; güncellemek için --{host}-vsix <file> verin.",
	"install.editor.noVsix": "doğrulanmış bir {artifact} verilmedi (--{host}-vsix <file>).",
	"install.editor.fromBundle":
		"  {label}: {cli} --install-extension ./{artifact} (doğrulanmış sürüm paketinden)",
	"install.editor.installed": "{extension}, {path} dosyasından kuruldu.",
	"install.editor.notRegistered": "eklenti kurulumu AIDR'yi kaydetmedi ({reason}).",
	"install.claude.manual1":
		"  Claude Code:  yayıncı imzalı sürüm paketini doğrulayıp aidr-claude-plugin-<version>.tar.gz dosyasını çıkarın,",
	"install.claude.manual2":
		"                sürümün Ed25519 açık anahtarını ~/.singularity-aidr/config.json içine ekleyin, ardından şunu çalıştırın:",
	"install.claude.manual3":
		"                aidr setup --claude-plugin-dir /absolute/path/to/extracted/aidr-claude-plugin",
	"install.claude.manual4":
		"                (ya da Claude Code isteminden: /plugin marketplace add <dir> ve /plugin install aidr@aidr).",
	"install.claude.noDir": "doğrulanmış bir eklenti dizini verilmedi (--claude-plugin-dir <dir>).",
	"install.claude.notPlugin":
		"{dir} çıkarılmış bir AIDR Claude Code eklentisi değil (.claude-plugin bildirimi yok).",
	"install.claude.cmdFailed": "claude {args} başarısız oldu ({reason}).",
	"install.claude.installed": "aidr@aidr doğrulanmış eklenti dizininden kuruldu.",
	"install.claude.restartPlugin":
		"  Claude Code: yeniden başlatın ve eklentinin etkin olduğunu doğrulayın (/plugin).",
	"install.claude.notRegistered": "eklenti kurulumu AIDR'yi kaydetmedi ({detail}).",
	"install.claude.disableAll":
		"Claude Code'da disableAllHooks ayarlı; bu yüzden hiçbir hook çalışmaz.",
	"install.claude.disableAllStep":
		"  Claude Code: ~/.claude/settings.json dosyasından \"disableAllHooks\" ayarını kaldırın, ardından 'aidr setup' komutunu yeniden çalıştırın.",
	"install.claude.pluginEnabled":
		"AIDR Claude Code eklentisi etkin; bağımsız hook'lar eklenmedi (her çağrıyı iki kez denetlerlerdi).",
	"install.claude.standaloneAlready": "{root} konumundaki AIDR hook'ları zaten kayıtlı.",
	"install.claude.wouldRegister": "{root} hook'ları {path} içinde kaydedilecek.",
	"install.claude.probeFailed": "paketin PreToolUse hook'u {reason}; kayıt değiştirilmedi.",
	"install.claude.registered":
		"{root} konumundaki AIDR hook'ları kaydedildi (yerel engelleme denemesi başarılı).",
	"install.claude.notSeen": "{path} yazıldı ama Claude Code denetimi hook'u görmüyor ({detail}).",
	"install.claude.restartHooks":
		"  Claude Code: AIDR hook'larını yüklemesi için yeniden başlatın, ardından 'aidr verify' çalıştırın.",

	"remove.codex.byHand":
		"  Codex: aidr-codex-hook işleyicilerini ~/.codex/hooks.json / config.toml dosyalarından elle kaldırın.",
	"remove.codex.none": "kayıtlı AIDR hook'u yok.",
	"remove.codex.would": "{count} aidr-codex-hook işleyicisi kaldırılacak.",
	"remove.codex.removed": "{count} aidr-codex-hook işleyicisi kaldırıldı.",
	"remove.codex.package":
		"  Codex: genel @singularityrd/aidr-codex paketi kurulu bırakıldı; npm uninstall --global @singularityrd/aidr-codex ile kaldırın.",
	"remove.opencode.none": "kayıtlı AIDR eklentisi yok.",
	"remove.opencode.byHand":
		'  OpenCode: "{package}" girdisini opencode.json "plugin" listesinden ve package.json dosyasından elle kaldırın.',
	"remove.would": "AIDR şuralardan kaldırılacak: {files}.",
	"remove.removedFrom": "AIDR şuralardan kaldırıldı: {files}.",
	"remove.deleted": "silindi: {path}",
	"remove.stillRegistered":
		"Yapay zekâ aracının komut satırı aracı çalıştıktan sonra AIDR hâlâ kayıtlı{reason}.",
	"remove.hostRemoved": "yapay zekâ aracının komut satırı aracı AIDR'yi kaldırdı.",
	"remove.claude.none": "etkin bir AIDR marketplace eklentisi yok.",
	"remove.claude.manual":
		"  Claude Code: /plugin uninstall aidr@aidr ve /plugin marketplace remove aidr",

	"uninstall.title": "Singularity AIDR — kaldırma",
	"uninstall.titleHooks": "Singularity AIDR — kaldırma (yalnızca yönetilen hook'lar)",
	"uninstall.targetHome": "Hedef ev dizini: {home}",
	"uninstall.refused": "Reddedildi: {reason}",
	"uninstall.refusedTarget": "hedef doğrulanamadı.",
	"uninstall.refusedInstall": "kurulum doğrulanamadı.",
	"uninstall.hooksRemoved":
		"Claude Code yönetilen hook'ları: {count} tane kaldırıldı (yedek: {backup}).",
	"uninstall.hooksRefused": "Claude Code yönetilen hook'ları: KALDIRILMADI — {reason}",
	"uninstall.refusedWord": "reddedildi",
	"uninstall.hooksWould": "Claude Code yönetilen hook'ları: {count} tane kaldırılacak.",
	"uninstall.action.removed": "kaldırıldı",
	"uninstall.action.nothingToRemove": "kaldırılacak bir şey yok",
	"uninstall.action.wouldRemove": "kaldırılacak",
	"uninstall.data.deleted":
		"{path} silindi (yapılandırma, izin listesi, denetim kaydı, onaylar, karantina, anahtarlar)",
	"uninstall.data.kept": "{path} korundu{reason}",
	"uninstall.data.wouldDelete": "{path} ve AIDR kasa öğeleri silinecek",
	"uninstall.data.absent": "{path} yok",
	"uninstall.data.failed": "{path} SİLİNEMEDİ: {reason}",
	"uninstall.unknownError": "bilinmeyen hata",
	"uninstall.localData": "Yerel veriler: {line}",
	"uninstall.vaultRemoved": "Kaldırılan kasa öğeleri: {items}",
	"uninstall.vaultFailed": "KALDIRILAMAYAN kasa öğeleri: {items}",
	"uninstall.byHand": "Elle yapılması gerekenler:",
	"uninstall.dryRun": "Deneme: hiçbir şey değiştirilmedi.",
	"uninstall.incomplete":
		"Kaldırma TAMAMLANMADI: yukarıdaki satırlara bakın. AIDR bazı yapay zekâ araçlarını hâlâ denetliyor olabilir.",
	"uninstall.removed":
		"AIDR kaldırıldı. AIDR'yi bırakmaları için yapay zekâ araçlarınızı yeniden başlatın.",
	"uninstall.browserGuard":
		"Browser Guard bir tarayıcı eklentisidir: onu tarayıcıdan (ya da kurumsal politikadan) ayrıca kaldırın.",
	"uninstall.nothing": "Kaldırılacak bir şey yok.",
	"uninstall.notRemoved": "{error} Hiçbir şey kaldırılmadı.",
	"uninstall.receiptVerified":
		"Kurulum makbuzu doğrulandı: {path} (bağlayıcı {connector}, özet {digest}…)",
	"uninstall.reasonCode": "Neden kodu: {code}",
	"uninstall.noConfigChanged": "Hiçbir yapılandırma değiştirilmedi.",
	"uninstall.noManagedHooks":
		"AIDR'nin yönettiği bir hook girdisi bulunamadı; yapay zekâ aracı ayarlarına dokunulmadı.",
	"uninstall.leftAlone":
		"Dokunulmayanlar: {entries} hook {entryWord} ve AIDR'ye ait olmayan {hooks} hook kaydı.",
	"uninstall.entry": "girdisi",
	"uninstall.entries": "girdisi",
	"uninstall.removedCount": "AIDR'nin yönettiği {count} hook kaydı kaldırıldı:",
	"uninstall.noCommand": "(kayıtlı komut yok)",
	"uninstall.emptyEvents": "Boş kaldığı için silinen hook olayları: {events}",
	"uninstall.backup": "Önceki ayarların yedeği: {path}",
	"uninstall.preserved":
		"Korunanlar: AIDR politika/izin listesi yapılandırması, bağlayıcı dosyaları, kurulum makbuzu ve AIDR'ye ait olmayan her hook.",
	"uninstall.credentialKept":
		"Yerel CLI kimlik bilgisi ve kasa öğesi de korundu; bu kimlik bilgisini kaldırmak için 'aidr config revoke-key' kullanın. Yönetilen uç nokta API anahtarları değişmedi.",
	"uninstall.notActive":
		"Bu yapay zekâ aracı için koruma artık ETKİN DEĞİL: AIDR araç çağrılarını denetlemiyor.",
	"uninstall.reEnable":
		"Yeniden etkinleştirmek için 'aidr setup' çalıştırın ve yapay zekâ aracınızın bağlayıcısını kurun (docs/getting-started.md).",
	"uninstall.remedy.receipt":
		"Neyin kayıtlı olduğunu görmek için 'aidr status' çalıştırın. Claude Code marketplace kurulumunun makbuzu yoktur: '/plugin uninstall aidr@aidr' ve '/plugin marketplace remove aidr' ile kaldırın. AIDR elle ya da bir MDM ile kurulduysa, onu kuran araçla kaldırın.",
	"uninstall.remedy.settings":
		"Önce yapay zekâ aracınızın ayar dosyasını onarın ya da geri yükleyin; dosyaya dokunulmadı.",
	"uninstall.remedy.default":
		"Yeniden denemeden önce ölçülen kurulum durumunu görmek için 'aidr status' çalıştırın.",
	"uninstall.confirm.hooksTitle":
		"Singularity AIDR — yönetilen yapay zekâ aracı hook'larını kaldır",
	"uninstall.confirm.hooksEffect":
		"AIDR bu yapay zekâ aracının araç çağrılarını artık denetlemeyecek.",
	"uninstall.confirm.removes":
		"  AIDR bağlayıcısını her yapay zekâ aracından, AIDR'nin yönettiği hook'larla birlikte kaldırır.",
	"uninstall.confirm.keeps":
		"  ~/.singularity-aidr dizinini ve AIDR kasa öğelerini korur (--keep-data).",
	"uninstall.confirm.deletes":
		"  ~/.singularity-aidr dizinini (yapılandırma, izin listesi, denetim kaydı, onaylar,\n  karantinadaki dosyalar, anahtarlar) ve işletim sistemi kimlik kasasındaki AIDR öğelerini SİLER.",
	"uninstall.confirm.effect":
		"AIDR hiçbir yapay zekâ aracının araç çağrılarını artık denetlemeyecek.",

	"scan.usageTitle": "AIDR altyapı ve beceri taraması",
	"scan.noTargets": "Hedef verilmedi.",
	"scan.usage": "Kullanım:",
	"scan.usageFile": "  aidr scan --file targets.txt          # her satırda bir URL",
	"scan.usageSkill":
		"  aidr scan --skill ~/.claude/skills/my-skill   # beceri/eklenti paketi (T01-T09)",
	"scan.usageCode":
		"  aidr scan --code .                     # model yükleme + güvenli kod kuralları, dosya:satır",
	"scan.options": "Seçenekler:",
	"scan.optJson": "  --json             makinece okunabilir çıktı",
	"scan.optAllowPublic":
		"  --allow-public     özel ağ dışındaki hedeflere de izin ver (varsayılan: kapalı)",
	"scan.optTimeout": "  --timeout <ms>     istek başına zaman aşımı (varsayılan 3000)",
	"scan.optConcurrency": "  --concurrency <n>  aynı anda taranan hedef sayısı (varsayılan 4)",
	"scan.optUpload":
		"  --upload           bulguları yönetilen kontrol düzlemine gönder (kayıtlı API anahtarıyla)",
	"scan.dataset":
		"Veri kümesi: {fingerprints} parmak izi, {cves} CVE (AI-Infra-Guard'dan derlendi).",

	"discover.localProcess": "yerel süreç",
	"discover.project": " (proje {project})",
	"discover.noRiskHint": "Yapılandırılmış bir risk göstergesi yok; güvenilirlik doğrulanmadı",
	"discover.aigCategories": "    AIG kategorileri: {categories}",
	"discover.aigNone": "    AIG kategorileri: eşleşen yok (bu bir güvenlik kararı değildir)",
	"discover.secret":
		"    Koda gömülü gizli bilgi: {location} {key} ({kind}) - bir gizli bilgi deposuna ya da ortam değişkeni başvurusuna taşıyın",
	"discover.header": "MCP keşfi: {count} yapılandırılmış sunucu",
	"discover.unreadable": "Okunamayan ya da desteklenmeyen yapılandırma: {path}",
	"discover.coverage": "Envanter kapsamı: {status}; listelenemeyen hatalı sunucu girdisi: {count}",
	"discover.agents": "Yapay zekâ aracı ortamı: {hosts} bulundu; {count} bulgu",
	"discover.noAgentHost": "hiçbir yapay zekâ aracı",
	"discover.unreadableAgent": "Okunamayan yapay zekâ aracı yapılandırması: {path}",
	"discover.uploaded": "{count} MCP envanteri bulgusu kontrol düzlemine yüklendi.",
	"discover.uploadedAgents":
		"{count} MCP envanteri ve yapay zekâ aracı ortamı bulgusu kontrol düzlemine yüklendi.",
	"discover.uploadFailed": "Yükleme başarısız: {reason}.",
	"discover.queued": " {count} bulgu kuyrukta kaldı; bir sonraki gönderimde yeniden denenecek.",
	"discover.nothingUploaded": " Hiçbir şey yüklenmedi.",

	"privacy.unknownType":
		'Bilinmeyen tür "{type}". Geçerli türler: {valid} (diğer adları: {aliases})',
	"privacy.typesEmpty": "--types en az bir tür gerektirir",
	"privacy.badFailOn": '--fail-on none, any ya da secret olmalı (verilen: "{value}")',
	"privacy.notFound": "Dosya bulunamadı: {path}",
	"privacy.cannotRead": "{path} okunamıyor ({code})",
	"privacy.notRegular": "Normal bir dosya değil: {path}",
	"privacy.tooLarge":
		"Girdi {size}; gizlilik taraması en fazla {max} okur. Dosyayı bölüp parçaları ayrı ayrı tarayın.",
	"privacy.grew": "Girdi okunurken {max} sınırını aştı; gizlilik taraması en fazla {max} okur.",
	"privacy.stdinTooLarge":
		"Standart girdi {max} sınırını aşıyor; gizlilik taraması en fazla {max} okur. Girdiyi bölüp parçaları ayrı ayrı tarayın.",
	"privacy.binary":
		"Girdi ikili veri gibi görünüyor (NUL baytları içeriyor); gizlilik taraması yalnızca UTF-8 metni inceler.",
	"privacy.notUtf8":
		"Girdi geçerli bir UTF-8 metni değil; gizlilik taraması yalnızca UTF-8 metni inceler.",
	"privacy.more": "(+{count} tane daha)",
	"privacy.header": "AIDR gizlilik taraması: {source} ({bytes} bayt, yalnızca yerel)",
	"privacy.noFindingsPartial": "Girdinin incelenen kısmında bulgu yok.",
	"privacy.noFindings": "Seçilen algılayıcılar için bulgu yok.",
	"privacy.colType": "TÜR",
	"privacy.colCount": "ADET",
	"privacy.colLines": "SATIRLAR",
	"privacy.findings":
		"{count} bulgu. Değerler hiçbir zaman yazdırılmaz; maskelenmiş bir kopya için --mask kullanın.",
	"privacy.incomplete": "EKSİK: girdinin bir kısmı incelenmedi ({reasons}).",
	"privacy.notClean": "Bu temiz bir sonuç değildir; yukarıdaki bulgular yalnızca bir alt sınırdır.",
	"privacy.noInput":
		"Girdi yok: bir dosya yolu verin ya da metni standart girdiden aktarın (aidr privacy scan - < file).",
	"privacy.stdinSource": "standart girdi",
	"privacy.refuseMask":
		"Maskelenmiş kopya yazdırılmıyor: girdi tamamen incelenmedi, maskelenmemiş değerler kalmış olabilir.",
	"privacy.failed": "Gizlilik taraması başarısız: {name}",

	"coverage.badFormat": 'Bilinmeyen biçim "{format}". Şunlardan birini kullanın: {formats}.',
	"coverage.noMapping":
		"{path} konumunda çerçeve eşlemesi içeren bir kural kümesi bulunamadı. CLI'yi yeniden kurun ya da derleyin (resources/threats dizini {mapping} dosyasını içermelidir).",
	"coverage.invalidMapping": "{path} konumundaki çerçeve eşlemesi geçersiz:\n  {errors}",
	"coverage.noRules": "{path} konumundan hiçbir tespit kuralı yüklenmedi; raporlanacak kapsam yok.",
	"coverage.mismatch":
		"Uyarı: çerçeve eşlemesi kurulu kurallarla eşleşmiyor ({count} sorun):\n  {problems}",

	"config.unreadable":
		"Yerel yapılandırma okunamadı. Dosya izinlerini, JSON yapısını ve kimlik bilgisi deposunu denetleyin.",
	"config.notConfigured": "⚠️  AIDR yapılandırılmamış. Önce 'aidr setup' çalıştırın.",
	"config.notSet": "(ayarlanmamış)",
	"config.invalidPath": "Geçersiz yapılandırma yolu.",
	"config.secretArg":
		"Gizli değerler komut satırı argümanı olarak verilemez. Değeri gizli istemde girmek için komutu değer argümanı olmadan yeniden çalıştırın.",
	"config.setUsage":
		"⚠️  Kullanım: aidr config -s <key> <value> (gizli değerler güvenli biçimde sorulur)",
	"config.secretPrompt": "Gizli değer: ",
	"config.secretReadFailed": "Gizli girdi okunamadı.",
	"config.secretInObject":
		"Gizli alanlar nesne argümanlarının içinde verilemez. Her gizli alanı kendi gizli isteminden ayarlayın.",
	"config.unknownField": "Geçersiz ya da bilinmeyen yapılandırma alanı; değişiklik kaydedilmedi.",
	"config.invalid": "Geçersiz çalışma zamanı yapılandırması; değişiklik kaydedilmedi.",
	"config.invalidChoice":
		"  {key}: '{value}' geçerli bir değer değil. Geçerli değerler: {choices}.",
	"config.unknownFieldOnly": "Bilinmeyen yapılandırma alanı; değişiklik kaydedilmedi.",
	"config.confirmTitle": "Singularity AIDR — bir koruma ayarını değiştir",
	"config.confirmEffect":
		"Bu değişiklik AIDR'nin denetlediği ya da engellediği şeyleri zayıflatabilir.",
	"config.noChanges": "{error} Değişiklik kaydedilmedi.",
	"config.saveFailed":
		"Yapılandırma kaydedilemedi. Dosya izinlerini ve kimlik bilgisi deposunu denetleyip yeniden deneyin.",
	"config.set": "✅ {key} = {value} olarak ayarlandı",
	"config.listTitle": "🛡️  AIDR yapılandırması",
	"config.usage": "Kullanım:",
	"config.usageGet": "  aidr config -g <key>       Değeri oku",
	"config.usageSet": "  aidr config -s <key> <val> Gizli olmayan bir değer ayarla",
	"config.usageSecret": "  aidr config -s <secret-key> Gizli değeri gizli istemde gir",
	"config.usageList": "  aidr config -l             Tümünü listele",

	"simulate.fromConfig": "(yapılandırmadan)",
};
