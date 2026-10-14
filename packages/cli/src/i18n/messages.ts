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
	"doctor.lastVerdict": "Last verdict: {verdict} for {tool} at {time}.",
	"doctor.auditUnreadable": "Audit log unreadable.",
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
	"setup.configReused": "Config already present: {path}",
	"setup.configCreated": "Config: {path}",
	"setup.rerunNoChanges": "Configuration already in place — no changes were needed to it.",
	"setup.rerunConfig": "Existing config reused: {path}",
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
	"setup.incomplete": "⚠ Setup finished, but Protection is NOT yet active for every AI tool:",
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
	"doctor.lastVerdict": "Son karar: {tool} için {verdict}, {time}.",
	"doctor.auditUnreadable": "Denetim kaydı okunamadı.",
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
	"setup.configReused": "Yapılandırma zaten var: {path}",
	"setup.configCreated": "Yapılandırma: {path}",
	"setup.rerunNoChanges": "Yapılandırma zaten hazır — değişiklik gerekmedi.",
	"setup.rerunConfig": "Mevcut yapılandırma kullanıldı: {path}",
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
};
