#!/usr/bin/env node

import { VERSION } from "@singularityrd/aidr-core";
import { Command, Option } from "commander";
import aibomCommand from "./commands/aibom.js";
import {
	allowlistAddCommand,
	allowlistListCommand,
	allowlistRemoveCommand,
} from "./commands/allowlist.js";
import { approveCommand, pendingCommand } from "./commands/approvals.js";
import assistantCommand from "./commands/assistant.js";
import {
	auditExportCommand,
	auditRotateKeyCommand,
	auditTailCommand,
	auditVerifyCommand,
	auditVerifyResponseChainCommand,
} from "./commands/audit.js";
import {
	canaryDeployCommand,
	canaryListCommand,
	canaryRemoveCommand,
	canaryStatusCommand,
} from "./commands/canary.js";
import collectCommand from "./commands/collect.js";
import complianceVerifyCommand from "./commands/compliance.js";
import configCommand from "./commands/config.js";
import {
	revokeKeyCommand,
	rotateKeyCommand,
	SECRET_STORE_OPTION_DESCRIPTION,
} from "./commands/config-secret.js";
import coverageCommand from "./commands/coverage.js";
import discoverCommand from "./commands/discover.js";
import doctorCommand from "./commands/doctor.js";
import {
	exceptionAddCommand,
	exceptionListCommand,
	exceptionRemoveCommand,
} from "./commands/exceptions.js";
import heartbeatCommand from "./commands/heartbeat.js";
import {
	learningApproveCommand,
	learningExecuteCommand,
	learningExportAuthorityCommand,
	learningIngestCommand,
	learningKeygenCommand,
} from "./commands/learning.js";
import {
	machineHooksInstallCommand,
	machineHooksRemoveCommand,
	machineHooksStatusCommand,
} from "./commands/machine-hooks.js";
import privacyScanCommand from "./commands/privacy.js";
import { privacyNoticeCommand } from "./commands/privacy-notice.js";
import {
	profileListCommand,
	profileShowCommand,
	profileTestCommand,
	profileValidateCommand,
} from "./commands/profile.js";
import {
	quarantineDeleteCommand,
	quarantineListCommand,
	quarantineReleaseCommand,
	quarantineShowCommand,
	restoreCommand,
} from "./commands/quarantine.js";
import { reportFpCommand } from "./commands/report-fp.js";
import scanCommand from "./commands/scan.js";
import setupCommand from "./commands/setup.js";
import simulateCommand from "./commands/simulate.js";
import statusCommand from "./commands/status.js";
import supportBundleCommand from "./commands/support-bundle.js";
import uninstallCommand from "./commands/uninstall.js";
import updateCommand from "./commands/update.js";
import verifyCommand from "./commands/verify.js";
import { groupCommands, initCliLocale, localizeHelp } from "./i18n/index.js";

const program = new Command();

program
	.name("aidr")
	.description("Singularity AIDR command-line setup and diagnostics")
	.version(VERSION);

program
	.command("setup")
	.description(
		"Configure AIDR and install or update the connector of every detected agent host (idempotent)",
	)
	.option("-f, --force", "Replace an existing local configuration")
	.option("--secret-store <kind>", SECRET_STORE_OPTION_DESCRIPTION)
	.option("--dry-run", "Show what would be installed or updated; change nothing")
	.option(
		"--host <ids>",
		"Only these hosts, comma-separated: claude-code, cursor, vscode, openclaw, opencode, codex (default: every detected host)",
	)
	.option("--no-install", "Configure only and print the manual connector steps")
	.option(
		"--claude-plugin-dir <dir>",
		"Extracted, verified aidr-claude-plugin directory to install into Claude Code",
	)
	.option("--cursor-vsix <file>", "Verified aidr-cursor.vsix to install into Cursor")
	.option("--vscode-vsix <file>", "Verified aidr-vscode.vsix to install into VS Code")
	.option(
		"--release-key <file>",
		"Release public key (Ed25519 PEM) for a manual install; the desktop installers set it up themselves",
	)
	.option(
		"-y, --yes",
		"With AIDR_OPERATOR_NONINTERACTIVE=1, confirm --force or the installer's company connection without a prompt",
	)
	.action((options) => setupCommand(options));

const configProgram = program
	.command("config")
	.description("Read or update the local AIDR configuration")
	.option("-g, --get <key>", "Read a dotted configuration key")
	.option(
		"-s, --set <values...>",
		"Set a dotted key/value; enter secrets at the hidden prompt, never as arguments",
	)
	.option("-l, --list", "Print all configuration values")
	.action(configCommand);

configProgram
	.command("rotate-key")
	.description("Rotate the CLI setup credential (not a managed endpoint API key)")
	.option("--secret-store <kind>", SECRET_STORE_OPTION_DESCRIPTION)
	.option("--json", "Emit a machine-readable rotation receipt")
	.action(rotateKeyCommand);

configProgram
	.command("revoke-key")
	.description("Revoke the CLI setup credential (not a managed endpoint API key)")
	.option("--secret-store <kind>", SECRET_STORE_OPTION_DESCRIPTION)
	.option("--json", "Emit a machine-readable revocation receipt")
	.action(revokeKeyCommand);

program
	.command("status")
	.description("Show the local AIDR configuration and hook status")
	.option("--json", "Emit measured installation state without credentials")
	.action((options) => statusCommand(options));

program
	.command("verify")
	.description(
		"Pass a harmless canary (data only, never executed) through each registered connector's hook and report PASS/FAIL per host",
	)
	.option("--json", "Emit a machine-readable report")
	.action((options) => verifyCommand(options));

program
	.command("assistant")
	.description(
		"Open the Singularity AIDR Setup Assistant in your browser: a step-by-step setup on this computer (Windows, Linux)",
	)
	.option("--no-open", "Do not open a browser; print the one-time address instead")
	.action((options) => assistantCommand(options));

program
	.command("update")
	.description(
		"Update an installation from the Windows/Linux installers: verify the signed catalog and the installer's SHA-256, install silently, run 'aidr verify', roll back on failure",
	)
	.option("--check", "Only report whether a newer version is available; change nothing")
	.option(
		"--from <location>",
		"Installer file, portal mirror directory or https URL your administrator provides (instead of the portal)",
	)
	.option(
		"--catalog <location>",
		"Signed manifest.json for --from (default: next to the installer)",
	)
	.option(
		"--allow-downgrade",
		"Allow installing an older version (a rollback your administrator asked for)",
	)
	.option("-y, --yes", "With AIDR_OPERATOR_NONINTERACTIVE=1, install without a prompt")
	.option("--json", "With --check, emit a machine-readable result")
	.addOption(new Option("--auto", "Background install started by update.auto=install").hideHelp())
	.action((options) => updateCommand(options));

program
	.command("scan")
	.description(
		"Scan AI infrastructure targets, skill packages or project code (native, no external service)",
	)
	.option(
		"-t, --target <url...>",
		"Target base URL (repeatable). Loopback/private only unless --allow-public",
	)
	.option("-f, --file <path>", "Read targets from a file, one URL per line")
	.option(
		"--skill <path...>",
		"Scan a skill or plugin package directory with the T01-T09 skill rules (repeatable)",
	)
	.option(
		"--code <path...>",
		"Scan a project directory or file for unsafe model loading and insecure code patterns (file:line, local only)",
	)
	.option("--json", "Emit machine-readable JSON")
	.option("--allow-public", "Permit non-private targets (off by default)")
	.option("--timeout <ms>", "Per-request timeout in milliseconds", "3000")
	.option("--concurrency <n>", "Number of targets to scan in parallel", "4")
	.option("--save-report <path>", "Persist a scan report for the configured infrastructure policy")
	.option(
		"--upload",
		"Send findings (ids, severities, digests; no hosts, paths or secrets) to the managed control plane",
	)
	.action(scanCommand);

const privacyProgram = program
	.command("privacy")
	.description("Local TR/EN personal-data and secret checks (nothing is uploaded)");

privacyProgram
	.command("scan [file]")
	.description(
		"Scan a file or stdin for TCKN, IBAN, phone, e-mail, card, secret and other personal data; values are never printed",
	)
	.option("--json", "Emit findings as JSON (type, offsets, line; never the matched value)")
	.option("--mask", "Print the text with each finding replaced by its [TYPE] placeholder")
	.option("--types <list>", "Comma-separated detector names to report (default: all)")
	.option(
		"--fail-on <mode>",
		"Findings that exit 2: none, any (default) or secret; otherwise an incomplete inspection exits 3",
		"any",
	)
	.action(privacyScanCommand);

privacyProgram
	.command("notice")
	.description(
		"Show what Singularity AIDR guards and does not guard, what it records on this computer and what it sends where",
	)
	.option("--json", "Print the facts the notice is built from")
	.action((options) => privacyNoticeCommand(options));

program
	.command("simulate")
	.description(
		"Defensive self-test: feed defanged detection fixtures to the local evaluator and report what AIDR detects (never executes anything)",
	)
	.option(
		"--suite <names>",
		"Comma-separated categories to run (injection, exfiltration, destructive, encoding, supply-chain, mcp, self-defense, privacy)",
	)
	.option("--sensitivity <level>", "Override sensitivity: paranoid, balanced or relaxed")
	.option("--format <format>", "Output format: table, json or html", "table")
	.option("--output <file>", "Write the report to a file instead of stdout")
	.option(
		"--min-score <n>",
		"Exit non-zero when the overall detection score is below N (0-100; default 90, 0 = report only)",
	)
	.option(
		"--connector <name>",
		"Drive a built connector entry point instead of the in-process evaluator (claude-code, codex, cursor, vscode)",
	)
	.action(simulateCommand);

program
	.command("collect")
	.description("Continuously collect tenant-scoped AI infrastructure inventory")
	.requiredOption("--tenant <id>", "Tenant identifier recorded in the inventory")
	.option("--provider <id>", "Discovery provider: local, aws, azure, gcp or intune", "local")
	.option(
		"--provider-config <path>",
		"Tenant-bound cloud/Intune scope and credential references (JSON)",
	)
	.option("-t, --target <url...>", "Target base URL (repeatable)")
	.option("-f, --file <path>", "Read targets from a file, one URL per line")
	.option(
		"--inventory <path>",
		"Inventory output path (tenant-isolated default under ~/.singularity-aidr)",
	)
	.option(
		"--interval <seconds>",
		"Repeat without overlap every 10-86400 seconds; omitted means one run",
	)
	.option("--stale-after <minutes>", "Mark last-seen evidence stale after this age", "15")
	.option("--retry-attempts <n>", "Bounded attempts per unreachable target (1-5)", "3")
	.option("--retry-base-ms <ms>", "Initial retry backoff in milliseconds", "250")
	.option("--timeout <ms>", "Per-request timeout in milliseconds", "3000")
	.option("--concurrency <n>", "Maximum concurrently collected targets", "4")
	.option("--allow-public", "Permit non-private targets (off by default)")
	.option("--json", "Emit machine-readable inventory; interval mode emits JSON lines")
	.action(collectCommand);

program
	.command("discover")
	.description("Inventory local MCP servers with risk indicators and configuration fingerprints")
	.option("--config <paths...>", "Inspect explicit JSON configuration paths")
	.option("--json", "Emit a redacted machine-readable inventory")
	.option(
		"--agents",
		"Also check agent hosts for unsafe autonomy settings, missing AIDR hooks and environment exposure",
	)
	.option(
		"--upload",
		"Send server names, risk categories and digests (no paths, endpoints or arguments) to the managed control plane; with --agents also host, check id, severity and count per finding",
	)
	.action(discoverCommand);

program
	.command("aibom")
	.description(
		"Export an AI Bill of Materials (CycloneDX 1.6): agents, MCP servers, AI packages, models, plugins and known vulnerabilities; secrets are redacted",
	)
	.option("--format <format>", "cyclonedx-json or json (AIDR inventory)", "cyclonedx-json")
	.option("-o, --output <file>", "Write to a new file (0600) instead of stdout")
	.option("--path <project>", "Project directory whose manifests and MCP configs are read", ".")
	.option("--config <paths...>", "Inspect explicit MCP configuration paths instead of the defaults")
	.option(
		"--scan-report <path>",
		"Include a saved `aidr scan --save-report` result (defaults to the configured AI infrastructure report)",
	)
	.action(aibomCommand);

program
	.command("uninstall")
	.description(
		"Remove AIDR: the connector of every agent host, the AIDR-managed hooks, ~/.singularity-aidr and the AIDR vault items (confirmation required)",
	)
	.option(
		"--home <path>",
		"Target an explicit home directory (managed fleets and verification); defaults to the current user",
	)
	.option("--json", "Emit a machine-readable report")
	.option(
		"--keep-data",
		"Keep ~/.singularity-aidr (config, audit log, approvals) and the vault items",
	)
	.option("--dry-run", "Show what would be removed; change nothing")
	.option(
		"--host <ids>",
		"Only these hosts, comma-separated: claude-code, cursor, vscode, openclaw, opencode, codex (default: all)",
	)
	.option(
		"--hooks-only",
		"Remove only the receipt-managed Claude Code hooks, preserving everything else",
	)
	.option("-y, --yes", "Skip the prompt; honoured only with AIDR_OPERATOR_NONINTERACTIVE=1")
	.action((options) => uninstallCommand(options));

const learningProgram = program
	.command("learning")
	.description(
		"Explicit, signed behavioral learning with separate execution and approval authorities",
	);

learningProgram
	.command("keygen")
	.description("Create one operator authority; publish only its public key and private reference")
	.requiredOption("--role <role>", "Authority role: execution or approval")
	.requiredOption("--out <path>", "New private authority-reference JSON file (never overwritten)")
	.option("--secret-store <kind>", SECRET_STORE_OPTION_DESCRIPTION)
	.action(learningKeygenCommand);

learningProgram
	.command("export-authority")
	.description(
		"Export private signed broker policy and entitlement for an independent approval station",
	)
	.requiredOption("--runtime <runtime>", "Installed connector policy runtime")
	.requiredOption("--out <path>", "New private authority-handoff JSON file (never overwritten)")
	.action(learningExportAuthorityCommand);

learningProgram
	.command("execute")
	.description("Execute one allowed foreground Bash request and issue a verified success receipt")
	.requiredOption(
		"--runtime <runtime>",
		"Installed connector policy: claude-code, cursor, vscode, openclaw, opencode or codex",
	)
	.requiredOption(
		"--request <path>",
		"Strict JSON request with sessionId, toolName Bash, command and execution_shell",
	)
	.requiredOption("--key-ref <path>", "Private execution authority-reference file")
	.requiredOption("--out <path>", "New execution-receipt JSON file (never overwritten)")
	.action(learningExecuteCommand);

learningProgram
	.command("approve")
	.description(
		"Independently confirm benign execution and consent to learning at an interactive prompt",
	)
	.requiredOption("--runtime <runtime>", "Installed connector policy runtime")
	.requiredOption("--receipt <path>", "Signed execution-receipt JSON file")
	.requiredOption(
		"--request <path>",
		"The exact original request for independent benign classification",
	)
	.requiredOption(
		"--broker-authority <path>",
		"Private signed broker-authority handoff; verified against this station's fixed issuer roots",
	)
	.requiredOption(
		"--key-ref <path>",
		"Private approval authority-reference file in separate operator custody",
	)
	.requiredOption("--out <path>", "New approval-receipt JSON file (never overwritten)")
	.action(learningApproveCommand);

learningProgram
	.command("ingest")
	.description(
		"Verify both independent signatures and accept one bounded durable baseline observation",
	)
	.requiredOption("--runtime <runtime>", "Installed connector policy runtime")
	.requiredOption("--request <path>", "The exact original request JSON file")
	.requiredOption("--receipt <path>", "Signed execution-receipt JSON file")
	.requiredOption("--approval <path>", "Signed benign-consent approval JSON file")
	.action(learningIngestCommand);

program
	.command("doctor")
	.description(
		"Check AI tools, hook registration, release key, rules, mode, DLP policy, agent profiles, approvals and the last verdict; exits non-zero on problems",
	)
	.option("--json", "Emit a machine-readable report")
	.option("-v, --verbose", "Explain each check (paths, reasons, key storage)")
	.action((options) => doctorCommand(options));

program
	.command("heartbeat")
	.description(
		"Report whether each AI tool's AIDR hook is in place to the control plane (run hourly by the per-machine installers)",
	)
	.option("--json", "Print the measured report as JSON")
	.option("--dry-run", "Measure and print; send nothing")
	.option("--quiet", "Print only errors (for the scheduler)")
	.action((options) => heartbeatCommand(options));

const machineHooksProgram = program
	.command("machine-hooks")
	.description(
		"Deploy AIDR hooks through each AI tool's system-wide managed policy so users cannot remove or disable them (administrator)",
	);

machineHooksProgram
	.command("install")
	.description(
		"Register the hooks for every user of this machine (Claude Code managed settings, Codex system config)",
	)
	.option(
		"--lock-other-hooks",
		"Also make the hosts run only managed hooks (Claude Code allowManagedHooksOnly, Codex allow_managed_hooks_only)",
	)
	.option("--heartbeat", "Also schedule the hourly 'aidr heartbeat' for every user")
	.option(
		"--bundle-root <dir>",
		"Installed AIDR bundle whose hook binaries the hosts run (default: this bundle)",
	)
	.option("--dry-run", "Show what would change; change nothing")
	.option("--json", "Emit machine-readable results")
	.action((options) => machineHooksInstallCommand(options));

machineHooksProgram
	.command("remove")
	.description("Remove only AIDR's system-wide hook registrations")
	.option("--heartbeat", "Also remove the scheduled heartbeat")
	.option("--dry-run", "Show what would change; change nothing")
	.option("--json", "Emit machine-readable results")
	.action((options) => machineHooksRemoveCommand(options));

machineHooksProgram
	.command("status")
	.description(
		"Show where the system-wide AIDR hooks are registered and whether only administrators can change them",
	)
	.option("--json", "Emit machine-readable results")
	.action((options) => machineHooksStatusCommand(options));

program
	.command("support-bundle")
	.description(
		"Write a redacted diagnostic archive (versions, doctor checks, hooks, config, recent verdict metadata, rule hashes) for a support case",
	)
	.option("-o, --out <path>", "Archive path (.tar.gz); never overwrites an existing file")
	.option("--audit-entries <n>", "Recent audit verdicts to summarise (0-1000)", "50")
	.option("--json", "Print the bundle summary as JSON")
	.action((options) => supportBundleCommand(options));

program
	.command("coverage")
	.description(
		"Show how the installed detection rules map to OWASP LLM Top 10 2025, OWASP Agentic Top 10 2026 and MITRE ATLAS",
	)
	.option("--format <format>", "table, json or markdown", "table")
	.action((options) => coverageCommand(options));

program
	.command("pending")
	.description(
		"List blocked agent actions waiting for your approval (given only in your own terminal)",
	)
	.option("--json", "Emit machine-readable JSON")
	.action((options) => pendingCommand(options));

program
	.command("report-fp")
	.description(
		"Report a blocked or held action as a false positive to your IT or security team (ids and rule only; never the command)",
	)
	.argument("<actionId>", "The id from the block message (its first 8+ characters are enough)")
	.option(
		"--reason <code>",
		"Why it is a false positive: benign_automation, benign_maintenance, expected_egress, expected_file_write, legitimate_mcp_tool, developer_test, environment_specific, insufficient_context, policy_too_strict or other",
		"other",
	)
	.option("--note <text>", "A short note for the reviewer (secrets are masked; max 500 characters)")
	.option("--dry-run", "Show what would be reported without sending it")
	.option("--json", "Emit a machine-readable result")
	.action((actionId, options) => reportFpCommand(actionId, options));

program
	.command("approve")
	.description(
		"Operator only: approve ONE retry of a blocked call (interactive confirmation; 15-minute default)",
	)
	.argument(
		"[actionId]",
		"The id from `aidr pending`, or its first 8+ characters; omit it in a terminal to pick from a list",
	)
	.option("--ttl <minutes>", "Minutes the approval stays usable (1-1440)", "15")
	.option("--permit-allowlist", "Also let the agent add these artifacts to the allowlist once")
	.option("-y, --yes", "Skip the prompt; honoured only with AIDR_OPERATOR_NONINTERACTIVE=1")
	.option("--json", "Emit a machine-readable receipt")
	.action((actionId, options) => approveCommand(actionId, options));

const allowlistProgram = program
	.command("allowlist")
	.description("List, add or remove permanent allowlist entries");

allowlistProgram
	.command("list")
	.description("Show allowlist entries (commands are stored as hashes)")
	.option("--json", "Emit machine-readable JSON")
	.action((options) => allowlistListCommand(options));

allowlistProgram
	.command("add <type> <value>")
	.description(
		"Operator only: permanently allow a url, command or file_path (interactive confirmation)",
	)
	.option("--reason <text>", "Why this artifact is safe")
	.option("-y, --yes", "Skip the prompt; honoured only with AIDR_OPERATOR_NONINTERACTIVE=1")
	.action((type, value, options) => allowlistAddCommand(type, value, options));

allowlistProgram
	.command("remove <type> <value>")
	.description("Remove a url, command (text or hash) or file_path from the allowlist")
	.action((type, value) => allowlistRemoveCommand(type, value));

const exceptionProgram = program
	.command("exception")
	.description("Time-limited detection exceptions per user, agent or repository");

exceptionProgram
	.command("add <ruleId>")
	.description(
		"Operator only: lift one detection rule for one subject until it expires (max 30 days; interactive confirmation)",
	)
	.option("--user <name>", "Subject: this OS account")
	.option("--agent <runtime>", "Subject: this agent runtime (claude-code, cursor, vscode, ...)")
	.option("--repo <path|remote>", "Subject: this repository (root path or origin remote)")
	.option("--expires <duration>", "Lifetime such as 30m, 12h or 7d (required; max 30d)")
	.option("--reason <text>", "Why the exception is needed (required)")
	.option("--artifact <value>", "Narrow to one exact command, URL or file path")
	.option("-y, --yes", "Skip the prompt; honoured only with AIDR_OPERATOR_NONINTERACTIVE=1")
	.option("--json", "Emit a machine-readable receipt")
	.action((ruleId, options) => exceptionAddCommand(ruleId, options));

exceptionProgram
	.command("list")
	.description("Show local detection exceptions")
	.option("--all", "Include expired exceptions")
	.option("--json", "Emit machine-readable JSON")
	.action((options) => exceptionListCommand(options));

exceptionProgram
	.command("remove <id>")
	.description("Revoke a local detection exception now")
	.option("--json", "Emit a machine-readable receipt")
	.action((id, options) => exceptionRemoveCommand(id, options));

const complianceProgram = program
	.command("compliance")
	.description("Work with compliance evidence reports from the control plane");

complianceProgram
	.command("verify <report>")
	.description(
		"Verify a compliance report offline: recompute its SHA-256 and check the Ed25519 signature",
	)
	.option("--public-key <file>", "PEM public key the report must be signed with (pins the issuer)")
	.option("--require-signature", "Fail when the report is not signed")
	.option("--json", "Emit a machine-readable result")
	.action((report, options) => complianceVerifyCommand(report, options));

const auditProgram = program.command("audit").description("Read the local verdict audit log");

auditProgram
	.command("tail")
	.description("Show the most recent audit entries (redacted)")
	.option("-n, --lines <count>", "Number of entries", "20")
	.option("--json", "Emit JSON Lines")
	.action((options) => auditTailCommand(options));

auditProgram
	.command("export")
	.description("Export redacted audit entries, including rotated files")
	.option("--since <when>", "ISO-8601 date/time or a relative age such as 24h, 7d, 30m")
	.option("--format <format>", "jsonl or csv", "jsonl")
	.option("-o, --output <file>", "Write to a new file (0600) instead of stdout")
	.action((options) => auditExportCommand(options));

auditProgram
	.command("verify")
	.description(
		"Verify the signed verdict log and the signed response-action chain; exit 0 verified, 1 broken, 2 unverifiable",
	)
	.option("--expect-root <fingerprint>", "Pin the first root key (SHA256:<hex>)")
	.option(
		"--response-chain <path>",
		"Verify only this response-action chain file (exit 1 broken, 2 unverifiable)",
	)
	.option("--json", "Emit a machine-readable result")
	.action(async (options) => {
		if (options.responseChain) {
			await auditVerifyResponseChainCommand(options.responseChain, options);
			return;
		}
		await auditVerifyCommand(options);
	});

auditProgram
	.command("rotate-key")
	.description("Operator only: replace the verdict-log root signing key (interactive confirmation)")
	.option("-y, --yes", "Skip the prompt; honoured only with AIDR_OPERATOR_NONINTERACTIVE=1")
	.option("--json", "Emit a machine-readable result")
	.action((options) => auditRotateKeyCommand(options));

const quarantineProgram = program
	.command("quarantine")
	.description("Inspect, release or delete files quarantined as malicious");

quarantineProgram
	.command("list")
	.description("List quarantined files (newest first)")
	.option("--json", "Emit machine-readable JSON")
	.action((options) => quarantineListCommand(options));

quarantineProgram
	.command("show <id>")
	.description("Show one quarantined file: original path, hash, reason, time")
	.option("--json", "Emit machine-readable JSON")
	.action((id, options) => quarantineShowCommand(id, options));

quarantineProgram
	.command("release <id>")
	.description(
		"Operator only: put a quarantined file back at its original path (interactive confirmation)",
	)
	.option("-y, --yes", "Skip the prompt; honoured only with AIDR_OPERATOR_NONINTERACTIVE=1")
	.action((id, options) => quarantineReleaseCommand(id, options));

quarantineProgram
	.command("delete <id>")
	.description("Operator only: permanently delete a quarantined file (interactive confirmation)")
	.option("-y, --yes", "Skip the prompt; honoured only with AIDR_OPERATOR_NONINTERACTIVE=1")
	.action((id, options) => quarantineDeleteCommand(id, options));

program
	.command("restore [snapshotId]")
	.description(
		"Operator only: restore a protected path from its pre-operation snapshot (interactive confirmation), or --list them",
	)
	.option("--list", "List stored snapshots")
	.option("--overwrite-changed", "Also overwrite a target that changed after the snapshot")
	.option("-y, --yes", "Skip the prompt; honoured only with AIDR_OPERATOR_NONINTERACTIVE=1")
	.option("--json", "Emit machine-readable JSON (with --list)")
	.action((snapshotId, options) => restoreCommand(snapshotId, options));

const profileProgram = program
	.command("profile")
	.description("Inspect, validate and dry-run agent permission profiles (least privilege)");

profileProgram
	.command("list")
	.description("List local and managed agent permission profiles and the shipped templates")
	.option("--json", "Emit machine-readable JSON")
	.action((options) => profileListCommand(options));

profileProgram
	.command("show <name>")
	.description("Print one profile (local or managed), or a shipped template with --template")
	.option(
		"--template",
		"Show a shipped template: read-only-reviewer, standard-developer, ci-agent, locked-down",
	)
	.action((name, options) => profileShowCommand(name, options));

profileProgram
	.command("validate [file]")
	.description("Validate a profile document (default: ~/.singularity-aidr/agent-profiles.json)")
	.option("--json", "Emit machine-readable JSON")
	.action((file, options) => profileValidateCommand(file, options));

profileProgram
	.command("test <tool-call-json>")
	.description(
		'Dry-run a tool call (JSON or @file, e.g. \'{"tool_name":"Bash","tool_input":{"command":"ls"}}\') against the effective profiles',
	)
	.option("--connector <name>", "Connector whose profiles apply", "claude-code")
	.option("--cwd <dir>", "Working directory of the agent session (selects repository profiles)")
	.option("--file <path>", "Test against this profile document instead of the installed ones")
	.option("--json", "Emit machine-readable JSON")
	.action((toolCall, options) => profileTestCommand(toolCall, options));

const canaryProgram = program
	.command("canary")
	.description(
		"Operator only: plant and manage decoy credentials that expose an agent hunting for secrets",
	);

canaryProgram
	.command("deploy")
	.description(
		"Create new decoy credential files (never overwrites a file); the registry stores only digests",
	)
	.option("--path <dir>", "Directory for project decoys (env, db-url); defaults to the current one")
	.option("--kinds <list>", "Comma-separated kinds: aws, github, openai, env, ssh-config, db-url")
	.option("--json", "Emit machine-readable JSON")
	.action((options) => canaryDeployCommand(options));

canaryProgram
	.command("list")
	.description("List deployed canary credentials and whether each decoy file is intact")
	.option("--json", "Emit machine-readable JSON")
	.action((options) => canaryListCommand(options));

canaryProgram
	.command("remove [id]")
	.description("Delete one decoy (by id) or all of them, and drop them from the registry")
	.option("--all", "Remove every deployed canary credential")
	.option("--json", "Emit machine-readable JSON")
	.action((id, options) => canaryRemoveCommand(id, options));

canaryProgram
	.command("status")
	.description("Check the registry, the decoy files and triggers recorded in the audit log")
	.option("--json", "Emit machine-readable JSON")
	.action((options) => canaryStatusCommand(options));

// Help text in the user's language (AIDR_LOCALE, config `locale`, LANG); English is unchanged.
initCliLocale();
groupCommands(program);
localizeHelp(program);

// No top-level await: the standalone (SEA) build bundles this entry as CommonJS.
// An unhandled rejection still exits non-zero with its stack, as before.
void program.parseAsync(process.argv);
