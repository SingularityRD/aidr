#!/usr/bin/env node

import { VERSION } from "@singularityrd/aidr-core";
import { Command } from "commander";
import {
	allowlistAddCommand,
	allowlistListCommand,
	allowlistRemoveCommand,
} from "./commands/allowlist.js";
import { approveCommand, pendingCommand } from "./commands/approvals.js";
import { auditExportCommand, auditTailCommand } from "./commands/audit.js";
import collectCommand from "./commands/collect.js";
import configCommand from "./commands/config.js";
import {
	revokeKeyCommand,
	rotateKeyCommand,
	SECRET_STORE_OPTION_DESCRIPTION,
} from "./commands/config-secret.js";
import discoverCommand from "./commands/discover.js";
import doctorCommand from "./commands/doctor.js";
import scanCommand from "./commands/scan.js";
import setupCommand from "./commands/setup.js";
import statusCommand from "./commands/status.js";
import uninstallCommand from "./commands/uninstall.js";

const program = new Command();

program
	.name("aidr")
	.description("Singularity AIDR command-line setup and diagnostics")
	.version(VERSION);

program
	.command("setup")
	.description("Configure AIDR and show connector setup guidance")
	.option("-f, --force", "Replace an existing local configuration")
	.option("--secret-store <kind>", SECRET_STORE_OPTION_DESCRIPTION)
	.action(setupCommand);

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
	.action(statusCommand);

program
	.command("scan")
	.description(
		"Scan AI infrastructure targets for known products and CVEs (native, no external service)",
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

program
	.command("collect")
	.description("Continuously collect tenant-scoped AI infrastructure inventory")
	.requiredOption("--tenant <id>", "Tenant identifier recorded in the inventory")
	.option(
		"--provider <id>",
		"Discovery provider (local is implemented; cloud/MDM require an adapter)",
		"local",
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
		"--upload",
		"Send server names, risk categories and digests (no paths, endpoints or arguments) to the managed control plane",
	)
	.action(discoverCommand);

program
	.command("uninstall")
	.description(
		"Remove only the AIDR-managed agent hooks, preserving your own hooks and configuration",
	)
	.option(
		"--home <path>",
		"Target an explicit home directory (managed fleets and verification); defaults to the current user",
	)
	.option("--json", "Emit a machine-readable report")
	.action(uninstallCommand);

program
	.command("doctor")
	.description(
		"Check hosts, hook registration, rules, mode, DLP policy, approvals and the last verdict; exits non-zero on problems",
	)
	.option("--json", "Emit a machine-readable report")
	.action((options) => doctorCommand(options));

program
	.command("pending")
	.description("List blocked agent actions waiting for an out-of-band operator approval")
	.option("--json", "Emit machine-readable JSON")
	.action((options) => pendingCommand(options));

program
	.command("approve <actionId>")
	.description(
		"Operator only: approve ONE retry of a blocked call (interactive confirmation; 15-minute default)",
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

await program.parseAsync(process.argv);
