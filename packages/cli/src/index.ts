#!/usr/bin/env node

import { VERSION } from "@singularityrd/aidr-core";
import { Command } from "commander";
import collectCommand from "./commands/collect.js";
import configCommand from "./commands/config.js";
import {
	revokeKeyCommand,
	rotateKeyCommand,
	SECRET_STORE_OPTION_DESCRIPTION,
} from "./commands/config-secret.js";
import discoverCommand from "./commands/discover.js";
import {
	learningApproveCommand,
	learningExecuteCommand,
	learningExportAuthorityCommand,
	learningIngestCommand,
	learningKeygenCommand,
} from "./commands/learning.js";
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
	.option("--json", "Emit machine-readable JSON")
	.option("--allow-public", "Permit non-private targets (off by default)")
	.option("--timeout <ms>", "Per-request timeout in milliseconds", "3000")
	.option("--concurrency <n>", "Number of targets to scan in parallel", "4")
	.option("--save-report <path>", "Persist a scan report for the configured infrastructure policy")
	.action(scanCommand);

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

await program.parseAsync(process.argv);
