#!/usr/bin/env node

import { VERSION } from "@singularityrd/aidr-core";
import { Command } from "commander";
import collectCommand from "./commands/collect.js";
import configCommand from "./commands/config.js";
import discoverCommand from "./commands/discover.js";
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
	.description("Configure AIDR and install the detected agent hooks")
	.option("-f, --force", "Replace an existing local configuration")
	.action(setupCommand);

program
	.command("config")
	.description("Read or update the local AIDR configuration")
	.option("-g, --get <key>", "Read a dotted configuration key")
	.option("-s, --set <values...>", "Set a dotted configuration key and value")
	.option("-l, --list", "Print all configuration values")
	.action(configCommand);

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
	.description("Remove only the AIDR-managed agent hooks, preserving your own hooks and configuration")
	.option(
		"--home <path>",
		"Target an explicit home directory (managed fleets and verification); defaults to the current user",
	)
	.option("--json", "Emit a machine-readable report")
	.action(uninstallCommand);

await program.parseAsync(process.argv);
