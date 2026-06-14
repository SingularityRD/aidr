/**
 * aidr scan — AIDR Scan engine CLI command.
 *
 * Subcommands:
 *   aidr scan cve <package>[@<version>] [--ecosystem <eco>] [--framework <name>]
 *   aidr scan mcp <url> [--tool <server.tool>]
 *   aidr scan agent --config <yaml-or-path>
 *   aidr scan jailbreak --endpoint <url> --model <name> --token <tok>
 *   aidr scan stats
 *
 * Output: human-friendly by default; --json for machine-readable.
 *
 * Migrated and rebranded from the previous AIG aig-scan-client. The CLI
 * now talks to the in-process AIDR Scan engine — no HTTP, no Go sidecar.
 */

import chalk from "chalk";
import { scan, getEngineStats, type ScanResult } from "@singularityrd/aidr-core/scan";

interface ScanOptions {
	json?: boolean;
	ecosystem?: string;
	framework?: string;
	tool?: string;
	config?: string;
	endpoint?: string;
	model?: string;
	token?: string;
	suites?: string;
}

export async function scanCommand(
	subcommand: string,
	target: string | undefined,
	options: ScanOptions,
): Promise<void> {
	const start = Date.now();
	let result: ScanResult;

	try {
		switch (subcommand) {
			case "cve":
				result = await runCveScanCli(target, options);
				break;
			case "mcp":
				result = await runMcpScanCli(target, options);
				break;
			case "agent":
				result = await runAgentScanCli(options);
				break;
			case "jailbreak":
				result = await runJailbreakScanCli(options);
				break;
			case "threats":
				result = await runThreatsScanCli(target, options);
				break;
			case "stats":
				return printStats(options);
			default:
				console.error(chalk.red(`Unknown subcommand: ${subcommand}`));
				console.log(chalk.gray("Usage: aidr scan <cve|mcp|agent|jailbreak|threats|stats>"));
				process.exitCode = 1;
				return;
		}
	} catch (err) {
		console.error(chalk.red(`Scan failed: ${err instanceof Error ? err.message : String(err)}`));
		process.exitCode = 1;
		return;
	}

	const dur = Date.now() - start;

	if (options.json) {
		console.log(JSON.stringify(result, null, 2));
	} else {
		printHumanReadable(subcommand, result, dur);
	}
}

async function runCveScanCli(
	target: string | undefined,
	options: ScanOptions,
): Promise<ScanResult> {
	if (!target) {
		throw new Error("Usage: aidr scan cve <package>[@<version>] [--ecosystem <npm|pypi|...>]");
	}
	// Accept both @ (npm) and : (docker) as version separators
	const atIdx = target.lastIndexOf("@");
	const colonIdx = target.lastIndexOf(":");
	let sep = -1;
	if (atIdx > 0 && colonIdx > 0) sep = Math.max(atIdx, colonIdx);
	else if (atIdx > 0) sep = atIdx;
	else if (colonIdx > 0) sep = colonIdx;
	const packageName = sep > 0 ? target.slice(0, sep) : target;
	const version = sep > 0 ? target.slice(sep + 1) : "*";
	const ecosystem = options.ecosystem ?? "npm";

	return await scan({
		type: "cve",
		target: {
			package: packageName,
			version,
			ecosystem,
			framework: options.framework,
		},
	});
}

async function runMcpScanCli(
	target: string | undefined,
	_options: ScanOptions,
): Promise<ScanResult> {
	if (!target) {
		throw new Error("Usage: aidr scan mcp <url> [--tool <server.tool>]");
	}
	// Without --tool, we pass the URL only and let the SaaS layer handle
	// dynamic probing. The edge engine returns a catalog result.
	return await scan({
		type: "mcp",
		target: { url: target },
	});
}

async function runAgentScanCli(options: ScanOptions): Promise<ScanResult> {
	if (!options.config) {
		throw new Error("Usage: aidr scan agent --config <yaml-or-path>");
	}
	return await scan({
		type: "agent",
		target: { config: options.config },
	});
}

async function runThreatsScanCli(
	target: string | undefined,
	options: ScanOptions,
): Promise<ScanResult> {
	if (!target) {
		throw new Error("Usage: aidr scan threats <content> [--match-on content|command|file_path]");
	}
	const matchOn = (options as unknown as { matchOn?: string }).matchOn ?? "content";
	return await scan({
		type: "threats",
		target: { content: target, matchOn: matchOn as "content" | "command" | "file_path" },
	});
}

async function runJailbreakScanCli(options: ScanOptions): Promise<ScanResult> {
	if (!options.endpoint || !options.model || !options.token) {
		throw new Error(
			"Usage: aidr scan jailbreak --endpoint <url> --model <name> --token <tok>",
		);
	}
	const suites = options.suites ? options.suites.split(",") : ["direct_jailbreak"];
	return await scan({
		type: "jailbreak",
		target: {
			endpoint: options.endpoint,
			model: options.model,
			token: options.token,
			testSuites: suites,
		},
	});
}

function printHumanReadable(
	subcommand: string,
	result: ScanResult,
	durationMs: number,
): void {
	const ok = result.status === "completed";
	const sym = ok ? chalk.green("✓") : chalk.red("✗");
	console.log("");
	console.log(`${sym} ${chalk.bold(`AIDR Scan ${subcommand.toUpperCase()}`)} ${chalk.gray(`(${durationMs}ms)`)}`);
	console.log(chalk.gray(`  scan_id: ${result.scan_id}`));

	if (!ok) {
		console.log(chalk.red(`  error: ${result.error ?? "unknown"}`));
		return;
	}

	const s = result.summary;
	console.log("");
	console.log(chalk.bold("  Summary"));
	console.log(`    total:    ${s.total}`);
	if (s.critical > 0) console.log(`    ${chalk.red("critical:")} ${chalk.red(s.critical)}`);
	if (s.high > 0) console.log(`    ${chalk.yellow("high:")}     ${chalk.yellow(s.high)}`);
	if (s.medium > 0) console.log(`    medium:   ${s.medium}`);
	if (s.low > 0) console.log(`    low:      ${s.low}`);
	if (s.info > 0) console.log(`    info:     ${s.info}`);

	if (result.findings.length === 0) {
		console.log("");
		console.log(chalk.green("  ✓ No findings."));
		return;
	}

	console.log("");
	console.log(chalk.bold(`  Findings (${result.findings.length})`));
	for (const f of result.findings) {
		const sev = colorSeverity(f.severity);
		console.log(`    ${sev(`[${f.severity.toUpperCase()}]`)} ${f.id}`);
		console.log(`        ${f.title}`);
		if (f.description) {
			console.log(chalk.gray(`        ${f.description.slice(0, 120)}`));
		}
	}
	console.log("");
}

function colorSeverity(sev: string): (s: string) => string {
	switch (sev) {
		case "critical":
			return (s) => chalk.red(s);
		case "high":
			return (s) => chalk.yellow(s);
		case "medium":
			return (s) => chalk.cyan(s);
		case "low":
			return (s) => chalk.gray(s);
		default:
			return (s) => chalk.gray(s);
	}
}

function printStats(_options: ScanOptions): void {
	const stats = getEngineStats();
	console.log("");
	console.log(chalk.bold(`AIDR Scan Engine v${stats.version}`));
	console.log(chalk.gray(`  generated: ${stats.generated_at}`));
	console.log("");
	console.log(chalk.bold("  CVE"));
	console.log(`    total:        ${stats.cve.total}`);
	console.log(`    by_severity:  ${JSON.stringify(stats.cve.by_severity)}`);
	console.log(`    by_ecosystem: ${JSON.stringify(stats.cve.by_ecosystem)}`);
	console.log("");
	console.log(chalk.bold("  MCP"));
	console.log(`    categories: ${stats.mcp.categories}`);
	console.log(`    patterns:   ${stats.mcp.patterns}`);
	console.log("");
	console.log(chalk.bold("  Agent"));
	console.log(`    patterns: ${stats.agent.pattern_count}`);
	console.log("");
	console.log(chalk.bold("  Jailbreak"));
	console.log(`    test catalog: ${stats.jailbreak.test_catalog_size} tests`);
	console.log(`    suites:       ${stats.jailbreak.suites.join(", ")}`);
	console.log("");
	console.log(chalk.bold("  Threats"));
	console.log(`    rules: ${stats.threats.rule_count}`);
	console.log("");
}
