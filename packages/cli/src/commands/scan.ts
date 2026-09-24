import { existsSync, readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import {
	type AigInfraScanSummary,
	type AigInfraTargetResult,
	atomicWriteJson,
	buildInfraScanFindingEvents,
	buildSkillScanFindingEvents,
	cveCount,
	describePostureUploadError,
	fingerprintCount,
	loadThreatsFromDirs,
	newPostureScanId,
	type PluginScanResult,
	type PostureUploadResult,
	resolvePath,
	SKILL_RISK_TYPES,
	scanPlugin,
	scanTargets,
	skillRiskTypeForThreatId,
	uploadPostureEvents,
} from "@singularityrd/aidr-core";
import { resolveBundledDataDirs } from "../utils/test-protection.js";

interface ScanOptions {
	target?: string[];
	file?: string;
	skill?: string[];
	json?: boolean;
	allowPublic?: boolean;
	timeout?: string;
	concurrency?: string;
	saveReport?: string;
	upload?: boolean;
}

/** Injectable collaborators, for tests. */
export interface ScanDependencies {
	upload?: typeof uploadPostureEvents;
	threatsDir?: string;
}

/**
 * `aidr scan` — native AI-infrastructure and skill/plugin package scan.
 *
 * Infrastructure: runs the compiled AI-Infra-Guard fingerprints against the
 * given targets entirely in-process (HTTP probes, version extraction and CVE
 * applicability). No Go server, Python worker, Docker stack or LLM is involved.
 * Targets must be loopback or private unless `--allow-public` is passed
 * explicitly, so a typo cannot turn this into a public port scanner.
 *
 * Skills: `--skill <dir>` runs the deterministic AIG Skill-Scan T01–T09 rules
 * (threats/skill-scan.yaml) plus the command rules over a skill or plugin
 * package directory. Nothing is executed and no file leaves the machine.
 *
 * `--upload` sends the findings (identifiers, severities and digests only) to
 * the managed control plane with this installation's enrolled API key.
 */
async function scanCommand(options: ScanOptions): Promise<void> {
	// Commander passes the Command as the second argument; never treat it as dependencies.
	await runScan(options);
}

export async function runScan(
	options: ScanOptions,
	dependencies: ScanDependencies = {},
): Promise<void> {
	const targets = collectTargets(options);
	const skills = [...new Set((options.skill ?? []).map((path) => resolve(path)))];

	if (targets.length === 0 && skills.length === 0) {
		printUsage();
		return;
	}

	const timeoutMs = parsePositiveInt(options.timeout, 3000);
	const concurrency = parsePositiveInt(options.concurrency, 4);
	const allowPublic = Boolean(options.allowPublic);

	if (allowPublic && targets.length > 0) {
		console.error(
			"⚠️  --allow-public is set: targets outside loopback/private ranges will be contacted.\n",
		);
	}

	const summary =
		targets.length > 0
			? await scanTargets(targets, { timeoutMs, concurrency, allowPublicTargets: allowPublic })
			: null;
	const skillResults = skills.length > 0 ? await scanSkills(skills, dependencies.threatsDir) : null;

	if (summary && options.saveReport)
		await atomicWriteJson(resolvePath(options.saveReport), summary);

	if (options.json) {
		console.log(
			JSON.stringify(skillResults ? { infra: summary, skills: skillResults } : summary, null, 2),
		);
	} else {
		if (summary) printHumanSummary(summary, targets.length);
		if (skillResults) printSkillSummary(skillResults);
	}
	setExitCode(summary, skillResults);

	if (options.upload) {
		const scanId = newPostureScanId();
		const events = [
			...(summary ? buildInfraScanFindingEvents(summary, scanId) : []),
			...(skillResults ? buildSkillScanFindingEvents(skillResults.results, scanId) : []),
		];
		const upload = await (dependencies.upload ?? uploadPostureEvents)(events);
		reportUpload(upload, Boolean(options.json));
	}
}

interface SkillScanReport {
	results: PluginScanResult[];
	/** Paths that could not be scanned at all; never presented as clean. */
	missing: string[];
	rules: number;
}

async function scanSkills(paths: string[], threatsDirOverride?: string): Promise<SkillScanReport> {
	const threatsDir = threatsDirOverride ?? resolveBundledDataDirs().threatsDir;
	const threats = existsSync(threatsDir) ? await loadThreatsFromDirs([threatsDir]) : [];
	const rules = threats.filter(
		(threat) =>
			threat.matchOn.has("plugin_content") || threat.matchOn.has("plugin_orphan_bytecode"),
	).length;
	const results: PluginScanResult[] = [];
	const missing: string[] = [];
	for (const installPath of paths) {
		if (!existsSync(installPath)) {
			missing.push(installPath);
			continue;
		}
		results.push(
			await scanPlugin(
				{ key: basename(installPath), installPath, version: "local", lastUpdated: "" },
				threats,
				// Reputation legs stay off: a local package scan sends nothing anywhere.
				{ checkUrls: false, checkFileHashes: false },
			),
		);
	}
	return { results, missing, rules };
}

function printUsage(): void {
	console.log("\n🛡️  AIDR infrastructure and skill scan\n");
	console.log("No targets given.");
	console.log("\nUsage:");
	console.log("  aidr scan --target http://127.0.0.1:8080");
	console.log("  aidr scan --target http://127.0.0.1:8080 --target http://10.0.0.4:3000");
	console.log("  aidr scan --file targets.txt          # one URL per line");
	console.log("  aidr scan --skill ~/.claude/skills/my-skill   # skill/plugin package (T01-T09)");
	console.log("\nOptions:");
	console.log("  --json             machine-readable output");
	console.log("  --allow-public     permit non-private targets (off by default)");
	console.log("  --timeout <ms>     per-request timeout (default 3000)");
	console.log("  --concurrency <n>  parallel targets (default 4)");
	console.log("  --upload           send findings to the managed control plane (enrolled API key)");
	console.log(
		`\nDataset: ${fingerprintCount()} fingerprints, ${cveCount()} CVEs (compiled from AI-Infra-Guard).\n`,
	);
}

function collectTargets(options: ScanOptions): string[] {
	const targets = [...(options.target ?? [])];
	if (options.file) {
		try {
			const contents = readFileSync(options.file, "utf8");
			for (const line of contents.split(/\r?\n/)) {
				const trimmed = line.trim();
				if (!trimmed || trimmed.startsWith("#")) continue;
				targets.push(trimmed);
			}
		} catch (error) {
			console.error(
				`Could not read target file ${options.file}: ${error instanceof Error ? error.message : String(error)}`,
			);
			process.exit(1);
		}
	}
	return [...new Set(targets)];
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
	if (!value) return fallback;
	const parsed = Number.parseInt(value, 10);
	return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function describe(result: AigInfraTargetResult): string {
	if (result.matched.length === 0) {
		if (result.error === "target_not_allowed") {
			return "skipped - not a loopback/private target (use --allow-public)";
		}
		if (result.reachable) return "reachable, no known product identified";
		return `not scanned (${result.error ?? "unreachable"})`;
	}
	return result.matched
		.map((m) => `${m.name}${m.version ? ` ${m.version}` : " (version unknown)"}`)
		.join(", ");
}

function printHumanSummary(summary: AigInfraScanSummary, targetCount: number): void {
	console.log("\n🛡️  AIDR infrastructure scan\n");
	console.log(
		`Targets: ${targetCount}   Dataset: ${fingerprintCount()} fingerprints / ${cveCount()} CVEs\n`,
	);

	for (const result of summary.targets) {
		const findings = result.cves.length;
		const marker = findings > 0 ? "!" : result.matched.length > 0 ? "✓" : "○";
		console.log(`${marker} ${result.url}`);
		console.log(`    ${describe(result)}`);
		if (findings > 0) {
			const shown = result.cves.slice(0, 10);
			for (const cve of shown) {
				const conf = cve.evaluated ? "" : " (applicability unconfirmed)";
				const score = cve.cvss !== null ? ` cvss ${cve.cvss}` : "";
				console.log(`      ${cve.cveId}  ${cve.severity}${score}${conf}`);
			}
			if (result.cves.length > shown.length) {
				console.log(`      ... and ${result.cves.length - shown.length} more`);
			}
		}
		// An unreachable/unevaluated result must never be presented as clean.
		if (result.error && result.error !== "target_not_allowed" && result.reachable) {
			console.log(`    note: ${result.error} - result is not a clean verdict`);
		}
	}

	console.log("");
	console.log(
		`Findings: ${summary.critical} critical, ${summary.high} high (${summary.cvesFound} total)`,
	);

	// Distinguish "inspected and found nothing" from "never inspected". Reporting
	// the former when only the latter happened would invent a clean result.
	const skipped = summary.targets.filter((t) => t.error === "target_not_allowed").length;
	const scanned = summary.targets.filter(
		(t) => t.error !== "target_not_allowed" && t.reachable,
	).length;
	const unreachable = summary.targets.length - skipped - scanned;

	if (scanned === 0) {
		console.log(
			`\nNo target was scanned (${skipped} skipped, ${unreachable} unreachable). This is NOT a clean result.\n`,
		);
		return;
	}

	if (summary.cvesFound === 0) {
		console.log(
			`\nNo vulnerabilities matched across ${scanned} scanned target(s). This is not proof of safety:\n` +
				"it reflects only the compiled fingerprint and CVE dataset, for the targets that were\n" +
				"reachable and identified.\n",
		);
	}
}

function printSkillSummary(report: SkillScanReport): void {
	console.log("\n🛡️  AIDR skill / plugin package scan\n");
	console.log(
		`Packages: ${report.results.length + report.missing.length}   Skill rules: ${report.rules}\n`,
	);
	if (report.rules === 0) {
		console.log("No skill-scan rules were loaded. This is NOT a clean result.\n");
	}
	for (const path of report.missing) {
		console.log(`○ ${path}\n    not scanned (path does not exist)`);
	}
	for (const result of report.results) {
		const marker = result.findings.length > 0 ? "!" : "✓";
		console.log(`${marker} ${result.plugin.installPath}`);
		for (const finding of result.findings.slice(0, 25)) {
			const riskType = skillRiskTypeForThreatId(finding.threatId);
			const taxonomy = riskType ? ` [${riskType} ${SKILL_RISK_TYPES[riskType]}]` : "";
			console.log(`      ${finding.severity.padEnd(8)} ${finding.threatId}${taxonomy}`);
			console.log(`               ${finding.sourceFile || "(package root)"} ${finding.artifact}`);
		}
		if (result.findings.length > 25) {
			console.log(`      ... and ${result.findings.length - 25} more`);
		}
		for (const unavailable of result.unavailableChecks ?? []) {
			if (unavailable.check !== "plugin_files") continue;
			console.log(`    note: ${unavailable.reason} (${unavailable.uncheckedCount} unchecked)`);
		}
	}
	const total = report.results.reduce((count, result) => count + result.findings.length, 0);
	console.log(`\nSkill findings: ${total}`);
	if (total === 0 && report.results.length > 0) {
		console.log(
			"No rule matched. This reflects only the deterministic T01-T09 rules; it is not a\n" +
				"semantic review of the skill's intent.\n",
		);
	}
}

function reportUpload(result: PostureUploadResult, json: boolean): void {
	// Keep stdout parseable in --json mode: upload status goes to stderr there.
	const write = json ? console.error : console.log;
	if (result.ok) {
		write(`Uploaded ${result.delivered} posture finding(s) to the control plane.`);
		return;
	}
	console.error(
		`Upload failed: ${describePostureUploadError(result.error)}.` +
			(result.queued
				? ` ${result.total - result.delivered} finding(s) remain queued and will be retried on the next delivery.`
				: " Nothing was uploaded."),
	);
	if (!process.exitCode) process.exitCode = 1;
}

function setExitCode(summary: AigInfraScanSummary | null, skills: SkillScanReport | null): void {
	const skillSevere =
		skills?.results.some((result) =>
			result.findings.some(
				(finding) => finding.severity === "critical" || finding.severity === "high",
			),
		) ?? false;
	// Non-zero when a vulnerability was found, so this is usable in CI.
	if ((summary && (summary.critical > 0 || summary.high > 0)) || skillSevere) {
		process.exitCode = 2;
		return;
	}
	const infraIncomplete = summary?.targets.some((target) => target.error !== null) ?? false;
	const skillIncomplete = skills
		? skills.missing.length > 0 ||
			skills.rules === 0 ||
			skills.results.some((result) =>
				(result.unavailableChecks ?? []).some((entry) => entry.check === "plugin_files"),
			)
		: false;
	process.exitCode = infraIncomplete || skillIncomplete ? 1 : 0;
}

export default scanCommand;
