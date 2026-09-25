import { existsSync, readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import {
	type AigInfraScanSummary,
	type AigInfraTargetResult,
	atomicWriteJson,
	buildInfraScanFindingEvents,
	buildSkillScanFindingEvents,
	type CodeScanReport,
	cveCount,
	describePostureUploadError,
	fingerprintCount,
	loadConfig,
	loadThreatsFromDirs,
	loadTrustedModelSources,
	newPostureScanId,
	type PluginScanResult,
	type PostureUploadResult,
	resolvePath,
	SKILL_RISK_TYPES,
	scanCodePath,
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
	code?: string[];
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
	allowlistsDir?: string;
	/** Configuration whose `disabled_threats` and `ai_supply_chain` apply to `--code`. */
	configPath?: string;
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
 * Code: `--code <path>` runs the AI model supply-chain and secure-code rules
 * (threats/ai-supply-chain.yaml, threats/secure-code.yaml) over a project
 * directory or file and reports every finding as file:line. Local only:
 * code findings are never uploaded.
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
	const codePaths = [...new Set((options.code ?? []).map((path) => resolve(path)))];

	if (targets.length === 0 && skills.length === 0 && codePaths.length === 0) {
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
	const codeResults = codePaths.length > 0 ? await scanCode(codePaths, dependencies) : null;

	if (summary && options.saveReport)
		await atomicWriteJson(resolvePath(options.saveReport), summary);

	printResults(Boolean(options.json), summary, skillResults, targets.length, codeResults);
	setExitCode(summary, skillResults, codeResults);

	if (options.upload) {
		const upload = await (dependencies.upload ?? uploadPostureEvents)(
			findingEvents(summary, skillResults),
		);
		reportUpload(upload, Boolean(options.json));
	}
}

function printResults(
	json: boolean,
	summary: AigInfraScanSummary | null,
	skillResults: SkillScanReport | null,
	targetCount: number,
	codeResults: CodeScanReport[] | null = null,
): void {
	if (json) {
		const combined =
			skillResults || codeResults
				? {
						infra: summary,
						...(skillResults ? { skills: skillResults } : {}),
						...(codeResults ? { code: codeResults } : {}),
					}
				: summary;
		console.log(JSON.stringify(combined, null, 2));
		return;
	}
	if (summary) printHumanSummary(summary, targetCount);
	if (skillResults) printSkillSummary(skillResults);
	if (codeResults) printCodeSummary(codeResults);
}

async function scanCode(paths: string[], dependencies: ScanDependencies): Promise<CodeScanReport[]> {
	const bundled = resolveBundledDataDirs();
	const threatsDir = dependencies.threatsDir ?? bundled.threatsDir;
	const allowlistsDir = dependencies.allowlistsDir ?? bundled.allowlistsDir;
	const threats = existsSync(threatsDir) ? await loadThreatsFromDirs([threatsDir]) : [];
	// An unreadable configuration falls back to the shipped defaults: no extra
	// trusted model sources and no disabled rules (the stricter reading).
	const config = await loadConfig(dependencies.configPath).catch(() => null);
	const trustedModelSources = await loadTrustedModelSources(allowlistsDir, config?.ai_supply_chain);
	const reports: CodeScanReport[] = [];
	for (const path of paths) {
		reports.push(
			await scanCodePath(path, threats, {
				trustedModelSources,
				disabledThreats: config?.disabled_threats ?? [],
			}),
		);
	}
	return reports;
}

function printCodeReport(report: CodeScanReport): void {
	const marker = !report.exists ? "○" : report.findings.length > 0 ? "!" : "✓";
	console.log(`${marker} ${report.root}`);
	if (!report.exists) {
		console.log("    not scanned (path does not exist)");
		return;
	}
	console.log(
		`    ${report.filesScanned} file(s) scanned, ${report.filesSkipped} skipped, ${report.linksSkipped} link(s) not followed`,
	);
	for (const finding of report.findings) {
		const where = `${finding.file}${finding.cell !== undefined ? ` [cell ${finding.cell}]` : ""}:${finding.line}`;
		console.log(`    ${where}  ${finding.severity.padEnd(8)} ${finding.ruleId}  ${finding.title}`);
		if (finding.evidence) console.log(`        ${finding.evidence}`);
	}
	if (report.truncated) console.log("    note: finding limit reached; the list is incomplete");
}

function printCodeSummary(reports: CodeScanReport[]): void {
	console.log("\n🛡️  AIDR code scan (AI model supply chain + secure-code guardrails)\n");
	const rules = reports[0]?.rules ?? 0;
	console.log(`Paths: ${reports.length}   Code rules: ${rules}\n`);
	if (rules === 0) console.log("No code rules were loaded. This is NOT a clean result.\n");
	for (const report of reports) printCodeReport(report);
	const findings = reports.flatMap((report) => report.findings);
	const supplyChain = findings.filter((finding) => finding.kind === "ai_supply_chain").length;
	console.log(
		`\nCode findings: ${findings.length} (${supplyChain} AI supply chain, ${findings.length - supplyChain} secure code)`,
	);
	const skipped = reports.reduce((count, report) => count + report.filesSkipped, 0);
	if (skipped > 0) console.log(`${skipped} file(s) could not be inspected; they are not clean.`);
	if (findings.length === 0 && reports.some((report) => report.filesScanned > 0)) {
		console.log(
			"No rule matched. This reflects only the deterministic pattern rules; it is not a\n" +
				"full security review of the code.\n",
		);
	}
}

function findingEvents(summary: AigInfraScanSummary | null, skillResults: SkillScanReport | null) {
	const scanId = newPostureScanId();
	return [
		...(summary ? buildInfraScanFindingEvents(summary, scanId) : []),
		...(skillResults ? buildSkillScanFindingEvents(skillResults.results, scanId) : []),
	];
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
	console.log("  aidr scan --code .                     # model loading + secure-code rules, file:line");
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

function printCves(result: AigInfraTargetResult): void {
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

function printTarget(result: AigInfraTargetResult): void {
	const findings = result.cves.length;
	const marker = findings > 0 ? "!" : result.matched.length > 0 ? "✓" : "○";
	console.log(`${marker} ${result.url}`);
	console.log(`    ${describe(result)}`);
	if (findings > 0) printCves(result);
	// An unreachable/unevaluated result must never be presented as clean.
	if (result.error && result.error !== "target_not_allowed" && result.reachable) {
		console.log(`    note: ${result.error} - result is not a clean verdict`);
	}
}

function printHumanSummary(summary: AigInfraScanSummary, targetCount: number): void {
	console.log("\n🛡️  AIDR infrastructure scan\n");
	console.log(
		`Targets: ${targetCount}   Dataset: ${fingerprintCount()} fingerprints / ${cveCount()} CVEs\n`,
	);

	for (const result of summary.targets) printTarget(result);

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

function printSkillResult(result: PluginScanResult): void {
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
	for (const result of report.results) printSkillResult(result);
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

function setExitCode(
	summary: AigInfraScanSummary | null,
	skills: SkillScanReport | null,
	code: CodeScanReport[] | null = null,
): void {
	const skillSevere =
		skills?.results.some((result) =>
			result.findings.some(
				(finding) => finding.severity === "critical" || finding.severity === "high",
			),
		) ?? false;
	const codeSevere =
		code?.some((report) =>
			report.findings.some(
				(finding) => finding.severity === "critical" || finding.severity === "high",
			),
		) ?? false;
	// Non-zero when a vulnerability was found, so this is usable in CI.
	if ((summary && (summary.critical > 0 || summary.high > 0)) || skillSevere || codeSevere) {
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
	const codeIncomplete =
		code?.some((report) => !report.exists || report.filesSkipped > 0 || report.rules === 0) ?? false;
	process.exitCode = infraIncomplete || skillIncomplete || codeIncomplete ? 1 : 0;
}

export default scanCommand;
