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
	loadThreatsFromDirsWithReport,
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
	type Threat,
	uploadPostureEvents,
} from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
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
		// Nothing to scan is a usage error, never a clean (0) result.
		printUsage();
		process.exitCode = 1;
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
	const skillResults =
		skills.length > 0
			? await scanSkills(skills, dependencies.threatsDir, dependencies.configPath)
			: null;
	const codeResults = codePaths.length > 0 ? await scanCode(codePaths, dependencies) : null;

	if (summary && options.saveReport)
		await atomicWriteJson(resolvePath(options.saveReport), summary);

	printResults(Boolean(options.json), summary, skillResults, targets.length, codeResults);
	// stderr in both modes, so --json stdout stays parseable.
	warnRulesIncomplete(incompleteRules(skillResults, codeResults));
	setExitCode(summary, skillResults, codeResults);

	if (options.upload) {
		const upload = await (dependencies.upload ?? uploadPostureEvents)(
			findingEvents(summary, skillResults),
		);
		reportUpload(upload, Boolean(options.json));
	}
}

/** `--json` output: the infra summary alone, or every leg plus any incomplete rule files. */
function jsonReport(
	summary: AigInfraScanSummary | null,
	skillResults: SkillScanReport | null,
	codeResults: CodeScanResults | null,
): unknown {
	if (!skillResults && !codeResults) return summary;
	const rulesIncomplete = incompleteRules(skillResults, codeResults);
	return {
		infra: summary,
		...(skillResults ? { skills: skillResults } : {}),
		...(codeResults ? { code: codeResults.reports } : {}),
		...(rulesIncomplete.length > 0 ? { rulesIncomplete } : {}),
	};
}

function printResults(
	json: boolean,
	summary: AigInfraScanSummary | null,
	skillResults: SkillScanReport | null,
	targetCount: number,
	codeResults: CodeScanResults | null = null,
): void {
	if (json) {
		console.log(JSON.stringify(jsonReport(summary, skillResults, codeResults), null, 2));
		return;
	}
	if (summary) printHumanSummary(summary, targetCount);
	if (skillResults) printSkillSummary(skillResults);
	if (codeResults) printCodeSummary(codeResults.reports);
}

/** The bundled rules a scan runs with, and the rule files that did not load or verify. */
interface ScanRules {
	threats: Threat[];
	/** Rule files (or the unreadable directory) missing from `threats`; empty when complete. */
	incomplete: string[];
}

/**
 * Loads the bundled rules with the loader that reports load and integrity errors (the same one
 * the evaluator uses). A rule file that is corrupt, emptied or fails the artifact manifest is
 * absent from `threats`, so the scan must say so instead of reporting "no rule matched".
 */
export async function loadScanRules(threatsDir: string, configPath?: string): Promise<ScanRules> {
	const config = await loadConfig(configPath).catch(() => null);
	const report = await loadThreatsFromDirsWithReport([threatsDir], undefined, {
		manifest: { publicKeysPem: config?.integrity?.public_keys_pem ?? [] },
	});
	const incomplete = report.bundledUnavailable
		? [threatsDir]
		: [...new Set(report.bundledErrors.map((error) => basename(error.file)))];
	return { threats: report.threats, incomplete };
}

/** Rule files missing from either leg, for the warning and the exit status. */
function incompleteRules(skills: SkillScanReport | null, code: CodeScanResults | null): string[] {
	return [...new Set([...(skills?.rulesIncomplete ?? []), ...(code?.rulesIncomplete ?? [])])];
}

function warnRulesIncomplete(files: string[]): void {
	if (files.length === 0) return;
	const shown =
		files.slice(0, 5).join(", ") + (files.length > 5 ? `, +${files.length - 5} more` : "");
	console.error(
		`⚠️  Threat rules incomplete — protection degraded: ${files.length} rule file(s) did not load or verify (${shown}).\n` +
			"    These results are NOT complete and are not a clean result. Reinstall the AIDR CLI.\n",
	);
}

interface CodeScanResults {
	reports: CodeScanReport[];
	rulesIncomplete: string[];
}

async function scanCode(paths: string[], dependencies: ScanDependencies): Promise<CodeScanResults> {
	const bundled = resolveBundledDataDirs();
	const threatsDir = dependencies.threatsDir ?? bundled.threatsDir;
	const allowlistsDir = dependencies.allowlistsDir ?? bundled.allowlistsDir;
	const { threats, incomplete } = await loadScanRules(threatsDir, dependencies.configPath);
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
	return { reports, rulesIncomplete: incomplete };
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
	/** Bundled rule files that did not load or verify; never a clean result when non-empty. */
	rulesIncomplete: string[];
}

async function scanSkills(
	paths: string[],
	threatsDirOverride?: string,
	configPath?: string,
): Promise<SkillScanReport> {
	const threatsDir = threatsDirOverride ?? resolveBundledDataDirs().threatsDir;
	const { threats, incomplete } = await loadScanRules(threatsDir, configPath);
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
	return { results, missing, rules, rulesIncomplete: incomplete };
}

/** Usage for a run without targets; on stderr, since it reports a usage error. */
function printUsage(): void {
	const lines = [
		`\n🛡️  ${ct("scan.usageTitle")}\n`,
		ct("scan.noTargets"),
		`\n${ct("scan.usage")}`,
		"  aidr scan --target http://127.0.0.1:8080",
		"  aidr scan --target http://127.0.0.1:8080 --target http://10.0.0.4:3000",
		ct("scan.usageFile"),
		ct("scan.usageSkill"),
		ct("scan.usageCode"),
		`\n${ct("scan.options")}`,
		ct("scan.optJson"),
		ct("scan.optAllowPublic"),
		ct("scan.optTimeout"),
		ct("scan.optConcurrency"),
		ct("scan.optUpload"),
		`\n${ct("scan.dataset", { fingerprints: fingerprintCount(), cves: cveCount() })}\n`,
	];
	console.error(lines.join("\n"));
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
	// "!" = a version-confirmed CVE, "?" = CVEs whose applicability is unconfirmed.
	const marker = result.cves.some((cve) => cve.evaluated)
		? "!"
		: findings > 0
			? "?"
			: result.matched.length > 0
				? "✓"
				: "○";
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
		`Confirmed findings: ${summary.confirmedCritical} critical, ${summary.confirmedHigh} high (${summary.confirmedFindings} total, version-matched)`,
	);
	if (summary.unconfirmedFindings > 0) {
		console.log(
			`Unconfirmed findings: ${summary.unconfirmedCritical} critical, ${summary.unconfirmedHigh} high (${summary.unconfirmedFindings} total) - ` +
				"applicability unconfirmed (version unknown or rule not evaluable); review required, not a clean result",
		);
	}

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

/**
 * Exit status contract for the infrastructure leg (CI-usable):
 *   2 - at least one version-confirmed critical or high CVE;
 *   1 - the assessment is incomplete: a target could not be scanned, or a
 *       detected product has CVEs whose applicability is unconfirmed;
 *   0 - every target was scanned and nothing applicable was matched.
 * Unconfirmed findings are never folded into 0: an unknown version is not clean.
 */
function scanExitCode(summary: AigInfraScanSummary): 0 | 1 | 2 {
	if (summary.confirmedCritical > 0 || summary.confirmedHigh > 0) return 2;
	if (summary.unconfirmedFindings > 0 || summary.targets.some((target) => target.error !== null)) {
		return 1;
	}
	return 0;
}

/** Combined exit status: the infrastructure contract above plus skill and code scans. */
function setExitCode(
	summary: AigInfraScanSummary | null,
	skills: SkillScanReport | null,
	codeResults: CodeScanResults | null = null,
): void {
	const code = codeResults?.reports ?? null;
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
	const infra = summary ? scanExitCode(summary) : 0;
	// Non-zero when a vulnerability was found, so this is usable in CI.
	if (infra === 2 || skillSevere || codeSevere) {
		process.exitCode = 2;
		return;
	}
	const skillIncomplete = skills
		? skills.missing.length > 0 ||
			skills.rules === 0 ||
			skills.results.some((result) =>
				(result.unavailableChecks ?? []).some((entry) => entry.check === "plugin_files"),
			)
		: false;
	const codeIncomplete =
		code?.some((report) => !report.exists || report.filesSkipped > 0 || report.rules === 0) ??
		false;
	// Bundled rules that did not load or verify: the scan is degraded, never a clean 0.
	const rulesIncomplete = incompleteRules(skills, codeResults).length > 0;
	process.exitCode = infra === 1 || skillIncomplete || codeIncomplete || rulesIncomplete ? 1 : 0;
}

export default scanCommand;
