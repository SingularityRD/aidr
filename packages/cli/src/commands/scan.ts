import { readFileSync } from "node:fs";
import { atomicWriteJson, resolvePath, cveCount, fingerprintCount, type AigInfraTargetResult, scanTargets } from "@singularityrd/aidr-core";

interface ScanOptions {
	target?: string[];
	file?: string;
	json?: boolean;
	allowPublic?: boolean;
	timeout?: string;
	concurrency?: string;
	saveReport?: string;
}

/**
 * `aidr scan` — native AI-infrastructure scan.
 *
 * Runs the compiled AI-Infra-Guard fingerprints against the given targets
 * entirely in-process: HTTP probes, version extraction and CVE applicability.
 * No Go server, Python worker, Docker stack or LLM is involved.
 *
 * Safety: targets must be loopback or private unless `--allow-public` is passed
 * explicitly, so a typo cannot turn this into a public port scanner.
 */
async function scanCommand(options: ScanOptions): Promise<void> {
	const targets = collectTargets(options);

	if (targets.length === 0) {
		console.log("\n🛡️  AIDR infrastructure scan\n");
		console.log("No targets given.");
		console.log("\nUsage:");
		console.log("  aidr scan --target http://127.0.0.1:8080");
		console.log("  aidr scan --target http://127.0.0.1:8080 --target http://10.0.0.4:3000");
		console.log("  aidr scan --file targets.txt          # one URL per line");
		console.log("\nOptions:");
		console.log("  --json             machine-readable output");
		console.log("  --allow-public     permit non-private targets (off by default)");
		console.log("  --timeout <ms>     per-request timeout (default 3000)");
		console.log("  --concurrency <n>  parallel targets (default 4)");
		console.log(
			`\nDataset: ${fingerprintCount()} fingerprints, ${cveCount()} CVEs (compiled from AI-Infra-Guard).\n`,
		);
		return;
	}

	const timeoutMs = parsePositiveInt(options.timeout, 3000);
	const concurrency = parsePositiveInt(options.concurrency, 4);
	const allowPublic = Boolean(options.allowPublic);

	if (allowPublic) {
		console.error(
			"⚠️  --allow-public is set: targets outside loopback/private ranges will be contacted.\n",
		);
	}

	const summary = await scanTargets(targets, { timeoutMs, concurrency, allowPublicTargets: allowPublic });
	if (options.saveReport) await atomicWriteJson(resolvePath(options.saveReport), summary);

	if (options.json) {
		console.log(JSON.stringify(summary, null, 2));
		setExitCode(summary);
		return;
	}

	printHumanSummary(summary, targets.length);
	setExitCode(summary);
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

function printHumanSummary(
	summary: Awaited<ReturnType<typeof scanTargets>>,
	targetCount: number,
): void {
	console.log("\n🛡️  AIDR infrastructure scan\n");
	console.log(`Targets: ${targetCount}   Dataset: ${fingerprintCount()} fingerprints / ${cveCount()} CVEs\n`);

	for (const result of summary.targets) {
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

/**
 * Exit status contract (CI-usable):
 *   2 - at least one version-confirmed critical or high CVE;
 *   1 - the assessment is incomplete: a target could not be scanned, or a
 *       detected product has CVEs whose applicability is unconfirmed;
 *   0 - every target was scanned and nothing applicable was matched.
 * Unconfirmed findings are never folded into 0: an unknown version is not clean.
 */
export function scanExitCode(summary: Awaited<ReturnType<typeof scanTargets>>): 0 | 1 | 2 {
	if (summary.confirmedCritical > 0 || summary.confirmedHigh > 0) return 2;
	if (
		summary.unconfirmedFindings > 0 ||
		summary.targets.some((target) => target.error !== null)
	) {
		return 1;
	}
	return 0;
}

function setExitCode(summary: Awaited<ReturnType<typeof scanTargets>>): void {
	process.exitCode = scanExitCode(summary);
}

export default scanCommand;
