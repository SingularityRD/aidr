#!/usr/bin/env node
// Browser Guard real-browser E2E runner.
//
//   node e2e/run.mjs [--ext <dir>] [--only <ids>] [--headed] [--self-test] [--report <file>]
//
// Loads the unpacked extension into Chromium (Playwright persistent context),
// serves simulated AI chat sites for the real product origins through
// context.route, drives them like a user and checks what would have left the
// browser. Prints a summary table, writes a JSON report (default
// e2e/report.json) and exits non-zero when any scenario fails.
//
// --self-test swaps the product extension for a throwaway MV3 extension
// generated in os.tmpdir() (lib/self-test-extension.mjs) and additionally runs
// a negative control, proving the harness can both pass and fail scenarios
// independent of the product build.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { PROFILES } from "./lib/data.mjs";
import { Checks } from "./lib/expect.mjs";
import { launch } from "./lib/harness.mjs";
import { createSelfTestExtension } from "./lib/self-test-extension.mjs";
import { SCENARIOS, selectScenarios } from "./scenarios/index.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const SCENARIO_TIMEOUT_MS = 60_000;

const USAGE = `Usage: node e2e/run.mjs [options]

  --ext <dir>       unpacked extension directory (default: ../dist/chrome relative to e2e/)
  --only <ids>      comma-separated scenario ids or id prefixes (e.g. auto,mode-block)
  --headed          show the browser window
  --self-test       run against a generated throwaway extension to verify the harness
  --report <file>   JSON report path (default: e2e/report.json)
  --list            list scenario ids and exit
  -h, --help        show this help

Exit codes: 0 all selected scenarios passed (skips allowed), 1 a scenario failed,
2 the harness could not start (no build, browser or extension did not load).`;

function parseCli(argv) {
	const { values } = parseArgs({
		args: argv,
		options: {
			ext: { type: "string" },
			only: { type: "string" },
			headed: { type: "boolean", default: false },
			"self-test": { type: "boolean", default: false },
			report: { type: "string" },
			list: { type: "boolean", default: false },
			help: { type: "boolean", short: "h", default: false },
		},
		strict: true,
	});
	return values;
}

function withTimeout(promise, ms, label) {
	let timer;
	const timeout = new Promise((_, reject) => {
		timer = setTimeout(() => reject(new Error(`${label} exceeded ${ms}ms`)), ms);
	});
	return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** Runs one scenario in fresh tabs and returns its report row. */
async function runScenario(h, scenario, data, { settingsOverride, artifactsDir } = {}) {
	const started = Date.now();
	const checks = new Checks();
	const pages = [];
	const row = { id: scenario.id, title: scenario.title, status: "pass", checks: checks.results };

	const skipReason = scenario.skip?.(h);
	if (skipReason) {
		return { ...row, status: "skip", reason: skipReason, durationMs: 0 };
	}

	const open = async (siteKey, options) => {
		const page = await h.openSite(siteKey, options);
		pages.push(page);
		return page;
	};

	try {
		const settings = settingsOverride ?? scenario.settings;
		if (settings) row.settingsApplied = await h.setUserSettings(settings);
		await withTimeout(scenario.run({ h, checks, data, open }), SCENARIO_TIMEOUT_MS, scenario.id);
	} catch (error) {
		row.error = `${error.name ?? "Error"}: ${error.message}`;
		if (error.details !== undefined) row.errorDetails = error.details;
	}

	if (row.error || checks.failed.length > 0) {
		row.status = "fail";
		const page = pages.findLast((p) => !p.isClosed());
		if (page && artifactsDir) {
			fs.mkdirSync(artifactsDir, { recursive: true });
			const file = path.join(artifactsDir, `${scenario.id}.png`);
			if (
				await page.screenshot({ path: file, fullPage: true }).then(
					() => true,
					() => false,
				)
			) {
				row.screenshot = path.relative(process.cwd(), file);
			}
		}
	}
	const pageErrors = pages.flatMap((p) => p.__pageErrors ?? []);
	if (pageErrors.length > 0) row.pageErrors = pageErrors.slice(0, 20);
	for (const page of pages) await page.close().catch(() => {});
	row.durationMs = Date.now() - started;
	return row;
}

/**
 * Negative control (self-test only): the auto-mask scenario is run with the
 * guard in monitor mode, so the prompt leaves unmasked. The harness must
 * report that scenario as failed; if it passes, the assertions are not
 * actually looking at the recorded traffic.
 */
async function negativeControl(h, data) {
	const target = SCENARIOS.find((s) => s.id === "auto-chatgpt");
	const inner = await runScenario(h, target, data, { settingsOverride: { mode: "monitor" } });
	const failedChecks = inner.checks.filter((c) => !c.ok).map((c) => c.name);
	const detected =
		inner.status === "fail" &&
		failedChecks.some((n) => /does not contain|no request carried/.test(n));
	return {
		id: "self-test-negative-control",
		title: "harness: an unmasked send (monitor mode) is reported as a failure",
		status: detected ? "pass" : "fail",
		checks: [
			{
				name: "auto-chatgpt fails when the guard does not mask",
				ok: detected,
				...(detected
					? {}
					: { details: JSON.stringify({ status: inner.status, error: inner.error }) }),
			},
		],
		innerFailedChecks: failedChecks,
		durationMs: inner.durationMs,
	};
}

function pad(text, width) {
	const s = String(text);
	return s.length >= width ? `${s.slice(0, width - 1)}…` : s + " ".repeat(width - s.length);
}

function printSummary(rows, log) {
	const idWidth = Math.max(10, ...rows.map((r) => r.id.length)) + 2;
	log("");
	log(`${pad("SCENARIO", idWidth)}${pad("RESULT", 8)}${pad("CHECKS", 9)}${pad("TIME", 8)}NOTE`);
	log("-".repeat(idWidth + 8 + 9 + 8 + 40));
	for (const r of rows) {
		const passed = r.checks.filter((c) => c.ok).length;
		const counts = r.status === "skip" ? "-" : `${passed}/${r.checks.length}`;
		const note =
			r.status === "skip"
				? r.reason
				: r.status === "fail"
					? (r.error ?? `failed: ${r.checks.find((c) => !c.ok)?.name ?? "?"}`)
					: "";
		log(
			`${pad(r.id, idWidth)}${pad(r.status.toUpperCase(), 8)}${pad(counts, 9)}${pad(`${(r.durationMs / 1000).toFixed(1)}s`, 8)}${note}`,
		);
	}
	const by = (s) => rows.filter((r) => r.status === s).length;
	log("-".repeat(idWidth + 8 + 9 + 8 + 40));
	log(
		`${rows.length} scenarios: ${by("pass")} passed, ${by("fail")} failed, ${by("skip")} skipped`,
	);
}

function printFailures(rows, log) {
	for (const r of rows.filter((x) => x.status === "fail")) {
		log(`\nFAIL ${r.id}: ${r.title}`);
		if (r.error)
			log(`  error: ${r.error}${r.errorDetails ? ` ${JSON.stringify(r.errorDetails)}` : ""}`);
		for (const c of r.checks.filter((x) => !x.ok)) {
			log(`  x ${c.name}${c.details ? `\n      ${c.details}` : ""}`);
		}
		if (r.pageErrors) log(`  page errors: ${r.pageErrors.join(" | ")}`);
		if (r.screenshot) log(`  screenshot: ${r.screenshot}`);
	}
}

async function main() {
	let args;
	try {
		args = parseCli(process.argv.slice(2));
	} catch (error) {
		console.error(`${error.message}\n\n${USAGE}`);
		return 2;
	}
	if (args.help) {
		console.log(USAGE);
		return 0;
	}
	if (args.list) {
		for (const s of SCENARIOS) console.log(`${s.id}\t${s.title}`);
		return 0;
	}

	const log = (line) => console.log(line);
	const selfTest = args["self-test"];
	let scenarios;
	try {
		scenarios = selectScenarios(args.only);
	} catch (error) {
		console.error(error.message);
		return 2;
	}
	if (!scenarios.some((s) => s.id === "preflight")) scenarios = [SCENARIOS[0], ...scenarios];

	const selfTestDir = selfTest ? createSelfTestExtension() : null;
	const extDir = path.resolve(selfTestDir ?? args.ext ?? path.join(here, "../dist/chrome"));
	const reportPath = path.resolve(args.report ?? path.join(here, "report.json"));
	const artifactsDir = path.join(here, "artifacts");
	const data = selfTest ? PROFILES.selfTest : PROFILES.full;
	const started = new Date();

	log(`Browser Guard E2E${selfTest ? " (self-test: generated harness extension)" : ""}`);
	log(`extension: ${extDir}`);

	let h;
	try {
		h = await launch({ extDir, headed: args.headed, log });
	} catch (error) {
		console.error(`\nharness could not start: ${error.message}`);
		if (selfTestDir) fs.rmSync(selfTestDir, { recursive: true, force: true });
		return 2;
	}
	log(`browser: Chromium ${h.browserVersion} via ${h.launchMode}`);
	log(`extension id: ${h.extensionId} (${h.manifest.name} ${h.manifest.version})`);

	const rows = [];
	try {
		for (const scenario of scenarios) {
			const row = await runScenario(h, scenario, data, { artifactsDir });
			rows.push(row);
			log(`${row.status === "pass" ? "ok  " : row.status === "skip" ? "skip" : "FAIL"} ${row.id}`);
			if (scenario.id === "preflight" && row.status === "fail") {
				log("preflight failed: the harness itself is broken, not running product scenarios");
				break;
			}
		}
		if (selfTest && rows.every((r) => r.status !== "fail")) {
			const row = await negativeControl(h, data);
			rows.push(row);
			log(`${row.status === "pass" ? "ok  " : "FAIL"} ${row.id}`);
		}
	} finally {
		await h.close();
		if (selfTestDir) fs.rmSync(selfTestDir, { recursive: true, force: true });
	}

	printSummary(rows, log);
	printFailures(rows, log);

	const report = {
		suite: "browser-guard-e2e",
		selfTest,
		startedAt: started.toISOString(),
		finishedAt: new Date().toISOString(),
		browser: {
			name: "chromium",
			version: h.browserVersion,
			launchMode: h.launchMode,
			headed: args.headed,
		},
		extension: {
			dir: selfTest ? "<generated self-test extension>" : extDir,
			id: h.extensionId,
			name: h.manifest.name,
			version: h.manifest.version,
		},
		totals: {
			scenarios: rows.length,
			passed: rows.filter((r) => r.status === "pass").length,
			failed: rows.filter((r) => r.status === "fail").length,
			skipped: rows.filter((r) => r.status === "skip").length,
		},
		scenarios: rows,
	};
	fs.mkdirSync(path.dirname(reportPath), { recursive: true });
	fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
	log(`\nreport: ${path.relative(process.cwd(), reportPath)}`);

	return report.totals.failed > 0 ? 1 : 0;
}

main().then(
	(code) => {
		process.exitCode = code;
	},
	(error) => {
		console.error(error?.stack ?? String(error));
		process.exitCode = 2;
	},
);
