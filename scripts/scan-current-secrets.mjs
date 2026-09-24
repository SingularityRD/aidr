#!/usr/bin/env node

import {
	copyFileSync,
	existsSync,
	lstatSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const REQUIRED_GITLEAKS_VERSION = "8.30.1";
const WIN_X64_GITLEAKS_SHA256 = "17157e2ee8b76fc8b1d8bee607a250e34b8a8023c8bc81822d4b5ee4d78fcb7c";
const CANARY_RULE_ID = "github-pat";
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export function stageCurrentCheckout(repoRoot, destination) {
	const output = execFileSync(
		"git",
		["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
		{ cwd: repoRoot },
	);
	const staged = [];

	for (const path of output.toString("utf8").split("\0")) {
		if (!path) continue;
		const source = resolve(repoRoot, path);
		const local = relative(repoRoot, source);
		if (isAbsolute(local) || local === ".." || local.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)) {
			throw new Error(`git returned a path outside the checkout: ${path}`);
		}
		if (!existsSync(source) || !lstatSync(source).isFile()) continue;
		const target = resolve(destination, local);
		mkdirSync(dirname(target), { recursive: true });
		copyFileSync(source, target);
		staged.push(local);
	}

	return staged;
}

export function verifyGitleaksCanary(gitleaks, configPath, run = spawnSync) {
	const staging = mkdtempSync(join(tmpdir(), "aidr-gitleaks-canary-"));
	try {
		const scanRoot = join(staging, "scan");
		mkdirSync(scanRoot);
		copyFileSync(configPath, join(scanRoot, ".gitleaks.toml"));
		writeFileSync(
			join(scanRoot, "canary.txt"),
			`token = "ghp_${randomBytes(18).toString("hex")}"\n`,
		);
		const reportPath = join(staging, "canary-report.json");
		const result = run(
			gitleaks,
			[
				"dir",
				".",
				"--config",
				".gitleaks.toml",
				"--redact",
				"--report-format",
				"json",
				"--report-path",
				reportPath,
			],
			{ cwd: scanRoot, encoding: "utf8", stdio: ["ignore", "ignore", "ignore"] },
		);
		if (result.error) throw result.error;
		if (result.status !== 1 || !existsSync(reportPath)) {
			throw new Error("scanner did not reject its synthetic credential canary");
		}
		const findings = JSON.parse(readFileSync(reportPath, "utf8"));
		if (
			!Array.isArray(findings) ||
			!findings.some((finding) => finding.RuleID === CANARY_RULE_ID && finding.File === "canary.txt")
		) {
			throw new Error("scanner did not report the expected canary rule");
		}
	} finally {
		rmSync(staging, { recursive: true, force: true });
	}
}

export function scanStagedCheckout({ staging, files, gitleaks, version, run = spawnSync, log = console }) {
	if (!files.includes(".gitleaks.toml")) {
		throw new Error(".gitleaks.toml is not a tracked or non-ignored regular file");
	}
	verifyGitleaksCanary(gitleaks, join(staging, ".gitleaks.toml"), run);
	log.log(`Scanning ${files.length} current-checkout files with Gitleaks ${version}.`);
	const reportPath = join(staging, ".gitleaks-current-report.json");
	const result = run(
		gitleaks,
		[
			"dir",
			".",
			"--config",
			".gitleaks.toml",
			"--redact",
			"--report-format",
			"json",
			"--report-path",
			reportPath,
		],
		{ cwd: staging, encoding: "utf8", stdio: ["ignore", "ignore", "ignore"] },
	);
	if (result.error) throw result.error;
	if (result.status === 0) {
		log.log(`Current-checkout secret scan passed (${files.length} files).`);
	} else if (result.status === 1 && existsSync(reportPath)) {
		const findings = JSON.parse(readFileSync(reportPath, "utf8"));
		for (const finding of findings) {
			log.error(
				JSON.stringify({
					rule: finding.RuleID ?? "unknown",
					file: finding.File ?? "unknown",
					line: finding.StartLine ?? null,
					commit: finding.Commit || null,
				}),
			);
		}
	}
	return result.status ?? 2;
}

export function scanCurrentCheckout(repoRoot = REPO_ROOT) {
	const gitleaks = process.env.GITLEAKS_BIN || "gitleaks";
	if (process.platform === "win32" && process.arch === "x64") {
		if (!isAbsolute(gitleaks)) throw new Error("set GITLEAKS_BIN to the verified official Windows x64 executable");
		const digest = createHash("sha256").update(readFileSync(gitleaks)).digest("hex");
		if (digest !== WIN_X64_GITLEAKS_SHA256) throw new Error("GITLEAKS_BIN does not match the pinned official Windows x64 executable");
	}
	const version = execFileSync(gitleaks, ["version"], { encoding: "utf8" }).trim();
	if (version !== REQUIRED_GITLEAKS_VERSION) {
		throw new Error(
			`gitleaks ${REQUIRED_GITLEAKS_VERSION} is required; found '${version || "unknown"}'`,
		);
	}

	const staging = mkdtempSync(join(tmpdir(), "aidr-gitleaks-current-"));
	try {
		const files = stageCurrentCheckout(repoRoot, staging);
		return scanStagedCheckout({ staging, files, gitleaks, version });
	} finally {
		rmSync(staging, { recursive: true, force: true });
	}
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		process.exitCode = scanCurrentCheckout();
	} catch (error) {
		console.error(`Current-checkout secret scan failed: ${error.message}`);
		process.exitCode = 2;
	}
}
