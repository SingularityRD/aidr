#!/usr/bin/env node
/**
 * Supply-chain gate for the optional AI Security Posture scanner, which is
 * built from the vendored AI-Infra-Guard tree and therefore outside the root
 * `pnpm audit:prod` (workspace lockfile only).
 *
 *   node scripts/audit-vendored-aig.mjs [--skip-audit]
 *
 * Fails closed on:
 *   - any production advisory in vendor/ai-infra-guard/frontend
 *     (`pnpm audit --prod --ignore-workspace`, parsed like audit:prod);
 *   - a vendored Go toolchain below the supported floor, or Go builder images
 *     whose tag differs from the go.mod `toolchain` line;
 *   - an image base (FROM) that is not pinned by @sha256 digest, or a final
 *     stage without an explicit non-root USER, in any Dockerfile that AIDR
 *     builds (deploy/, services/aig-bridge, the two vendored AIG images).
 *
 * The Go module's own advisories need the Go vulnerability database and are
 * checked by govulncheck in the CI `posture-scanner-supply-chain` job; the
 * vendored Python locks and the whole tree are scanned there with Trivy.
 * `--skip-audit` runs only the offline checks.
 */

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assessProductionAuditReport } from "./audit-production-deps-report.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const VENDOR_DIR = "vendor/ai-infra-guard";
export const FRONTEND_DIR = `${VENDOR_DIR}/frontend`;

/**
 * Lowest Go minor still receiving security fixes. Go supports the two newest
 * minors, so raise this when a new minor ships (Go 1.28 is due in Feb 2027).
 */
export const SUPPORTED_GO_FLOOR = [1, 26];

/** Dockerfiles AIDR builds or ships, relative to the repository root. */
export const BUILT_DOCKERFILES = Object.freeze([
	"deploy/dashboard/Dockerfile",
	"deploy/privacy-gateway/Dockerfile",
	"deploy/helm/images/edge-functions.Dockerfile",
	"deploy/helm/images/migrations.Dockerfile",
	"deploy/helm/images/posture-scanner-agent.Dockerfile",
	"services/aig-bridge/Dockerfile",
	`${VENDOR_DIR}/Dockerfile`,
	`${VENDOR_DIR}/Dockerfile_Agent`,
]);

/**
 * Bases that are not registry images but an image built earlier in the same
 * build-images.mjs run from a Dockerfile in BUILT_DOCKERFILES.
 */
export const LOCAL_BUILD_ARG_BASES = Object.freeze({
	"deploy/helm/images/posture-scanner-agent.Dockerfile": "${AIG_AGENT_BASE}",
});

const DIGEST = /@sha256:[0-9a-f]{64}$/u;
const ROOT_USERS = new Set(["root", "0", "0:0", "root:root"]);

/** Classify a pnpm audit report: every advisory is a failure (fail closed). */
export function assessVendoredFrontendAudit(report, outcome = {}) {
	const { advisories, failures } = assessProductionAuditReport(report, outcome);
	for (const advisory of advisories) {
		const id = advisory.github_advisory_id ?? advisory.id ?? "unknown";
		failures.push(`${advisory.module_name} ${advisory.findings?.[0]?.version ?? "?"}: ${advisory.severity} ${id} (patched ${advisory.patched_versions})`);
	}
	return failures;
}

function parseGoVersion(value) {
	const match = /^(?:go)?(\d+)\.(\d+)(?:\.(\d+))?$/u.exec(String(value ?? "").trim());
	return match ? [Number(match[1]), Number(match[2]), Number(match[3] ?? 0)] : null;
}

const below = ([major, minor], [floorMajor, floorMinor]) => major < floorMajor || (major === floorMajor && minor < floorMinor);

/** go.mod `go`/`toolchain` lines and the golang builder tags must agree and be supported. */
export function checkGoToolchain(goMod, dockerfiles, floor = SUPPORTED_GO_FLOOR) {
	const failures = [];
	const language = parseGoVersion(/^go\s+(\S+)\s*$/mu.exec(goMod)?.[1]);
	const toolchainText = /^toolchain\s+(\S+)\s*$/mu.exec(goMod)?.[1];
	const toolchain = parseGoVersion(toolchainText);
	if (!language) failures.push("go.mod has no valid `go` line");
	if (!toolchain) failures.push("go.mod has no valid `toolchain goX.Y.Z` line");
	const effective = toolchain ?? language;
	if (effective && below(effective, floor)) failures.push(`Go ${effective.join(".")} is below the supported floor ${floor.join(".")}`);
	if (language && toolchain && below(toolchain, language)) failures.push("go.mod toolchain is older than its go line");
	for (const [name, text] of Object.entries(dockerfiles)) {
		const tags = [...text.matchAll(/^FROM\s+(?:docker\.io\/)?(?:library\/)?golang:(\d+\.\d+(?:\.\d+)?)[-@\s]/gmu)].map((match) => match[1]);
		if (tags.length === 0) failures.push(`${name}: no golang builder stage`);
		for (const tag of tags) {
			if (toolchainText && `go${tag}` !== toolchainText) failures.push(`${name}: golang:${tag} does not match go.mod ${toolchainText}`);
		}
	}
	return failures;
}

/** Every FROM is digest-pinned (or a known same-run base) and the final stage runs as non-root. */
export function checkDockerfile(name, text, localBase = LOCAL_BUILD_ARG_BASES[name]) {
	const failures = [];
	const stages = new Set();
	let lastFrom = -1;
	const lines = text.split(/\r?\n/u);
	lines.forEach((line, index) => {
		const match = /^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$/iu.exec(line.trim());
		if (!match) return;
		lastFrom = index;
		const [, image, alias] = match;
		if (stages.has(image.toLowerCase())) {
			// FROM <earlier stage>
		} else if (localBase && image === localBase) {
			// Built earlier in the same run from a digest-pinned Dockerfile.
		} else if (!DIGEST.test(image)) {
			failures.push(`${name}:${index + 1}: base ${image} is not pinned by @sha256 digest`);
		}
		if (alias) stages.add(alias.toLowerCase());
	});
	if (lastFrom < 0) failures.push(`${name}: no FROM line`);
	const users = lines.slice(lastFrom + 1).map((line) => /^USER\s+(\S+)/iu.exec(line.trim())?.[1]).filter(Boolean);
	const finalUser = users.at(-1);
	if (!finalUser) failures.push(`${name}: final stage has no USER (would run as root)`);
	else if (ROOT_USERS.has(finalUser.toLowerCase())) failures.push(`${name}: final stage runs as ${finalUser}`);
	return failures;
}

export function offlineChecks(read = (path) => readFileSync(join(root, path), "utf8")) {
	const failures = [];
	const goDockerfiles = Object.fromEntries([`${VENDOR_DIR}/Dockerfile`, `${VENDOR_DIR}/Dockerfile_Agent`].map((path) => [path, read(path)]));
	failures.push(...checkGoToolchain(read(`${VENDOR_DIR}/go.mod`), goDockerfiles));
	for (const path of BUILT_DOCKERFILES) failures.push(...checkDockerfile(path, read(path)));
	return failures;
}

function runFrontendAudit() {
	const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
	const audit = spawnSync(pnpm, ["audit", "--prod", "--json", "--ignore-workspace"], {
		cwd: join(root, FRONTEND_DIR),
		encoding: "utf8",
		maxBuffer: 32 * 1024 * 1024,
		shell: process.platform === "win32",
	});
	let report = null;
	try {
		report = JSON.parse((audit.stdout ?? "").trim());
	} catch {
		return [`${FRONTEND_DIR}: pnpm audit produced no parseable JSON ${(audit.stderr ?? "").trim().slice(0, 300)}`];
	}
	return assessVendoredFrontendAudit(report, { status: audit.status, error: audit.error, signal: audit.signal }).map((failure) => `${FRONTEND_DIR}: ${failure}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	const failures = offlineChecks();
	if (!process.argv.includes("--skip-audit")) failures.push(...runFrontendAudit());
	if (failures.length > 0) {
		console.error("Vendored posture scanner supply-chain gate failed:");
		for (const failure of failures) console.error(`- ${failure}`);
		process.exit(1);
	}
	console.log(`Vendored posture scanner gate passed (${BUILT_DOCKERFILES.length} Dockerfiles${process.argv.includes("--skip-audit") ? ", audit skipped" : ", frontend production audit clean"}).`);
}
