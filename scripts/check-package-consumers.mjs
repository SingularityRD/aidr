/**
 * Exercise the release artifacts the same way a consumer would.
 *
 * `check-package-contracts.mjs` proves that declared paths exist. This gate
 * goes one step further and loads/runs the paths that can be exercised in a
 * Node-only release environment. VS Code extension entry points are parsed
 * with `node --check` because the real `vscode` host is intentionally not
 * available in CI or in a plain Node consumer process.
 *
 * Usage:
 *   node scripts/check-package-consumers.mjs [packageDir ...]
 *
 * With no arguments all release package artifacts are checked. Passing
 * package directories is useful when iterating on one package locally.
 */

import {
	existsSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import { tarDirectory } from "./lib/tar-path.mjs";
import { cleanupDirectory } from "./release-candidate-cleanup.mjs";
import { resolvePnpmEntry } from "./build-workspace.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const TARGETS = [
	{ key: "packages/core", check: checkCore },
	{ key: "packages/claude-code", check: checkClaude },
	{ key: "packages/extension", check: checkExtension },
	{ key: "packages/openclaw", check: checkOpenClaw },
	{ key: "packages/opencode", check: checkOpenCode },
	{ key: "packages/cli", check: checkCli },
	{ key: "packages/sdk", check: checkSdk },
	{ key: "packages/dashboard", check: checkDashboard },
	{ key: "packages/codex", check: checkCodex },
	{ key: "packages/mcp-gateway", check: checkMcpGateway },
];

const requested = process.argv.slice(2).map(normalizePackageArg);
const failures = [];

if (requested.length > 0) {
	for (const arg of requested) {
		if (!TARGETS.some((target) => target.key === arg)) {
			failures.push(`Unknown package directory: ${arg}`);
		}
	}
}

const selected = TARGETS.filter((target) => requested.length === 0 || requested.includes(target.key));

for (const target of selected) {
	try {
		await target.check();
		console.log(`PASS ${target.key} consumer smoke`);
	} catch (error) {
		failures.push(`${target.key}: ${formatError(error)}`);
	}
}

if (failures.length > 0) {
	console.error("ERROR: release package consumer checks failed:");
	for (const failure of failures) console.error(`  - ${failure}`);
	process.exit(1);
}

console.log(`Package consumer checks passed for ${selected.length} package(s).`);

async function checkCore() {
	const entry = artifact("packages/core/dist/index.js");
	const result = runNodeModule(
		entry,
		"const mod = await import(process.argv[1]); if (typeof mod.evaluateToolCall !== 'function') throw new Error('evaluateToolCall export is missing');",
	);
	assertSuccess(result, "core ESM import");
}

async function checkClaude() {
	const entry = artifact("packages/claude-code/dist/health.cjs");
	const cleanCwd = mkdtempSync(path.join(tmpdir(), "aidr-claude-consumer-"));
	let result;
	try {
		result = runNode([entry, "--json"], { cwd: cleanCwd });
	} finally {
		rmSync(cleanCwd, { recursive: true, force: true });
	}
	assertClaudeHealthResult(result, "Claude health --json");

	// Pack and extract the actual package, then run its bin outside the
	// repository. This catches missing `files` entries and workspace-cwd
	// assumptions that a direct dist smoke would miss.
	const packRoot = mkdtempSync(path.join(tmpdir(), "aidr-claude-pack-"));
	const extractedRoot = mkdtempSync(path.join(tmpdir(), "aidr-claude-extract-"));
	try {
		const packageDir = path.join(repoRoot, "packages", "claude-code");
		const packed = runPnpm(["pack", "--pack-destination", packRoot], packageDir);
		assertSuccess(packed, "Claude package pack");
		const tarballs = readdirSync(packRoot).filter((name) => name.endsWith(".tgz"));
		if (tarballs.length !== 1) {
			throw new Error(`expected one Claude tarball, found ${tarballs.length}`);
		}
		const extracted = runCommand("tar", ["-xzf", tarballs[0], "-C", tarDirectory(extractedRoot)], packRoot); // relative archive + cwd: GNU tar on Windows parses "C:" as a host
		assertSuccess(extracted, "Claude package extraction");

		const unpacked = path.join(extractedRoot, "package");
		for (const required of [
			"package.json",
			"dist/health.cjs",
			"dist/pre-tool-use.cjs",
			"dist/pre-tool-use.bundle.cjs",
			"resources/threats",
			"resources/allowlists",
		]) {
			if (!existsSync(path.join(unpacked, required))) {
				throw new Error(`Claude tarball is missing ${required}`);
			}
		}
		const unpackedHealth = path.join(unpacked, "dist", "health.cjs");
		const unpackedCwd = mkdtempSync(path.join(tmpdir(), "aidr-claude-unpacked-cwd-"));
		try {
			const unpackedResult = runNode([unpackedHealth, "--json"], { cwd: unpackedCwd });
			assertClaudeHealthResult(unpackedResult, "unpacked Claude health --json");
		} finally {
			rmSync(unpackedCwd, { recursive: true, force: true });
		}
	} finally {
		rmSync(packRoot, { recursive: true, force: true });
		cleanupDirectory(extractedRoot);
	}
}

function assertClaudeHealthResult(result, label) {
	assertSuccess(result, label);
	let payload;
	try {
		payload = JSON.parse(result.stdout);
	} catch (error) {
		throw new Error(`${label} output is not valid JSON: ${formatError(error)}`);
	}
	if (payload?.status !== "healthy") {
		throw new Error(`${label} status is ${JSON.stringify(payload?.status)} (expected healthy)`);
	}
	if (typeof payload?.checks !== "object" || payload.checks === null) {
		throw new Error(`${label} output is missing checks`);
	}
	const threatCheck = payload.checkDetails?.find?.((check) => check?.name === "threat_rules");
	if (threatCheck?.status !== "healthy" || Number(threatCheck?.details?.rulesCount ?? 0) <= 0) {
		throw new Error(`${label} packaged threat rules are missing or empty`);
	}
	if (!String(threatCheck?.details?.threatsDir ?? "").includes("resources")) {
		throw new Error(`${label} did not resolve threat rules from packaged resources`);
	}
}

async function checkExtension() {
	for (const rel of [
		"packages/extension/dist/cursor_extension.js",
		"packages/extension/dist/vscode_extension.js",
		"packages/extension/dist/aidr-hook.cjs",
		"packages/extension/dist/aidr-hook.bundle.cjs",
	]) {
		const entry = artifact(rel);
		const result = runNode(["--check", entry]);
		assertSuccess(result, `${rel} syntax check`);
	}
}

async function checkOpenClaw() {
	const packageDir = path.join(repoRoot, "packages", "openclaw");
	const packageJson = JSON.parse(readFileSync(path.join(packageDir, "package.json"), "utf8"));
	const manifest = JSON.parse(readFileSync(path.join(packageDir, "openclaw.plugin.json"), "utf8"));
	if (JSON.stringify(packageJson.openclaw?.extensions) !== JSON.stringify(["./dist/index.cjs"])) {
		throw new Error("package.json must declare openclaw.extensions for the bundled entry point");
	}
	if (packageJson.dependencies?.["@singularityrd/aidr-core"]) {
		throw new Error("bundled core must not remain a runtime dependency of the OpenClaw package");
	}
	const expectedTools = ["aidr_allowlist_add", "aidr_allowlist_remove"];
	if (JSON.stringify(manifest.contracts?.tools) !== JSON.stringify(expectedTools)) {
		throw new Error("openclaw.plugin.json contracts.tools does not match registered tools");
	}
	// OpenClaw rejects the pre-model tool-result middleware without this contract.
	if (JSON.stringify(manifest.contracts?.agentToolResultMiddleware) !== JSON.stringify(["openclaw"])) {
		throw new Error("openclaw.plugin.json must declare contracts.agentToolResultMiddleware for openclaw");
	}

	const entry = artifact("packages/openclaw/dist/index.cjs");
	const result = runNode([
		"-e",
		"const mod = require(process.argv[1]); const plugin = mod?.default ?? mod; if (typeof plugin?.register !== 'function') throw new Error('default plugin register() is missing');",
		entry,
	]);
	assertSuccess(result, "OpenClaw CommonJS import");
}

async function checkOpenCode() {
	const entry = artifact("packages/opencode/dist/index.js");
	const result = runNodeModule(
		entry,
		"const mod = await import(process.argv[1]); const plugin = mod?.AidrPlugin ?? mod?.default; if (typeof plugin !== 'function') throw new Error('AidrPlugin export is missing');",
	);
	assertSuccess(result, "OpenCode ESM import");
}

async function checkCli() {
	const entry = artifact("packages/cli/dist/index.js");
	const result = runNode([entry, "--help"]);
	assertSuccess(result, "AIDR CLI --help");
	if (!/Usage:\s+aidr\b/i.test(result.stdout)) {
		throw new Error("CLI help output does not contain the aidr usage header");
	}
}

async function checkCodex() {
	const result = runNodeModule(artifact("packages/codex/dist/index.js"),
		"const mod = await import(process.argv[1]); if (typeof mod.enforceCodexPreToolUse !== 'function') throw new Error('Codex enforcement export is missing');");
	assertSuccess(result, "Codex ESM consumer import");
	assertSuccess(runNode(["--check", artifact("packages/codex/dist/pre-tool-use.cjs")]), "Codex hook syntax");
	assertSuccess(runNode(["--check", artifact("packages/codex/dist/pre-tool-use.bundle.cjs")]), "Codex hook bundle syntax");
}

async function checkMcpGateway() {
	const gateway = artifact("packages/mcp-gateway/dist/aidr-mcp-gateway.mjs");
	const approve = artifact("packages/mcp-gateway/dist/aidr-mcp-approve.mjs");
	const stdio = artifact("packages/mcp-gateway/dist/aidr-mcp-stdio.mjs");
	const library = artifact("packages/mcp-gateway/dist/aidr-mcp-library.mjs");
	assertSuccess(runNode(["--check", gateway]), "MCP gateway syntax");
	assertSuccess(runNode(["--check", approve]), "MCP gateway operator CLI syntax");
	assertSuccess(runNode(["--check", stdio]), "MCP gateway stdio syntax");
	assertSuccess(runNode(["--check", library]), "MCP gateway public library syntax");
	const usage = runNode([gateway]);
	if (usage.status !== 2 || !/usage: aidr-mcp-gateway <config\.json>/.test(usage.stderr ?? "")) {
		throw new Error("MCP gateway did not report bounded configuration usage");
	}
}

async function checkSdk() {
	const cjsEntry = artifact("packages/sdk/dist/index.cjs");
	const esmEntry = artifact("packages/sdk/dist/index.mjs");
	artifact("packages/sdk/dist/index.d.ts");
	artifact("packages/sdk/dist/index.d.cts");
	const cjsResult = runNode([
		"-e",
		"const mod = require(process.argv[1]); if (typeof mod.AIDRClient !== 'function') throw new Error('AIDRClient export is missing'); if (typeof mod.SDK_VERSION !== 'string') throw new Error('SDK_VERSION export is missing');",
		cjsEntry,
	]);
	assertSuccess(cjsResult, "SDK CommonJS import");
	const esmResult = runNodeModule(
		esmEntry,
		"const mod = await import(process.argv[1]); if (typeof mod.AIDRClient !== 'function') throw new Error('AIDRClient export is missing'); if (typeof mod.SDK_VERSION !== 'string') throw new Error('SDK_VERSION export is missing');",
	);
	assertSuccess(esmResult, "SDK ESM import");

	const typecheckDir = mkdtempSync(path.join(repoRoot, "packages", "sdk", ".consumer-types-"));
	try {
		const source = `
import {
  AIDRClient,
  createGenericMiddleware,
  createMiddleware,
  createMiddlewarePipeline,
  createSyncCompatibleMiddleware,
  enforceToolOutput,
  guardToolOutput,
  scanToolOutput,
  wrapToolWithMiddleware,
} from "@singularityrd/aidr-sdk";
import type {
  CheckResult,
  MiddlewareEnforcementOptions,
  MiddlewareOptions,
  SDKConfig,
  ToolOutputGuardOptions,
  ToolOutputGuardResult,
} from "@singularityrd/aidr-sdk";

void [
  AIDRClient,
  createGenericMiddleware,
  createMiddleware,
  createMiddlewarePipeline,
  createSyncCompatibleMiddleware,
  enforceToolOutput,
  guardToolOutput,
  scanToolOutput,
  wrapToolWithMiddleware,
];
declare const retainedTypes: [
  CheckResult,
  MiddlewareEnforcementOptions,
  MiddlewareOptions,
  SDKConfig,
  ToolOutputGuardOptions,
  ToolOutputGuardResult<unknown>,
];
void retainedTypes;
`;
		const esmSource = path.join(typecheckDir, "consumer.mts");
		const cjsSource = path.join(typecheckDir, "consumer.cts");
		writeFileSync(esmSource, source);
		writeFileSync(cjsSource, source);
		const result = runNode([
			artifact("node_modules/typescript/bin/tsc"),
			"--noEmit",
			"--strict",
			"--target",
			"ES2022",
			"--module",
			"NodeNext",
			"--moduleResolution",
			"NodeNext",
			"--skipLibCheck",
			"false",
			esmSource,
			cjsSource,
		]);
		assertSuccess(result, "SDK ESM/CommonJS declaration imports");
	} finally {
		rmSync(typecheckDir, { recursive: true, force: true });
	}
}

async function checkDashboard() {
	const htmlPath = artifact("packages/dashboard/dist/index.html");
	const html = readFileSync(htmlPath, "utf8");
	if (!/<div[^>]+id=["']root["']/i.test(html)) {
		throw new Error("dashboard index.html is missing the root mount element");
	}
	if (!/(?:src|href)=["'][^"']*assets\//i.test(html)) {
		throw new Error("dashboard index.html does not reference a built asset");
	}
}

function artifact(relativePath) {
	const absolute = path.resolve(repoRoot, relativePath);
	if (!existsSync(absolute)) throw new Error(`missing release artifact ${relativePath}`);
	return absolute;
}

function runNode(args, options = {}) {
	return runCommand(process.execPath, args, options.cwd ?? repoRoot);
}

function runPnpm(args, cwd) {
	const useWindowsPnpmEntry = process.platform === "win32";
	return runCommand(
		useWindowsPnpmEntry ? process.execPath : "pnpm",
		useWindowsPnpmEntry ? [resolvePnpmEntry(), ...args] : args,
		cwd,
	);
}

function runCommand(command, args, cwd, options = {}) {
	return spawnSync(command, args, {
		cwd,
		shell: options.shell ?? false,
		encoding: "utf8",
		maxBuffer: 4 * 1024 * 1024,
		timeout: 30_000,
		env: {
			...process.env,
			NODE_ENV: "test",
			CI: "1",
		},
	});
}

function runNodeModule(entry, expression) {
	return runNode(["--input-type=module", "-e", expression, pathToFileURL(entry).href]);
}

function assertSuccess(result, label) {
	if (result.error) throw new Error(`${label} could not start: ${formatError(result.error)}`);
	if (result.status !== 0) {
		const details = [result.stderr, result.stdout].filter(Boolean).join("\n").trim();
		throw new Error(`${label} exited ${String(result.status)}${details ? `: ${details}` : ""}`);
	}
}

function normalizePackageArg(value) {
	const absolute = path.resolve(repoRoot, value);
	const relative = path.relative(repoRoot, absolute).replaceAll("\\", "/");
	return relative.replace(/\/$/, "");
}

function formatError(error) {
	return error instanceof Error ? error.message : String(error);
}
