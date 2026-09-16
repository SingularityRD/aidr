#!/usr/bin/env node
/**
 * Verify a packed AIDR plugin against an official OpenClaw installation.
 *
 * This creates an isolated HOME/state and consumer prefix, installs only the
 * supplied tarball, runs OpenClaw's runtime plugin inspector, then starts a
 * loopback Gateway and checks health. It never configures a provider and does
 * not claim a model-driven tool-call test.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const options = parseArgs(process.argv.slice(2));
if (options.help) {
	console.log("Usage: node scripts/verify-openclaw-release-host.mjs --package <plugin.tgz> --openclaw-root <dir> [--node <node>] [--port <port>] [--keep]");
	process.exit(0);
}
for (const key of ["package", "openclawRoot"]) {
	if (!options[key]) fail(`missing --${key === "openclawRoot" ? "openclaw-root" : key}`);
}
const tarball = path.resolve(options.package);
const openclawRoot = path.resolve(options.openclawRoot);
const node = path.resolve(options.node ?? process.execPath);
const cli = path.join(openclawRoot, "openclaw.mjs");
for (const [label, target] of [["plugin tarball", tarball], ["OpenClaw CLI", cli], ["Node runtime", node]]) {
	if (!existsSync(target)) fail(`${label} not found: ${target}`);
}

const root = mkdtempSync(path.join(tmpdir(), "aidr-openclaw-host-"));
const consumer = path.join(root, "consumer");
const home = path.join(root, "home");
const state = path.join(home, ".openclaw");
const workspace = path.join(state, "workspace");
mkdirSync(consumer, { recursive: true });
mkdirSync(workspace, { recursive: true });
const environment = isolatedEnvironment({ home, state });
let gateway;
let gatewayOutput = "";

try {
	writeFileSync(path.join(consumer, "package.json"), `${JSON.stringify({ name: "aidr-openclaw-host-consumer", private: true }, null, 2)}\n`);
	// npm materializes a real package tree here. A pnpm junction would let the
	// host inspect a content-addressed store path instead of the isolated prefix,
	// weakening this consumer test and failing OpenClaw's path trust boundary.
	const install = runNpm(["install", "--offline", "--ignore-scripts", "--omit=optional", tarball], consumer, environment, 300_000);
	assertSuccess(install, "isolated plugin install");

	const pluginRoot = realpathSync(path.join(consumer, "node_modules", "@singularityrd", "aidr-openclaw"));
	const pkg = JSON.parse(readFileSync(path.join(pluginRoot, "package.json"), "utf8"));
	const manifest = JSON.parse(readFileSync(path.join(pluginRoot, "openclaw.plugin.json"), "utf8"));
	assert(JSON.stringify(pkg.openclaw?.extensions) === JSON.stringify(["./dist/index.cjs"]), "packed package must declare openclaw.extensions");
	assert(!pkg.dependencies?.["@singularityrd/aidr-core"], "packed plugin must not declare bundled core as a runtime dependency");
	assert(JSON.stringify(manifest.contracts?.tools) === JSON.stringify(["aidr_allowlist_add", "aidr_allowlist_remove"]), "plugin manifest tools contract does not match registration");

	const port = options.port ?? 19_000 + (process.pid % 1_000);
	writeFileSync(path.join(state, "openclaw.json"), `${JSON.stringify({
		gateway: { mode: "local", bind: "loopback", port, auth: { mode: "none" } },
		agents: { defaults: { workspace } },
		plugins: { enabled: true, allow: ["aidr-openclaw"], load: { paths: [pluginRoot] }, entries: { "aidr-openclaw": { enabled: true } } },
	}, null, 2)}\n`);

	const inspect = runOpenClaw(["plugins", "inspect", "aidr-openclaw", "--runtime", "--json"], environment, 120_000);
	assertSuccess(inspect, "OpenClaw runtime plugin inspection");
	const inspection = parseJsonOutput(inspect.stdout);
	assert(inspection?.plugin?.status === "loaded" || inspection?.status === "loaded", "OpenClaw did not report the plugin loaded");
	const inspectionText = `${inspect.stdout}\n${inspect.stderr}`;
	for (const required of ["aidr_allowlist_add", "aidr_allowlist_remove", "before_tool_call", "before_prompt_build"]) assert(inspectionText.includes(required), `runtime inspection omitted ${required}`);
	for (const forbidden of ["required dependencies are missing", "plugin must declare contracts.tools", "unknown typed hook"]) assert(!inspectionText.includes(forbidden), `runtime inspection reported: ${forbidden}`);

	gateway = spawn(node, [cli, "gateway", "run", "--port", String(port), "--bind", "loopback", "--auth", "none"], {
		cwd: consumer,
		env: environment,
		windowsHide: true,
		stdio: ["ignore", "pipe", "pipe"],
	});
	gateway.stdout.on("data", (chunk) => { gatewayOutput += chunk.toString(); });
	gateway.stderr.on("data", (chunk) => { gatewayOutput += chunk.toString(); });

	let health;
	for (let attempt = 0; attempt < 60; attempt++) {
		if (gateway.exitCode !== null) fail(`Gateway exited before becoming healthy (${gateway.exitCode}): ${tail(gatewayOutput)}`);
		health = runOpenClaw(["health", "--json"], environment, 10_000);
		if (health.status === 0) break;
		wait(500);
	}
	assertSuccess(health, "isolated OpenClaw Gateway health");
	const healthPayload = parseJsonOutput(health.stdout);
	assert(healthPayload?.ok === true, "Gateway health did not report ok=true");
	assert(
		JSON.stringify(healthPayload).includes("aidr-openclaw"),
		`Gateway health did not report AIDR loaded: ${tail(gatewayOutput)}`,
	);

	console.log(JSON.stringify({
		status: "PASS",
		openclawVersion: JSON.parse(readFileSync(path.join(openclawRoot, "package.json"), "utf8")).version,
		pluginVersion: pkg.version,
		checks: ["packed contract", "isolated offline install", "runtime plugin inspect", "loopback gateway startup", "gateway health"],
		limitations: ["No provider credentials configured.", "No model turn or native model-driven tool call was attempted."],
	}, null, 2));
} finally {
	if (gateway && gateway.exitCode === null) {
		gateway.kill();
		await Promise.race([new Promise((resolve) => gateway.once("exit", resolve)), new Promise((resolve) => setTimeout(resolve, 5_000))]);
		if (gateway.exitCode === null) gateway.kill("SIGKILL");
	}
	if (options.keep) console.error(`kept isolated verification root: ${root}`);
	else rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}

function parseArgs(argv) {
	const result = { keep: false, help: false };
	for (let i = 0; i < argv.length; i++) {
		const value = argv[i];
		if (value === "--keep") result.keep = true;
		else if (value === "--help" || value === "-h") result.help = true;
		else if (["--package", "--openclaw-root", "--node", "--port"].includes(value)) {
			const next = argv[++i];
			if (!next) fail(`${value} requires a value`);
			const key = value === "--openclaw-root" ? "openclawRoot" : value.slice(2);
			result[key] = value === "--port" ? Number(next) : next;
		} else fail(`unknown argument: ${value}`);
	}
	return result;
}

function isolatedEnvironment({ home, state }) {
	const env = {};
	for (const [key, value] of Object.entries(process.env)) {
		if (value === undefined || /^(HOME|USERPROFILE|OPENCLAW_|ANTHROPIC_|OPENAI_|GOOGLE_|AWS_|AZURE_)/i.test(key)) continue;
		env[key] = value;
	}
	return { ...env, HOME: home, USERPROFILE: home, OPENCLAW_STATE_DIR: state, OPENCLAW_CONFIG_PATH: path.join(state, "openclaw.json"), CI: "1", NO_COLOR: "1" };
}

function runOpenClaw(args, env, timeout) {
	return spawnSync(node, [cli, ...args], { cwd: consumer, env, encoding: "utf8", timeout, maxBuffer: 16 * 1024 * 1024, windowsHide: true });
}

function runNpm(args, cwd, env, timeout) {
	const lifecycleNpmCli = process.env.npm_execpath;
	const npmCliCandidates = [
		lifecycleNpmCli && /(?:^|[\\/])npm-cli\.js$/i.test(lifecycleNpmCli) ? lifecycleNpmCli : undefined,
		path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"),
	].filter(Boolean);
	const npmCli = npmCliCandidates.find((candidate) => existsSync(candidate));
	const command = npmCli ? process.execPath : process.platform === "win32" ? "npm.cmd" : "npm";
	const commandArgs = npmCli ? [npmCli, ...args] : args;
	return spawnSync(command, commandArgs, { cwd, env, encoding: "utf8", timeout, shell: false, maxBuffer: 16 * 1024 * 1024, windowsHide: true });
}

function parseJsonOutput(output) {
	const start = output.indexOf("{");
	const end = output.lastIndexOf("}");
	if (start < 0 || end < start) fail(`command did not emit JSON: ${tail(output)}`);
	try { return JSON.parse(output.slice(start, end + 1)); } catch (error) { fail(`command emitted invalid JSON: ${error.message}`); }
}
function assertSuccess(result, label) {
	if (!result || result.error || result.status !== 0) fail(`${label} failed (${result?.error?.message ?? `exit ${result?.status}`}): ${tail(`${result?.stderr ?? ""}\n${result?.stdout ?? ""}`)}`);
}
function assert(condition, message) { if (!condition) fail(message); }
function fail(message) { throw new Error(`FAIL: ${message}`); }
function wait(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function tail(value, lines = 12) { return String(value ?? "").trim().split(/\r?\n/).slice(-lines).join("\n"); }
