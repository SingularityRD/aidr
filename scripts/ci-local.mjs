#!/usr/bin/env node
/**
 * Run every gate .github/workflows/ci.yml runs, locally, with one command.
 *
 *   pnpm ci:local                 # full plan, stops at the first failing required step
 *   pnpm ci:local --keep-going    # run everything, then summarise
 *   pnpm ci:local:quick           # fast static/contract/drift subset
 *   pnpm ci:local --list          # groups, steps, commands, timeouts, prerequisites
 *
 * GitHub Actions is disabled for this organisation, so this is the gate. The
 * plan, selection, drift check against ci.yml and summary logic live in
 * scripts/lib/ci-local-plan.mjs (pure, tested by scripts/ci-local.test.mjs);
 * this file probes the host, provisions pinned tools on request, executes the
 * steps with live output and writes .ci-local/report.json.
 *
 * A step whose prerequisite is missing (Docker daemon, Helm, Node 24, ...) is
 * reported as SKIPPED with the exact prerequisite and the fix - never as PASS
 * and never silently. Requires bash (Linux, macOS, WSL or Git Bash).
 */

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, chmodSync, constants, copyFileSync, createWriteStream, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
	CI_WORKFLOW_PATH,
	GROUPS,
	LOCAL_DIR,
	ONPREM_EXTRA_SUITE_PATTERNS,
	REPORT_PATH,
	REQUIREMENTS,
	STATUS,
	STEPS,
	USAGE,
	buildReport,
	ciRunTokens,
	evaluateRequirements,
	findCiStep,
	formatDuration,
	formatSummary,
	parseArgs,
	parsePinnedTarball,
	referencedSecrets,
	resolveCiStep,
	selectExtraSuites,
	selectSteps,
	summarize,
	TOOL_SOURCES,
	blockingDependency,
	versionAtLeast,
} from "./lib/ci-local-plan.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const localDir = path.join(root, LOCAL_DIR);
const toolsDir = path.join(localDir, "tools");
const toolsBin = path.join(toolsDir, "bin");
const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, text) => (color ? `\u001b[${code}m${text}\u001b[0m` : text);
const bold = (text) => paint("1", text);
const statusColor = { PASS: "32", FAIL: "31", SKIPPED: "33", "NOT RUN": "90" };

function sh(command, args, options = {}) {
	const result = spawnSync(command, args, { cwd: root, encoding: "utf8", timeout: 30_000, ...options });
	return { ok: result.status === 0 && !result.error, stdout: (result.stdout ?? "").trim(), stderr: (result.stderr ?? "").trim(), status: result.status };
}

function isExecutable(file) {
	try {
		accessSync(file, constants.X_OK);
		return true;
	} catch {
		return false;
	}
}

function onPath(name) {
	for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
		if (dir && isExecutable(path.join(dir, name))) return path.join(dir, name);
	}
	return null;
}

function loadWorkflow() {
	let yaml;
	try {
		yaml = createRequire(path.join(root, "packages/core/package.json"))("yaml");
	} catch {
		throw new Error("the yaml package is not installed - run `pnpm install` first");
	}
	const document = yaml.parseDocument(readFileSync(path.join(root, CI_WORKFLOW_PATH), "utf8"), { uniqueKeys: true });
	if (document.errors.length > 0) throw new Error(`${CI_WORKFLOW_PATH} does not parse: ${document.errors.map(String).join("; ")}`);
	return document.toJS();
}

// ─── command resolution ───────────────────────────────────────────────────

function onpremExtraCommand(workflow, rootScripts) {
	let covered = "";
	for (const entry of STEPS.filter((candidate) => candidate.group === "onprem" && candidate.ci)) {
		const ciStep = findCiStep(workflow, ...entry.ci);
		covered += `\n${ciStep?.run ?? ""}`;
		for (const token of ciRunTokens(ciStep?.run ?? "")) {
			if (token.startsWith("pnpm ")) covered += `\n${rootScripts[token.slice(5)] ?? ""}`;
		}
	}
	const files = selectExtraSuites(readdirSync(path.join(root, "scripts")), ONPREM_EXTRA_SUITE_PATTERNS, covered);
	return files.length > 0 ? `node --test ${files.join(" ")}` : "true # no extra on-prem suites";
}

function resolveCommand(entry, workflow, rootScripts) {
	if (entry.ci) {
		const secrets = {};
		for (const name of referencedSecrets(findCiStep(workflow, ...entry.ci))) secrets[name] = process.env[name] ?? "";
		const resolved = resolveCiStep(workflow, entry.ci, { secrets });
		return { ...resolved, display: `ci.yml ${entry.ci[0]} / "${entry.ci[1]}" (literal run: block)` };
	}
	if (entry.expand === "onprem-extra") {
		const run = onpremExtraCommand(workflow, rootScripts);
		return { run, env: {}, workingDirectory: null, display: run };
	}
	if (entry.internal) return { run: null, env: {}, workingDirectory: null, display: entry.display };
	return { run: entry.run, env: {}, workingDirectory: null, display: entry.run };
}

// ─── host facts ───────────────────────────────────────────────────────────

const TOOL_ENV = { helm: "HELM_BIN", gitleaks: "GITLEAKS_BIN", promtool: "PROMTOOL_BIN", actionlint: "ACTIONLINT_BIN" };

function findTool(name) {
	const fromEnv = process.env[TOOL_ENV[name]];
	if (fromEnv) return isExecutable(fromEnv) ? { path: path.resolve(fromEnv) } : { detail: `${TOOL_ENV[name]}=${fromEnv} is not executable` };
	const cached = path.join(toolsBin, name);
	if (isExecutable(cached)) return { path: cached };
	const found = onPath(name);
	return found ? { path: found } : { detail: `${name} not on PATH, ${TOOL_ENV[name]} unset, nothing in ${LOCAL_DIR}/tools/bin` };
}

function nodeVersionOf(binary) {
	const result = sh(binary, ["--version"], { timeout: 10_000 });
	return result.ok ? result.stdout.replace(/^v/u, "") : null;
}

function nodeDistName(version) {
	const os = process.platform === "darwin" ? "darwin" : process.platform === "linux" ? "linux" : null;
	const arch = process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : null;
	return os && arch ? `node-v${version}-${os}-${arch}` : null;
}

function findNode24(pinned) {
	if (process.versions.node.startsWith("24.")) return { path: process.execPath, version: process.versions.node };
	const candidates = [];
	if (process.env.AIDR_NODE24_BIN) candidates.push(process.env.AIDR_NODE24_BIN);
	const dist = nodeDistName(pinned);
	if (dist) candidates.push(path.join(toolsDir, dist, "bin", "node"));
	candidates.push("/opt/node24/bin/node");
	for (const nvmRoot of [process.env.NVM_DIR, path.join(homedir(), ".nvm"), "/opt/nvm", "/usr/local/nvm"].filter(Boolean)) {
		const versions = path.join(nvmRoot, "versions", "node");
		if (!existsSync(versions)) continue;
		for (const name of readdirSync(versions).filter((entry) => entry.startsWith("v24.")).sort().reverse()) candidates.push(path.join(versions, name, "bin", "node"));
	}
	const onPathNode24 = onPath("node24");
	if (onPathNode24) candidates.push(onPathNode24);
	for (const candidate of candidates) {
		if (!isExecutable(candidate)) continue;
		const version = nodeVersionOf(candidate);
		if (version?.startsWith("24.")) return { path: candidate, version };
	}
	return { detail: `current Node is v${process.versions.node}; no Node 24 found via AIDR_NODE24_BIN, ${LOCAL_DIR}/tools, /opt/node24 or nvm` };
}

function findPython312() {
	const candidates = [process.env.AIDR_PYTHON312_BIN, onPath("python3.12"), onPath("python3"), onPath("python")].filter(Boolean);
	for (const candidate of candidates) {
		const probe = sh(candidate, ["-c", "import sys, venv; print('%d.%d.%d' % sys.version_info[:3])"], { timeout: 10_000 });
		if (probe.ok && probe.stdout.startsWith("3.12.")) return { path: candidate, version: probe.stdout };
	}
	return { detail: `no Python 3.12 with the venv module (checked ${candidates.join(", ") || "python3.12, python3"})` };
}

function findChromium() {
	let revision;
	try {
		// browsers.json is not in playwright-core's package exports; resolve it next to package.json.
		const manifest = createRequire(path.join(root, "packages/browser-guard/package.json")).resolve("playwright-core/package.json");
		const browsersJson = path.join(path.dirname(manifest), "browsers.json");
		revision = JSON.parse(readFileSync(browsersJson, "utf8")).browsers.find((browser) => browser.name === "chromium")?.revision;
	} catch {
		return { detail: "playwright-core is not installed for packages/browser-guard (run pnpm install)" };
	}
	const roots = [process.env.PLAYWRIGHT_BROWSERS_PATH, "/opt/pw-browsers", path.join(homedir(), ".cache", "ms-playwright")].filter(Boolean);
	for (const dir of roots) {
		if (existsSync(path.join(dir, `chromium-${revision}`))) return { path: dir, revision };
	}
	return { detail: `chromium-${revision} not found in ${roots.join(", ")}` };
}

function probeFacts(selected, workflow) {
	const needed = new Set(selected.flatMap((entry) => entry.requires ?? []));
	if (selected.some((entry) => entry.nodeLeg === "prefer-24")) needed.add("node24");
	const available = {};
	const detail = {};
	const found = {};
	const record = (key, result, describe = (value) => value.path) => {
		available[key] = Boolean(result.path);
		detail[key] = result.path ? describe(result) : result.detail;
		if (result.path) found[key] = result;
	};

	if (needed.has("docker-cli") || needed.has("docker-daemon")) {
		const cli = onPath("docker");
		const compose = cli ? sh("docker", ["compose", "version", "--short"], { timeout: 20_000 }) : null;
		available["docker-cli"] = Boolean(compose?.ok);
		detail["docker-cli"] = !cli ? "docker not on PATH" : compose.ok ? `compose ${compose.stdout}` : "`docker compose version` failed";
		const info = cli ? sh("docker", ["info", "--format", "{{.ServerVersion}}"], { timeout: 30_000 }) : null;
		available["docker-daemon"] = Boolean(info?.ok && info.stdout);
		detail["docker-daemon"] = !cli ? "docker not on PATH" : info.ok ? `server ${info.stdout}` : (info.stderr.split("\n").find(Boolean) ?? "`docker info` failed").slice(0, 200);
	}
	if (needed.has("network")) {
		const probe = onPath("curl") ? sh("curl", ["-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", "https://registry.npmjs.org/"], { timeout: 20_000 }) : null;
		available.network = Boolean(probe?.ok && probe.stdout !== "000");
		detail.network = !probe ? "curl not on PATH" : available.network ? `HTTP ${probe.stdout}` : (probe.stderr || "no response").slice(0, 200);
	}
	for (const tool of ["helm", "gitleaks", "promtool", "actionlint"]) if (needed.has(tool)) record(tool, findTool(tool));
	if (needed.has("node24")) record("node24", findNode24(workflow.env.NODE_24_VERSION), (value) => `v${value.version} at ${value.path}`);
	if (needed.has("node-privacy-floor")) {
		available["node-privacy-floor"] = versionAtLeast(process.versions.node, String(workflow.env.PRIVACY_NODE_VERSION));
		detail["node-privacy-floor"] = `current v${process.versions.node}, floor ${workflow.env.PRIVACY_NODE_VERSION}`;
	}
	if (needed.has("non-root")) {
		const uid = process.getuid?.();
		available["non-root"] = uid !== 0;
		detail["non-root"] = uid === undefined ? "no POSIX uid" : `uid ${uid}`;
	}
	if (needed.has("pwsh")) {
		const pwsh = onPath("pwsh");
		record("pwsh", pwsh ? { path: pwsh } : { detail: "pwsh not on PATH" });
	}
	if (needed.has("python312")) record("python312", findPython312(), (value) => `${value.version} at ${value.path}`);
	if (needed.has("chromium")) record("chromium", findChromium(), (value) => `chromium-${value.revision} in ${value.path}`);
	for (const entry of selected) {
		if (entry.requires?.includes("ci-secrets")) {
			const missing = referencedSecrets(findCiStep(workflow, ...entry.ci)).filter((name) => !process.env[name]);
			available[`ci-secrets:${entry.id}`] = missing.length === 0;
			detail[`ci-secrets:${entry.id}`] = missing.length > 0 ? `unset: ${missing.join(", ")}` : "all set";
		}
		if (entry.requires?.includes("release-candidate")) {
			available[`release-candidate:${entry.id}`] = existsSync(path.join(root, entry.requiresFile));
			detail[`release-candidate:${entry.id}`] = `${entry.requiresFile} is missing`;
		}
	}
	return { available, detail, found };
}

// ─── tool provisioning (--fetch-tools) ────────────────────────────────────

function sha256File(file) {
	return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function curlDownload(url, destination) {
	const result = spawnSync("curl", ["--fail", "--location", "--proto", "=https", "--tlsv1.2", "--silent", "--show-error", "--output", destination, url], { stdio: ["ignore", "inherit", "inherit"], timeout: 10 * 60_000 });
	if (result.status !== 0) throw new Error(`download failed: ${url}`);
}

function fetchPinnedTarball(name, workflow) {
	if (process.platform !== "linux" || process.arch !== "x64") throw new Error(`ci.yml pins the linux x64 ${name} build; install ${name} for ${process.platform}/${process.arch} yourself`);
	const pin = parsePinnedTarball(findCiStep(workflow, ...TOOL_SOURCES[name]).run);
	const downloads = path.join(toolsDir, "downloads");
	mkdirSync(downloads, { recursive: true });
	const archive = path.join(downloads, path.basename(new URL(pin.url).pathname));
	curlDownload(pin.url, archive);
	const digest = sha256File(archive);
	if (digest !== pin.sha256) {
		rmSync(archive, { force: true });
		throw new Error(`${name} checksum mismatch: expected ${pin.sha256} (ci.yml), got ${digest}`);
	}
	const staging = path.join(downloads, `${name}-extract`);
	rmSync(staging, { recursive: true, force: true });
	mkdirSync(staging, { recursive: true });
	const args = ["-xzf", archive, "-C", staging, ...(pin.strip ? [`--strip-components=${pin.strip}`] : []), pin.member];
	if (spawnSync("tar", args, { stdio: "inherit" }).status !== 0) throw new Error(`could not extract ${pin.member} from ${archive}`);
	mkdirSync(toolsBin, { recursive: true });
	copyFileSync(path.join(staging, path.basename(pin.member)), path.join(toolsBin, name));
	chmodSync(path.join(toolsBin, name), 0o755);
	rmSync(staging, { recursive: true, force: true });
	console.log(`  ${name}: ${pin.url} (sha256 ${pin.sha256.slice(0, 12)}... verified) -> ${path.relative(root, path.join(toolsBin, name))}`);
}

function fetchHelm(workflow) {
	const installStep = ["helm", "Install Helm 3.19.0 (pinned, signature and checksum verified)"];
	const resolved = resolveCiStep(workflow, installStep);
	const runnerTemp = path.join(toolsDir, "helm-runner");
	rmSync(runnerTemp, { recursive: true, force: true });
	mkdirSync(runnerTemp, { recursive: true });
	const script = path.join(runnerTemp, "install.sh");
	writeFileSync(script, resolved.run);
	console.log("  helm: running the ci.yml install step (signed get.helm.sh release)...");
	const signed = spawnSync("bash", ["--noprofile", "--norc", "-eo", "pipefail", script], {
		cwd: root,
		stdio: "inherit",
		env: { ...process.env, ...resolved.env, RUNNER_TEMP: runnerTemp, GITHUB_PATH: path.join(runnerTemp, "github_path") },
		timeout: 10 * 60_000,
	});
	mkdirSync(toolsBin, { recursive: true });
	if (signed.status === 0 && isExecutable(path.join(runnerTemp, "helm", "helm"))) {
		copyFileSync(path.join(runnerTemp, "helm", "helm"), path.join(toolsBin, "helm"));
		chmodSync(path.join(toolsBin, "helm"), 0o755);
		console.log(`  helm: ${resolved.env.HELM_VERSION} signature and checksum verified -> ${path.relative(root, path.join(toolsBin, "helm"))}`);
		return;
	}
	if (!onPath("go")) throw new Error("the signed Helm download failed and Go is not installed for the source-build fallback");
	console.log(`  helm: signed download unavailable; building ${resolved.env.HELM_VERSION} with go install (module checksums verified against sum.golang.org)...`);
	const built = spawnSync("go", ["install", `helm.sh/helm/v3/cmd/helm@${resolved.env.HELM_VERSION}`], {
		cwd: toolsDir,
		stdio: "inherit",
		env: { ...process.env, GOBIN: toolsBin, CGO_ENABLED: "0", GOSUMDB: "sum.golang.org", GONOSUMDB: "", GONOSUMCHECK: "", GOPRIVATE: "", GOINSECURE: "", GOFLAGS: "-trimpath" },
		timeout: 20 * 60_000,
	});
	if (built.status !== 0 || !isExecutable(path.join(toolsBin, "helm"))) throw new Error("go install of Helm failed");
	console.log(`  helm: built from source -> ${path.relative(root, path.join(toolsBin, "helm"))}`);
}

function fetchNode24(workflow) {
	const version = String(workflow.env.NODE_24_VERSION);
	const dist = nodeDistName(version);
	if (!dist) throw new Error(`no official Node ${version} build for ${process.platform}/${process.arch}`);
	const file = `${dist}.tar.${process.platform === "linux" ? "xz" : "gz"}`;
	const downloads = path.join(toolsDir, "downloads");
	mkdirSync(downloads, { recursive: true });
	curlDownload(`https://nodejs.org/dist/v${version}/SHASUMS256.txt`, path.join(downloads, `node-v${version}-SHASUMS256.txt`));
	const expected = readFileSync(path.join(downloads, `node-v${version}-SHASUMS256.txt`), "utf8")
		.split("\n")
		.map((line) => line.trim().split(/\s+/u))
		.find(([, name]) => name === file)?.[0];
	if (!/^[0-9a-f]{64}$/u.test(expected ?? "")) throw new Error(`SHASUMS256.txt has no entry for ${file}`);
	const archive = path.join(downloads, file);
	curlDownload(`https://nodejs.org/dist/v${version}/${file}`, archive);
	const digest = sha256File(archive);
	if (digest !== expected) throw new Error(`Node ${version} checksum mismatch: expected ${expected}, got ${digest}`);
	if (spawnSync("tar", [process.platform === "linux" ? "-xJf" : "-xzf", archive, "-C", toolsDir], { stdio: "inherit" }).status !== 0) throw new Error(`could not extract ${file}`);
	console.log(`  node24: v${version} (sha256 verified against nodejs.org SHASUMS256.txt) -> ${path.relative(root, path.join(toolsDir, dist))}`);
}

function provisionTools(facts, workflow) {
	const fetchers = {
		gitleaks: () => fetchPinnedTarball("gitleaks", workflow),
		promtool: () => fetchPinnedTarball("promtool", workflow),
		actionlint: () => fetchPinnedTarball("actionlint", workflow),
		helm: () => fetchHelm(workflow),
		node24: () => fetchNode24(workflow),
	};
	const missing = Object.keys(fetchers).filter((name) => name in facts.available && !facts.available[name]);
	if (missing.length === 0) return;
	if (!onPath("curl")) {
		console.log(paint("33", "--fetch-tools: curl is not on PATH; cannot download tools."));
		return;
	}
	console.log(bold(`--fetch-tools: provisioning ${missing.join(", ")} into ${LOCAL_DIR}/tools`));
	for (const name of missing) {
		try {
			fetchers[name]();
		} catch (error) {
			console.log(paint("33", `  ${name}: not provisioned - ${error.message}`));
		}
	}
}

// ─── execution ────────────────────────────────────────────────────────────

function gitSnapshot() {
	const status = sh("git", ["status", "--porcelain=v1", "--untracked-files=all"], { timeout: 120_000 });
	const diff = spawnSync("git", ["diff", "HEAD", "--binary"], { cwd: root, maxBuffer: 1024 * 1024 * 1024, timeout: 120_000 });
	return { status: status.stdout, diffSha256: createHash("sha256").update(diff.stdout ?? "").digest("hex") };
}

const internalSteps = {
	"playwright-pin"(_entry, context) {
		const pinned = JSON.parse(readFileSync(path.join(root, "packages/browser-guard/package.json"), "utf8")).devDependencies?.["playwright-core"];
		if (!/^\d+\.\d+\.\d+$/u.test(pinned ?? "")) return { ok: false, message: `playwright-core must be an exact version pin, found ${pinned}` };
		const installedPath = createRequire(path.join(root, "packages/browser-guard/package.json")).resolve("playwright-core/package.json");
		const installed = JSON.parse(readFileSync(installedPath, "utf8")).version;
		if (installed !== pinned) return { ok: false, message: `Installed playwright-core ${installed} != pinned ${pinned}` };
		return { ok: true, message: `playwright-core ${pinned} pinned and installed; ${context.facts.detail.chromium}` };
	},
	"tree-unchanged"(_entry, context) {
		const messages = [];
		if (context.startedClean) {
			const check = sh("git", ["diff", "--check"], { timeout: 120_000 });
			if (!check.ok) return { ok: false, message: `git diff --check found whitespace errors:\n${check.stdout}` };
		} else messages.push("git diff --check not applied: the tree already had uncommitted changes before the run");
		const after = gitSnapshot();
		if (after.status !== context.snapshot.status || after.diffSha256 !== context.snapshot.diffSha256) {
			const before = new Set(context.snapshot.status.split("\n"));
			const changed = after.status.split("\n").filter((line) => line && !before.has(line));
			return { ok: false, message: `verification or build mutated the working tree:\n${changed.join("\n") || "(contents of already-modified files changed)"}` };
		}
		messages.push("working tree identical to the pre-run snapshot");
		return { ok: true, message: messages.join("; ") };
	},
};

function runBash(script, { cwd, env, timeoutMs, logStream, runnerTemp, tail }) {
	return new Promise((resolvePromise) => {
		const file = path.join(runnerTemp, "step.sh");
		writeFileSync(file, `${script}\n`);
		const child = spawn("bash", ["--noprofile", "--norc", "-eo", "pipefail", file], { cwd, env, stdio: ["ignore", "pipe", "pipe"], detached: process.platform !== "win32" });
		activeChild = child;
		let timedOut = false;
		let partial = "";
		const onData = (target) => (chunk) => {
			target.write(chunk);
			logStream.write(chunk);
			partial += chunk.toString("utf8");
			const lines = partial.split("\n");
			partial = lines.pop() ?? "";
			tail.push(...lines);
			if (tail.length > 40) tail.splice(0, tail.length - 40);
		};
		child.stdout.on("data", onData(process.stdout));
		child.stderr.on("data", onData(process.stderr));
		const kill = (signal) => {
			try {
				process.kill(-child.pid, signal);
			} catch {
				child.kill(signal);
			}
		};
		const timer = setTimeout(() => {
			timedOut = true;
			kill("SIGTERM");
			setTimeout(() => kill("SIGKILL"), 15_000).unref();
		}, timeoutMs);
		child.on("close", (code, signal) => {
			clearTimeout(timer);
			activeChild = null;
			if (partial) tail.push(partial);
			resolvePromise({ exitCode: code ?? (signal ? 128 : 1), timedOut });
		});
		child.on("error", (error) => {
			clearTimeout(timer);
			activeChild = null;
			tail.push(String(error.message));
			resolvePromise({ exitCode: 127, timedOut: false });
		});
	});
}

let activeChild = null;
let interrupted = false;

function prependPath(env, dirs) {
	const key = Object.keys(env).find((name) => name.toUpperCase() === "PATH") ?? "PATH";
	env[key] = [...dirs.filter(Boolean), env[key] ?? ""].join(path.delimiter);
}

function ensureVenv(name, python) {
	const dir = path.join(localDir, "venv", name);
	if (!isExecutable(path.join(dir, "bin", "python"))) {
		console.log(`creating ${path.relative(root, dir)} with ${python}`);
		const created = spawnSync(python, ["-m", "venv", dir], { stdio: "inherit" });
		if (created.status !== 0) throw new Error(`could not create the ${name} virtualenv`);
	}
	return dir;
}

async function runStep(entry, index, total, context) {
	const resolved = context.commands.get(entry.id);
	const base = { id: entry.id, group: entry.group, name: entry.name, required: entry.required, command: resolved.display };
	const heading = `[${index + 1}/${total}] ${entry.group} > ${entry.name}`;

	const gate = evaluateRequirements(entry, context.facts);
	if (!gate.ok) {
		console.log(`\n${paint("33", "--- SKIPPED")} ${heading}\n    ${gate.reason}\n    fix: ${gate.fix}`);
		return { ...base, status: STATUS.SKIPPED, reason: gate.reason, fix: gate.fix, durationMs: 0 };
	}
	if (entry.dirtySensitive && context.dirty && context.options.allowDirty) {
		const reason = "--allow-dirty: the working tree has uncommitted changes and CI requires a clean checkout";
		console.log(`\n${paint("33", "--- SKIPPED")} ${heading}\n    ${reason}`);
		return { ...base, status: STATUS.SKIPPED, reason, fix: "commit or stash, then rerun without --allow-dirty", durationMs: 0 };
	}

	console.log(`\n${bold(`==> ${heading}`)}  (${entry.id}, timeout ${formatDuration(entry.timeoutMs)})\n    ${resolved.display}`);
	const started = Date.now();
	const logPath = path.join(localDir, "logs", `${String(index + 1).padStart(2, "0")}-${entry.id}.log`);
	const logStream = createWriteStream(logPath);
	const tail = [];
	const notes = [];
	let outcome;
	try {
		if (entry.internal) {
			const result = internalSteps[entry.internal](entry, context);
			console.log(result.message);
			logStream.write(`${result.message}\n`);
			tail.push(...result.message.split("\n"));
			outcome = { exitCode: result.ok ? 0 : 1, timedOut: false };
		} else {
			const runnerTemp = path.join(localDir, "runner-temp", entry.id);
			rmSync(runnerTemp, { recursive: true, force: true });
			mkdirSync(runnerTemp, { recursive: true });
			const env = { ...process.env, ...resolved.env, ...(entry.env ?? {}), AIDR_CI_LOCAL: "1", RUNNER_TEMP: runnerTemp, GITHUB_ENV: path.join(runnerTemp, "github_env"), GITHUB_PATH: path.join(runnerTemp, "github_path"), GITHUB_WORKSPACE: root };
			const pathDirs = [toolsBin];
			for (const [tool, variable] of Object.entries(TOOL_ENV)) {
				const found = context.facts.found[tool];
				if (found) {
					env[variable] = found.path;
					pathDirs.push(path.dirname(found.path));
				}
			}
			if (context.facts.found.chromium) env.PLAYWRIGHT_BROWSERS_PATH = context.facts.found.chromium.path;
			const node24 = context.facts.found.node24;
			const pins = context.workflow.env;
			if (entry.nodeLeg === "24" || (entry.nodeLeg === "prefer-24" && node24)) {
				pathDirs.unshift(path.dirname(node24.path));
				notes.push(`Node v${node24.version} (CI pins ${pins.NODE_24_VERSION})`);
			} else if (entry.nodeLeg === "prefer-24") {
				const warning = `WARNING: ran on Node v${process.versions.node}; CI runs this job on ${pins.NODE_24_VERSION} (${context.facts.detail.node24})`;
				console.log(paint("33", warning));
				notes.push(warning);
			} else if (entry.nodeLeg === "current") {
				notes.push(`Node v${process.versions.node} (CI pins ${pins.NODE_VERSION})`);
			}
			if (entry.venv) {
				const venv = ensureVenv(entry.venv, context.facts.found.python312.path);
				env.VIRTUAL_ENV = venv;
				pathDirs.unshift(path.join(venv, "bin"));
			}
			prependPath(env, pathDirs);
			const cwd = resolved.workingDirectory ? path.join(root, resolved.workingDirectory) : root;
			outcome = await runBash(resolved.run, { cwd, env, timeoutMs: entry.timeoutMs, logStream, runnerTemp, tail });
			if (entry.cleanup) {
				const cleanup = resolveCiStep(context.workflow, entry.cleanup);
				console.log(bold(`    cleanup: ci.yml ${entry.cleanup[0]} / "${entry.cleanup[1]}"`));
				const cleaned = await runBash(cleanup.run, { cwd, env: { ...env, ...cleanup.env }, timeoutMs: 5 * 60_000, logStream, runnerTemp, tail: [] });
				if (cleaned.exitCode !== 0) {
					notes.push(`cleanup "${entry.cleanup[1]}" exited ${cleaned.exitCode}`);
					if (outcome.exitCode === 0) outcome = { ...outcome, exitCode: cleaned.exitCode };
				}
			}
		}
	} catch (error) {
		tail.push(String(error.message));
		console.log(paint("31", String(error.message)));
		outcome = { exitCode: 1, timedOut: false };
	} finally {
		await new Promise((done) => logStream.end(done));
	}

	const durationMs = Date.now() - started;
	const passed = outcome.exitCode === 0 && !outcome.timedOut;
	if (!passed) {
		notes.unshift(outcome.timedOut ? `timed out after ${formatDuration(entry.timeoutMs)}` : `exit ${outcome.exitCode}`);
		if (entry.dirtySensitive && context.dirty) notes.push("the tree has uncommitted changes: commit/stash or pass --allow-dirty");
	}
	const status = passed ? STATUS.PASS : STATUS.FAIL;
	const label = status === STATUS.FAIL && !entry.required ? "FAIL (advisory)" : status;
	console.log(`${paint(statusColor[status], `<== ${label}`)} ${entry.id} in ${formatDuration(durationMs)}${notes.length ? ` - ${notes.join("; ")}` : ""}`);
	return {
		...base,
		status,
		durationMs,
		exitCode: outcome.exitCode,
		timedOut: outcome.timedOut,
		note: notes.join("; ") || null,
		log: path.relative(root, logPath),
		outputTail: passed ? null : tail.slice(-40).join("\n"),
	};
}

function printList(workflow, rootScripts, options) {
	const { selected } = selectSteps(STEPS, options);
	const chosen = new Set(selected.map((entry) => entry.id));
	console.log(USAGE);
	for (const [group, description] of GROUPS) {
		console.log(`\n${bold(group)} - ${description}`);
		for (const entry of STEPS.filter((candidate) => candidate.group === group)) {
			const flags = [chosen.has(entry.id) ? "selected" : "not selected", entry.quick ? "quick" : null, entry.optIn ? "opt-in" : null, entry.required ? null : "advisory", entry.phase ? `runs ${entry.phase === "pre" ? "first" : "last"}` : null].filter(Boolean);
			console.log(`  ${entry.id}  ${entry.name}  [${flags.join(", ")}]  timeout ${formatDuration(entry.timeoutMs)}`);
			const requires = [...(entry.requires ?? []), ...(entry.nodeLeg === "prefer-24" ? ["node24 (preferred; falls back to current Node with a warning)"] : [])];
			if (requires.length > 0) console.log(`      requires: ${requires.map((name) => (REQUIREMENTS[name] ? `${name} (${REQUIREMENTS[name].label})` : name)).join("; ")}`);
			console.log(`      $ ${resolveCommand(entry, workflow, rootScripts).display.split("\n")[0]}`);
		}
	}
}

async function main() {
	let options;
	try {
		options = parseArgs(process.argv.slice(2));
	} catch (error) {
		console.error(`ci:local: ${error.message}\n\n${USAGE}`);
		return 2;
	}
	if (options.help) {
		console.log(USAGE);
		return 0;
	}
	const workflow = loadWorkflow();
	const rootScripts = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).scripts;
	let selection;
	try {
		selection = selectSteps(STEPS, options);
	} catch (error) {
		console.error(`ci:local: ${error.message}`);
		return 2;
	}
	if (options.list) {
		printList(workflow, rootScripts, options);
		return 0;
	}
	if (!onPath("bash")) {
		console.error("ci:local needs bash (Linux, macOS, WSL or Git Bash).");
		return 2;
	}

	mkdirSync(path.join(localDir, "logs"), { recursive: true });
	for (const stale of readdirSync(path.join(localDir, "logs"))) rmSync(path.join(localDir, "logs", stale), { force: true });
	const { selected, notSelected } = selection;
	const commands = new Map(selected.map((entry) => [entry.id, resolveCommand(entry, workflow, rootScripts)]));
	let facts = probeFacts(selected, workflow);
	if (options.fetchTools) {
		provisionTools(facts, workflow);
		facts = probeFacts(selected, workflow);
	}
	const startStatus = sh("git", ["status", "--porcelain=v1", "--untracked-files=all"], { timeout: 120_000 });
	const dirty = startStatus.stdout.length > 0;
	const head = sh("git", ["rev-parse", "HEAD"]).stdout;
	const context = { options, workflow, facts, commands, dirty, startedClean: !dirty, snapshot: selected.some((entry) => entry.internal === "tree-unchanged") ? gitSnapshot() : null };

	console.log(bold(`ci:local - ${selected.length} step(s) mirroring ${CI_WORKFLOW_PATH}`));
	console.log(`  Node v${process.versions.node} (ci.yml: ${workflow.env.NODE_VERSION}; Node 24 leg ${workflow.env.NODE_24_VERSION}; privacy floor ${workflow.env.PRIVACY_NODE_VERSION})`);
	console.log(`  HEAD ${head}${dirty ? " + uncommitted changes" : " (clean)"}; logs in ${LOCAL_DIR}/logs`);
	for (const [key, value] of Object.entries(facts.detail)) console.log(`  ${facts.available[key] ? "found  " : paint("33", "MISSING")} ${key}: ${value}`);
	if (facts.available.node24 === false) {
		console.log(paint("33", `WARNING: Node 24 is not available - the core-node24 matrix leg will be SKIPPED and on-prem steps run on Node v${process.versions.node}. ${REQUIREMENTS.node24.fix}`));
	}

	const onSignal = () => {
		interrupted = true;
		if (activeChild) {
			try {
				process.kill(-activeChild.pid, "SIGTERM");
			} catch {
				activeChild.kill("SIGTERM");
			}
		}
	};
	process.on("SIGINT", onSignal);
	process.on("SIGTERM", onSignal);

	const startedAt = new Date().toISOString();
	const results = [];
	let stopped = false;
	for (const [index, entry] of selected.entries()) {
		const post = entry.phase === "post";
		if (interrupted || (stopped && !post)) {
			results.push({ id: entry.id, group: entry.group, name: entry.name, required: entry.required, status: STATUS.NOT_RUN, durationMs: 0, command: commands.get(entry.id).display, note: interrupted ? "interrupted" : "stopped after a required failure" });
			continue;
		}
		const blocker = blockingDependency(entry, results);
		if (blocker) {
			console.log(`\n${paint("90", "--- NOT RUN")} [${index + 1}/${selected.length}] ${entry.group} > ${entry.name}\n    ${blocker} did not complete, and this step consumes its output`);
			results.push({ id: entry.id, group: entry.group, name: entry.name, required: entry.required, status: STATUS.NOT_RUN, durationMs: 0, command: commands.get(entry.id).display, note: `blocked: ${blocker} did not complete`, blockedBy: blocker });
			continue;
		}
		const result = await runStep(entry, index, selected.length, context);
		results.push(result);
		if (result.status === STATUS.FAIL && result.required && !options.keepGoing) stopped = true;
	}

	const finishedAt = new Date().toISOString();
	console.log(`\n${bold("ci:local summary")} (${formatDuration(Date.parse(finishedAt) - Date.parse(startedAt))})\n`);
	console.log(formatSummary(results, { notSelected, strict: options.strict, interrupted }));
	const report = buildReport(results, {
		startedAt,
		finishedAt,
		options,
		notSelected,
		strict: options.strict,
		interrupted,
		environment: { node: process.version, platform: process.platform, arch: process.arch, head, dirty, facts: { available: facts.available, detail: facts.detail } },
	});
	const json = `${JSON.stringify(report, null, 2)}\n`;
	writeFileSync(path.join(root, REPORT_PATH), json);
	if (options.json && path.resolve(root, options.json) !== path.join(root, REPORT_PATH)) {
		mkdirSync(path.dirname(path.resolve(root, options.json)), { recursive: true });
		writeFileSync(path.resolve(root, options.json), json);
	}
	console.log(`\nReport: ${REPORT_PATH}${options.json && path.resolve(root, options.json) !== path.join(root, REPORT_PATH) ? ` and ${options.json}` : ""}`);
	return summarize(results, { strict: options.strict, interrupted }).exitCode;
}

main().then(
	(code) => {
		process.exitCode = code;
	},
	(error) => {
		console.error(`ci:local: ${error.stack ?? error.message}`);
		process.exitCode = 2;
	},
);
