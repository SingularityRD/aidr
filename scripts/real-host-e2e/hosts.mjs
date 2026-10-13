/**
 * Host adapters for the real-host E2E tier.
 *
 * Each adapter knows how to find (or install, pinned, into a private prefix) one
 * real host program, how to install AIDR into it from this checkout's built
 * artefacts inside a disposable HOME, how to point it at the scripted mock model
 * and how to run one non-interactive turn. Nothing here touches the operator's
 * own HOME or any global prefix.
 *
 * AIDR install modes a scenario can ask for:
 *
 *   - "installed": AIDR registered exactly as the connector README documents.
 *   - "absent":    the same host configuration with AIDR not registered. Used as
 *                  the attribution control: the scripted call must then run, or a
 *                  block in "installed" mode could be the host's own doing.
 *   - "crash":     (command-hook hosts only) the hook command is replaced by
 *                  scripts/real-host-e2e/crash-hook.mjs, which is SIGKILLed after
 *                  reading its payload, to observe the host's crashed-hook policy.
 */
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { embeddedBuildFlavors } from "../lib/release-minify.mjs";

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const CRASH_HOOK = path.join(REPO_ROOT, "scripts", "real-host-e2e", "crash-hook.mjs");

/** Pinned host versions. Codex matches the version packages/codex/README.md was verified against. */
export const HOST_PINS = Object.freeze({
	"claude-code": { npm: "@anthropic-ai/claude-code", version: "2.1.282", envOverride: "AIDR_CLAUDE_PATH" },
	codex: { npm: "@openai/codex", version: "0.141.0", envOverride: "AIDR_CODEX_PATH" },
	opencode: { npm: "opencode-ai", version: "1.18.32", envOverride: "AIDR_OPENCODE_PATH" },
	openclaw: { npm: "openclaw", version: "2026.9.6", envOverride: "AIDR_OPENCLAW_ROOT", node: "24.21.0" },
});

export const HOST_IDS = Object.keys(HOST_PINS);

/** Minimal child environment: no proxy, no credentials, no operator HOME. */
function baseEnv(sandbox, extraPath = []) {
	const pathEntries = [...extraPath, path.dirname(process.execPath), "/usr/local/bin", "/usr/bin", "/bin"];
	return {
		PATH: [...new Set(pathEntries)].join(path.delimiter),
		HOME: sandbox.home,
		USERPROFILE: sandbox.home,
		TMPDIR: sandbox.tmp,
		LANG: "C.UTF-8",
		NO_COLOR: "1",
		CI: "1",
	};
}

/** Receipt contract from packages/core/src/host-observation.ts: proves the connector handled the call. */
function observationEnv(sandbox) {
	return {
		AIDR_NATIVE_TEST_RECEIPT: sandbox.receipt,
		AIDR_NATIVE_TEST_CASE_NONCE: sandbox.nonce,
		AIDR_NATIVE_TEST_WORKSPACE: sandbox.ws,
		AIDR_REAL_HOST_CRASH_PROOF: sandbox.crashProof,
	};
}

function runProcess(command, args, { cwd, env, timeoutMs }) {
	return new Promise((resolve) => {
		const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		child.stdout.on("data", (chunk) => {
			stdout += chunk;
		});
		child.stderr.on("data", (chunk) => {
			stderr += chunk;
		});
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGKILL");
		}, timeoutMs);
		child.on("error", (error) => {
			clearTimeout(timer);
			resolve({ status: null, signal: null, stdout, stderr: `${stderr}\n${error.message}`, timedOut });
		});
		child.on("close", (status, signal) => {
			clearTimeout(timer);
			resolve({ status, signal, stdout, stderr, timedOut });
		});
	});
}

function versionOf(command, args, env) {
	const result = spawnSync(command, args, { encoding: "utf8", env, timeout: 60_000 });
	const text = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim().split(/\r?\n/u).filter(Boolean).at(-1);
	return result.status === 0 && text ? text : null;
}

/**
 * Install a pinned host package with lifecycle scripts disabled. `postinstall`
 * names the one package whose own postinstall is then run explicitly (OpenCode
 * links its platform binary there), so no other dependency's script ever runs.
 */
function npmInstall(prefix, spec, postinstall = null) {
	mkdirSync(prefix, { recursive: true });
	const result = spawnSync("npm", ["install", "--prefix", prefix, "--no-audit", "--no-fund", "--ignore-scripts", spec], {
		encoding: "utf8",
		timeout: 900_000,
		env: process.env,
	});
	if (result.status !== 0) {
		throw new Error(`npm install ${spec} failed: ${(result.stderr || result.stdout || "").slice(-2000)}`);
	}
	if (postinstall) {
		const packageDir = path.join(prefix, "node_modules", postinstall);
		const script = JSON.parse(readFileSync(path.join(packageDir, "package.json"), "utf8")).scripts?.postinstall;
		if (script !== "node ./postinstall.mjs") throw new Error(`${postinstall} postinstall changed (${script}); review it before running`);
		const run = spawnSync(process.execPath, ["./postinstall.mjs"], { cwd: packageDir, encoding: "utf8", timeout: 120_000 });
		if (run.status !== 0) throw new Error(`${postinstall} postinstall failed: ${(run.stderr || run.stdout || "").slice(-2000)}`);
	}
}

/**
 * A host whose npm package ships a `<name>` bin: the override path, else the
 * pinned local install (installed on demand when `install` is set). The package's
 * own postinstall runs only when `runPostinstall` is set, after npmInstall checks it.
 */
function resolveNpmHost(hostsDir, install, name, { runPostinstall }) {
	const pin = HOST_PINS[name];
	const local = path.join(hostsDir, name, "node_modules", ".bin", name);
	let binary = [process.env[pin.envOverride], local].filter(Boolean).find((candidate) => existsSync(candidate));
	if (!binary && install) {
		npmInstall(path.join(hostsDir, name), `${pin.npm}@${pin.version}`, runPostinstall ? pin.npm : null);
		binary = local;
	}
	if (!binary || !existsSync(binary)) return null;
	return { binary, version: versionOf(binary, ["--version"], process.env), pinnedVersion: pin.version };
}

/** Download and sha256-verify an official Node.js build (OpenClaw needs Node >= 24.16). */
async function installNode(version, hostsDir) {
	const platform = process.platform === "darwin" ? "darwin" : process.platform === "linux" ? "linux" : null;
	const arch = process.arch === "x64" || process.arch === "arm64" ? process.arch : null;
	if (!platform || !arch) throw new Error(`no pinned Node.js ${version} build for ${process.platform}/${process.arch}`);
	const name = `node-v${version}-${platform}-${arch}`;
	const target = path.join(hostsDir, name, "bin", "node");
	if (existsSync(target)) return target;
	const base = `https://nodejs.org/dist/v${version}`;
	const sums = await (await fetch(`${base}/SHASUMS256.txt`)).text();
	const expected = sums.split(/\r?\n/u).find((line) => line.endsWith(`  ${name}.tar.xz`))?.split(/\s+/u)[0];
	if (!expected) throw new Error(`SHASUMS256.txt for Node.js ${version} does not list ${name}.tar.xz`);
	const archive = Buffer.from(await (await fetch(`${base}/${name}.tar.xz`)).arrayBuffer());
	const actual = createHash("sha256").update(archive).digest("hex");
	if (actual !== expected) throw new Error(`Node.js ${version} archive sha256 mismatch (${actual} != ${expected})`);
	mkdirSync(hostsDir, { recursive: true });
	const archivePath = path.join(hostsDir, `${name}.tar.xz`);
	writeFileSync(archivePath, archive);
	const untar = spawnSync("tar", ["-xJf", archivePath, "-C", hostsDir], { encoding: "utf8" });
	if (untar.status !== 0) throw new Error(`could not unpack ${archivePath}: ${untar.stderr}`);
	return target;
}

function nodeMajorMinor(nodePath) {
	const version = versionOf(nodePath, ["--version"], process.env) ?? "";
	const match = /^v(\d+)\.(\d+)/u.exec(version);
	return match ? [Number(match[1]), Number(match[2])] : [0, 0];
}

function onPath(name) {
	const result = spawnSync("sh", ["-c", `command -v ${name}`], { encoding: "utf8" });
	return result.status === 0 ? result.stdout.trim() : null;
}

// ── Claude Code ─────────────────────────────────────────────────────────────

const claudeCode = {
	id: "claude-code",
	hostName: "Claude Code",
	protocol: "anthropic-messages",
	canaryTool: "read",
	supportsCrashProbe: true,
	supportsOutputInspection: true,
	toolDeadlineEnv: "AIDR_PRE_TOOL_USE_DEADLINE_MS",
	async resolve({ hostsDir }) {
		const pin = HOST_PINS["claude-code"];
		const candidates = [
			process.env[pin.envOverride],
			path.join(hostsDir, "claude-code", "node_modules", ".bin", "claude"),
			onPath("claude"),
		].filter(Boolean);
		const binary = candidates.find((candidate) => existsSync(candidate));
		// The Claude Code npm package fetches its native binary in a postinstall
		// step; it is not installed here. Provide it on PATH or via AIDR_CLAUDE_PATH.
		if (!binary) return null;
		return { binary, version: versionOf(binary, ["--version"], process.env), pinnedVersion: pin.version };
	},
	prepare(sandbox, mode) {
		if (mode === "crash") {
			const pluginDir = path.join(sandbox.root, "crash-plugin");
			mkdirSync(path.join(pluginDir, ".claude-plugin"), { recursive: true });
			mkdirSync(path.join(pluginDir, "hooks"), { recursive: true });
			writeFileSync(path.join(pluginDir, ".claude-plugin", "plugin.json"), `${JSON.stringify({ name: "aidr-crash-probe", version: "0.0.0" })}\n`);
			writeFileSync(
				path.join(pluginDir, "hooks", "hooks.json"),
				`${JSON.stringify({ hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: `node "${CRASH_HOOK}"`, timeout: 15 }] }] } }, null, 2)}\n`,
			);
			return { pluginDir };
		}
		// The repository root is the Claude Code plugin layout (.claude-plugin/ + hooks/hooks.json).
		return { pluginDir: mode === "installed" ? REPO_ROOT : null };
	},
	run(host, sandbox, prepared, { prompt, mockUrl, env, timeoutMs }) {
		const args = [
			"-p",
			prompt,
			"--output-format",
			"stream-json",
			"--verbose",
			"--max-turns",
			"3",
			"--model",
			"claude-sonnet-4-5",
			"--allowedTools",
			"Bash,Read",
		];
		if (prepared.pluginDir) args.push("--plugin-dir", prepared.pluginDir);
		return runProcess(host.binary, args, {
			cwd: sandbox.ws,
			timeoutMs,
			env: {
				...baseEnv(sandbox),
				...observationEnv(sandbox),
				ANTHROPIC_BASE_URL: mockUrl,
				ANTHROPIC_API_KEY: "sk-ant-aidr-real-host-e2e-not-a-key",
				CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
				DISABLE_AUTOUPDATER: "1",
				DISABLE_TELEMETRY: "1",
				...env,
			},
		});
	},
};

// ── Codex ───────────────────────────────────────────────────────────────────

const codex = {
	id: "codex",
	hostName: "Codex CLI",
	protocol: "openai-responses",
	canaryTool: "shell",
	supportsCrashProbe: true,
	supportsOutputInspection: false,
	async resolve({ hostsDir, install }) {
		return resolveNpmHost(hostsDir, install, "codex", { runPostinstall: false });
	},
	prepare(sandbox, mode, { mockUrl }) {
		const codexHome = path.join(sandbox.home, ".codex");
		mkdirSync(codexHome, { recursive: true });
		const hook = path.join(REPO_ROOT, "packages", "codex", "dist", "pre-tool-use.cjs");
		const command = mode === "crash" ? `node "${CRASH_HOOK}"` : `node "${hook}"`;
		if (mode !== "absent") {
			// PascalCase event names and the shipped matcher, as packages/codex/README.md documents.
			const hooks = {
				PreToolUse: [{ matcher: "^(Bash|apply_patch|mcp__.+)$", hooks: [{ type: "command", command, timeout: 10 }] }],
			};
			if (mode === "installed") hooks.UserPromptSubmit = [{ hooks: [{ type: "command", command, timeout: 10 }] }];
			writeFileSync(path.join(codexHome, "hooks.json"), `${JSON.stringify({ hooks }, null, 2)}\n`);
		}
		writeFileSync(
			path.join(codexHome, "config.toml"),
			[
				'model = "mock-model"',
				'model_provider = "aidrmock"',
				"",
				"[model_providers.aidrmock]",
				'name = "AIDR real-host E2E mock model"',
				`base_url = "${mockUrl}/v1"`,
				'env_key = "AIDR_MOCK_MODEL_KEY"',
				'wire_api = "responses"',
				"",
				`[projects."${sandbox.ws}"]`,
				'trust_level = "trusted"',
				"",
			].join("\n"),
		);
		return { codexHome };
	},
	run(host, sandbox, prepared, { prompt, env, timeoutMs }) {
		// --dangerously-bypass-hook-trust skips Codex's persisted /hooks trust review
		// (an interactive step), not AIDR's decision; danger-full-access keeps the
		// host sandbox from being the thing that blocks a call.
		const args = ["exec", "--skip-git-repo-check", "--dangerously-bypass-hook-trust", "--sandbox", "danger-full-access", "--json", prompt];
		return runProcess(host.binary, args, {
			cwd: sandbox.ws,
			timeoutMs,
			env: { ...baseEnv(sandbox), ...observationEnv(sandbox), CODEX_HOME: prepared.codexHome, AIDR_MOCK_MODEL_KEY: "aidr-real-host-e2e-not-a-key", ...env },
		});
	},
};

// ── OpenCode ────────────────────────────────────────────────────────────────

const opencode = {
	id: "opencode",
	hostName: "OpenCode",
	protocol: "openai-chat-completions",
	canaryTool: "read",
	supportsCrashProbe: false,
	supportsOutputInspection: true,
	async resolve({ hostsDir, install }) {
		return resolveNpmHost(hostsDir, install, "opencode", { runPostinstall: true });
	},
	prepare(sandbox, mode, { mockUrl }) {
		const configDir = path.join(sandbox.home, ".config", "opencode");
		mkdirSync(configDir, { recursive: true });
		const config = {
			$schema: "https://opencode.ai/config.json",
			provider: {
				aidrmock: {
					npm: "@ai-sdk/openai-compatible",
					name: "AIDR real-host E2E mock model",
					options: { baseURL: `${mockUrl}/v1`, apiKey: "aidr-real-host-e2e-not-a-key" },
					models: { "mock-model": { name: "mock-model", tool_call: true } },
				},
			},
			model: "aidrmock/mock-model",
			small_model: "aidrmock/mock-model",
			permission: { bash: "allow", read: "allow", edit: "allow", external_directory: "allow" },
			autoupdate: false,
			share: "disabled",
		};
		// Local plugin path, as packages/opencode/README.md allows for development builds.
		if (mode === "installed") config.plugin = [`file://${path.join(REPO_ROOT, "packages", "opencode", "dist", "index.js")}`];
		writeFileSync(path.join(configDir, "opencode.json"), `${JSON.stringify(config, null, 2)}\n`);
		return {};
	},
	run(host, sandbox, _prepared, { prompt, env, timeoutMs }) {
		return runProcess(host.binary, ["run", "--format", "json", prompt], {
			cwd: sandbox.ws,
			timeoutMs,
			env: {
				...baseEnv(sandbox),
				...observationEnv(sandbox),
				XDG_CONFIG_HOME: path.join(sandbox.home, ".config"),
				XDG_DATA_HOME: path.join(sandbox.home, ".local", "share"),
				XDG_CACHE_HOME: path.join(sandbox.home, ".cache"),
				XDG_STATE_HOME: path.join(sandbox.home, ".local", "state"),
				OPENCODE_DISABLE_AUTOUPDATE: "1",
				OPENCODE_DISABLE_MODELS_FETCH: "1",
				...env,
			},
		});
	},
};

// ── OpenClaw ────────────────────────────────────────────────────────────────

const openclaw = {
	id: "openclaw",
	hostName: "OpenClaw",
	protocol: "openai-chat-completions",
	canaryTool: "read",
	supportsCrashProbe: false,
	// Asserted: the connector replaces a risky tool result through OpenClaw's agent
	// tool-result middleware, which the embedded runner awaits before the result
	// enters the model context (requires plugins.entries.aidr-openclaw.enabled: true).
	supportsOutputInspection: true,
	async resolve({ hostsDir, install }) {
		const pin = HOST_PINS.openclaw;
		const localRoot = path.join(hostsDir, "openclaw", "node_modules", "openclaw");
		let root = [process.env[pin.envOverride], localRoot].filter(Boolean).find((candidate) => existsSync(path.join(candidate, "openclaw.mjs")));
		if (!root && install) {
			npmInstall(path.join(hostsDir, "openclaw"), `${pin.npm}@${pin.version}`);
			root = localRoot;
		}
		if (!root || !existsSync(path.join(root, "openclaw.mjs"))) return null;
		let node = process.env.AIDR_OPENCLAW_NODE;
		if (!node) {
			const [major, minor] = nodeMajorMinor(process.execPath);
			const pinnedNode = path.join(hostsDir, `node-v${pin.node}-${process.platform}-${process.arch}`, "bin", "node");
			if (major > 24 || (major === 24 && minor >= 16)) node = process.execPath;
			else if (existsSync(pinnedNode)) node = pinnedNode;
			else if (install) node = await installNode(pin.node, hostsDir);
		}
		if (!node || !existsSync(node)) return null;
		const cli = path.join(root, "openclaw.mjs");
		const env = { ...process.env, PATH: `${path.dirname(node)}${path.delimiter}${process.env.PATH}` };
		return { binary: cli, node, version: versionOf(node, [cli, "--version"], env), nodeVersion: versionOf(node, ["--version"], env), pinnedVersion: pin.version };
	},
	prepare(sandbox, mode, { mockUrl }) {
		const state = path.join(sandbox.home, ".openclaw");
		mkdirSync(state, { recursive: true });
		const config = {
			agents: { defaults: { workspace: sandbox.ws, model: { primary: "aidrmock/mock-model" } } },
			models: {
				mode: "merge",
				providers: {
					aidrmock: {
						baseUrl: `${mockUrl}/v1`,
						apiKey: "aidr-real-host-e2e-not-a-key",
						api: "openai-completions",
						models: [
							{
								id: "mock-model",
								name: "mock-model",
								api: "openai-completions",
								reasoning: false,
								input: ["text"],
								cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
								contextWindow: 128000,
								maxTokens: 4096,
							},
						],
					},
				},
			},
		};
		if (mode === "installed") {
			// OpenClaw refuses plugin paths that resolve through pnpm links, so the
			// built plugin (package.json, manifest, bundled dist) is copied as the
			// packed tarball would lay it out.
			const pluginRoot = path.join(sandbox.root, "aidr-openclaw");
			for (const entry of ["package.json", "openclaw.plugin.json", "dist"]) {
				cpSync(path.join(REPO_ROOT, "packages", "openclaw", entry), path.join(pluginRoot, entry), { recursive: true });
			}
			config.plugins = {
				enabled: true,
				allow: ["aidr-openclaw"],
				load: { paths: [pluginRoot] },
				entries: { "aidr-openclaw": { enabled: true, hooks: { allowConversationAccess: true } } },
			};
		}
		writeFileSync(path.join(state, "openclaw.json"), `${JSON.stringify(config, null, 2)}\n`);
		return { state };
	},
	run(host, sandbox, prepared, { prompt, env, timeoutMs }) {
		return runProcess(host.node, [host.binary, "agent", "--local", "--json", "--session-id", sandbox.nonce, "-m", prompt], {
			cwd: sandbox.ws,
			timeoutMs,
			env: {
				...baseEnv(sandbox, [path.dirname(host.node)]),
				...observationEnv(sandbox),
				OPENCLAW_STATE_DIR: prepared.state,
				OPENCLAW_CONFIG_PATH: path.join(prepared.state, "openclaw.json"),
				...env,
			},
		});
	},
};

export const ADAPTERS = Object.freeze({ "claude-code": claudeCode, codex, opencode, openclaw });

/** Which connector build artefacts an adapter loads; a missing one is a setup failure, never a skip. */
export const CONNECTOR_ARTIFACTS = Object.freeze({
	// Each per-call hook is a compile-cache bootstrap (`<hook>.cjs`) plus the bundle it requires.
	"claude-code": [
		"packages/claude-code/dist/pre-tool-use.cjs",
		"packages/claude-code/dist/pre-tool-use.bundle.cjs",
		"packages/claude-code/dist/post-tool-use.cjs",
		"packages/claude-code/dist/post-tool-use.bundle.cjs",
		"packages/claude-code/dist/user-prompt-submit.cjs",
		"packages/claude-code/dist/user-prompt-submit.bundle.cjs",
		"hooks/hooks.json",
	],
	codex: ["packages/codex/dist/pre-tool-use.cjs", "packages/codex/dist/pre-tool-use.bundle.cjs"],
	opencode: ["packages/opencode/dist/index.js"],
	openclaw: ["packages/openclaw/dist/index.cjs", "packages/openclaw/openclaw.plugin.json"],
});

/** Build flavour baked into a connector artefact (release builds embed "commercial"). */
const FLAVOR_FILES = Object.freeze({
	// The hook bundle, not its compile-cache bootstrap, embeds core's build flavour.
	"claude-code": "packages/claude-code/dist/pre-tool-use.bundle.cjs",
	codex: "packages/codex/dist/pre-tool-use.bundle.cjs",
	// The OpenCode plugin imports the core package rather than bundling it.
	opencode: "packages/core/dist/build-flavor.js",
	openclaw: "packages/openclaw/dist/index.cjs",
});

export function artifactFlavor(connector) {
	const file = path.join(REPO_ROOT, FLAVOR_FILES[connector]);
	if (!existsSync(file)) return null;
	// Release bundles are minified; this reads the flavour from either form.
	const flavors = embeddedBuildFlavors(readFileSync(file, "utf8"));
	return flavors.length === 1 ? flavors[0] : "unknown";
}
