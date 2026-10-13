import { spawnSync } from "node:child_process";
import {
	accessSync,
	constants,
	copyFileSync,
	existsSync,
	lstatSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	renameSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import {
	type ConnectorState,
	type ConnectorStatus,
	detectConnectorStatuses,
} from "./connector-status.js";

/**
 * Connector installation and removal for every supported agent host.
 *
 * ## Why this exists
 *
 * `aidr setup` used to install nothing: it recorded state and printed manual
 * steps, so a user who ran only setup stayed unprotected (CON-13), and `aidr
 * uninstall` only knew Claude Code's receipt-managed hooks (PRD-9).
 *
 * ## Rules every host follows
 *
 * - **Measured, not claimed.** Detection and the after-state come from
 *   {@link detectConnectorStatuses}, the same measurement `aidr status` prints;
 *   an action is reported as done only when the re-measurement agrees.
 * - **Only AIDR's own entries.** A registration is ours only when it names the
 *   AIDR package or hook command; everything else in a host config is preserved.
 *   A config file we cannot parse is never rewritten.
 * - **Idempotent.** Nothing is written when the registration is already exactly
 *   what we would write; a changed file is backed up next to itself first.
 * - **Host tooling where the host owns installation** (OpenClaw plugins, VSIX
 *   extensions, Claude Code marketplace plugins): AIDR runs the host's own CLI
 *   when it is on PATH and the operator supplied the verified artifact; otherwise
 *   the host is reported as `manual` with the exact steps.
 */

export type HostId = ConnectorStatus["id"];

export const HOST_IDS: readonly HostId[] = [
	"claude-code",
	"cursor",
	"vscode",
	"openclaw",
	"opencode",
	"codex",
];

/** Command runner for host CLIs; injectable so tests never touch a real host. */
export type HostCommandRunner = (
	command: string,
	args: readonly string[],
	options: { env: NodeJS.ProcessEnv; timeoutMs: number },
) => { status: number | null; stdout?: string; stderr?: string; error?: Error };

export interface ConnectorDeps {
	/** Home whose host configs are measured and changed. */
	home: string;
	/** Environment for PATH lookups and host CLIs (HOME is pinned to `home`). */
	env?: NodeJS.ProcessEnv;
	run?: HostCommandRunner;
	/** The connector version to install; defaults to this CLI's version. */
	version: string;
	/** Clock for backup names (tests). */
	now?: () => number;
}

type HostInstallAction =
	| "already_installed"
	| "installed"
	| "updated"
	| "would_install"
	| "would_update"
	| "manual"
	| "failed"
	| "skipped_not_detected";

export interface HostInstallResult {
	host: HostId;
	label: string;
	action: HostInstallAction;
	/** One concrete sentence about what happened or why not. */
	detail: string;
	/** Files written and commands run, verbatim. */
	changes: string[];
	/** What the operator still has to do for this host. */
	followUp: string[];
	/** Measured state after this run. */
	state: ConnectorState;
}

export interface ConnectorInstallOptions {
	/** Explicit host selection. Default: every host found in the home directory. */
	hosts?: readonly HostId[];
	dryRun?: boolean;
	/** Extracted, verified Claude Code plugin directory (marketplace root). */
	claudePluginDir?: string;
	/** Verified VSIX files. */
	cursorVsix?: string;
	vscodeVsix?: string;
}

const AIDR_OPENCODE_PACKAGE = "@singularityrd/aidr-opencode";
const AIDR_OPENCLAW_PLUGIN_ID = "aidr-openclaw";
const AIDR_CODEX_HOOK = "aidr-codex-hook";
const CODEX_HOOK_PATTERN = /\baidr-codex-hook\b/;
const OPENCODE_LOCAL_MARKER = "Singularity AIDR OpenCode plugin";
const EXTENSION_IDS: Record<"cursor" | "vscode", string> = {
	cursor: "singularityrd.aidr-cursor",
	vscode: "singularityrd.aidr-vscode",
};
const EDITOR_CLIS: Record<"cursor" | "vscode", string> = { cursor: "cursor", vscode: "code" };
const HOST_COMMAND_TIMEOUT_MS = 180_000;

/** The Codex registrations AIDR owns, in the documented form (packages/codex/README.md). */
const CODEX_HOOK_EVENTS: ReadonlyArray<{ event: string; matcher?: string }> = [
	{ event: "PreToolUse", matcher: "^(Bash|apply_patch|mcp__.+)$" },
	{ event: "UserPromptSubmit" },
	{ event: "PostToolUse", matcher: "^(Bash|mcp__.+)$" },
];

// ── Small helpers ───────────────────────────────────────────────────────

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hostEnv(deps: ConnectorDeps): NodeJS.ProcessEnv {
	return { ...(deps.env ?? process.env), HOME: deps.home, USERPROFILE: deps.home };
}

function opencodeConfigDir(deps: ConnectorDeps): string {
	const xdg = (deps.env ?? process.env).XDG_CONFIG_HOME?.trim();
	return join(xdg || join(deps.home, ".config"), "opencode");
}

const defaultRunner: HostCommandRunner = (command, args, options) => {
	const windowsScript = process.platform === "win32" && /\.(cmd|bat)$/i.test(command);
	if (windowsScript && args.some((arg) => /["%^&|<>\r\n]/.test(arg))) {
		return {
			status: null,
			error: new Error("argument contains characters cmd.exe would interpret"),
		};
	}
	const result = spawnSync(
		windowsScript ? `"${command}"` : command,
		windowsScript ? args.map((arg) => `"${arg}"`) : [...args],
		{
			env: options.env,
			encoding: "utf8",
			timeout: options.timeoutMs,
			windowsHide: true,
			shell: windowsScript,
			maxBuffer: 8 * 1024 * 1024,
		},
	);
	return {
		status: result.status,
		stdout: result.stdout ?? "",
		stderr: result.stderr ?? "",
		...(result.error ? { error: result.error } : {}),
	};
};

/** Absolute path of an executable on PATH, or null. Never consults the cwd. */
function findExecutable(name: string, env: NodeJS.ProcessEnv): string | null {
	const pathValue = env.PATH ?? env.Path ?? "";
	const extensions =
		process.platform === "win32"
			? ["", ...(env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean)]
			: [""];
	for (const directory of pathValue.split(delimiter)) {
		if (!directory || !isAbsolute(directory)) continue;
		for (const extension of extensions) {
			const candidate = join(directory, `${name}${extension}`);
			try {
				if (!statSync(candidate).isFile()) continue;
				if (process.platform !== "win32") accessSync(candidate, constants.X_OK);
				return candidate;
			} catch {
				// Not here.
			}
		}
	}
	return null;
}

function measure(deps: Pick<ConnectorDeps, "home" | "env">, host: HostId): ConnectorStatus {
	return detectConnectorStatuses(deps.home, deps.env ?? process.env).find(
		(status) => status.id === host,
	) as ConnectorStatus;
}

/** Read a JSON object file: absent → {}, unparsable or not an object → error (never rewritten). */
function readJsonObject(path: string): { value: Record<string, unknown>; raw: Buffer | null } {
	let raw: Buffer;
	try {
		const info = lstatSync(path);
		if (info.isSymbolicLink() || !info.isFile()) throw new Error(`${path} is not a regular file`);
		raw = readFileSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return { value: {}, raw: null };
		throw error;
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw.toString("utf8"));
	} catch {
		throw new Error(`${path} is not valid JSON; it was left untouched`);
	}
	if (!isPlainObject(parsed))
		throw new Error(`${path} is not a JSON object; it was left untouched`);
	return { value: parsed, raw };
}

/** Back up an existing file, then replace it atomically. Returns the change lines. */
function writeWithBackup(
	path: string,
	content: string,
	original: Buffer | null,
	deps: ConnectorDeps,
	purpose: string,
): string[] {
	const changes: string[] = [];
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	if (original !== null) {
		const backup = `${path}.aidr-${purpose}-backup-${(deps.now ?? Date.now)()}`;
		copyFileSync(path, backup);
		changes.push(`backed up ${path} to ${backup}`);
	}
	const temporary = `${path}.aidr-${process.pid}.tmp`;
	writeFileSync(temporary, content, { flag: "wx", mode: 0o600 });
	try {
		// Re-check: another editor must not lose a concurrent change.
		const current = existsSync(path) ? readFileSync(path) : null;
		if (
			(current === null) !== (original === null) ||
			(current && original && !current.equals(original))
		) {
			throw new Error(`${path} changed while AIDR was editing it; retry`);
		}
		renameSync(temporary, path);
	} catch (error) {
		try {
			unlinkSync(temporary);
		} catch {
			/* Nothing left behind. */
		}
		throw error;
	}
	changes.push(`wrote ${path}`);
	return changes;
}

function result(
	host: HostId,
	label: string,
	action: HostInstallAction,
	detail: string,
	state: ConnectorState,
	changes: string[] = [],
	followUp: string[] = [],
): HostInstallResult {
	return { host, label, action, detail, changes, followUp, state };
}

function summarizeFailure(outcome: ReturnType<HostCommandRunner>): string {
	if (outcome.error) return outcome.error.message;
	const text = `${outcome.stderr ?? ""}\n${outcome.stdout ?? ""}`
		.trim()
		.split(/\r?\n/)
		.slice(-3)
		.join(" ");
	return `exit ${outcome.status}${text ? `: ${text.slice(0, 300)}` : ""}`;
}

// ── Codex: hooks.json registration ─────────────────────────────────────

function isAidrCodexHook(hook: unknown): boolean {
	return (
		isPlainObject(hook) && typeof hook.command === "string" && CODEX_HOOK_PATTERN.test(hook.command)
	);
}

/** Remove every AIDR handler from a Codex hooks object, keeping everything else. */
function stripCodexHooks(hooks: Record<string, unknown>): {
	hooks: Record<string, unknown>;
	removed: number;
} {
	const next: Record<string, unknown> = {};
	let removed = 0;
	for (const [event, entries] of Object.entries(hooks)) {
		if (!Array.isArray(entries)) {
			next[event] = entries;
			continue;
		}
		const kept: unknown[] = [];
		for (const entry of entries) {
			if (!isPlainObject(entry) || !Array.isArray(entry.hooks)) {
				kept.push(entry);
				continue;
			}
			const remaining = entry.hooks.filter((hook) => !isAidrCodexHook(hook));
			removed += entry.hooks.length - remaining.length;
			if (remaining.length === entry.hooks.length) kept.push(entry);
			else if (remaining.length > 0) kept.push({ ...entry, hooks: remaining });
		}
		if (kept.length > 0 || entries.length === 0) next[event] = kept;
	}
	return { hooks: next, removed };
}

function codexDesiredHooks(existing: Record<string, unknown>): Record<string, unknown> {
	const { hooks } = stripCodexHooks(existing);
	for (const { event, matcher } of CODEX_HOOK_EVENTS) {
		const entries = Array.isArray(hooks[event]) ? [...(hooks[event] as unknown[])] : [];
		entries.push({
			...(matcher ? { matcher } : {}),
			hooks: [{ type: "command", command: AIDR_CODEX_HOOK, timeout: 10 }],
		});
		hooks[event] = entries;
	}
	return hooks;
}

function installCodex(deps: ConnectorDeps, dryRun: boolean): HostInstallResult {
	const label = "Codex";
	const before = measure(deps, "codex");
	if (before.state === "installed" && before.detail.includes("config.toml")) {
		return result(
			"codex",
			label,
			"already_installed",
			"AIDR hook already registered in ~/.codex/config.toml; left as is.",
			before.state,
		);
	}
	const path = join(deps.home, ".codex", "hooks.json");
	let document: ReturnType<typeof readJsonObject>;
	try {
		document = readJsonObject(path);
	} catch (error) {
		return result(
			"codex",
			label,
			"manual",
			`${(error as Error).message}.`,
			before.state,
			[],
			["  Codex: register aidr-codex-hook by hand as shown in packages/codex/README.md."],
		);
	}
	const existingHooks = document.value.hooks;
	if (existingHooks !== undefined && !isPlainObject(existingHooks)) {
		return result(
			"codex",
			label,
			"manual",
			`${path} has a 'hooks' value that is not an object; it was left untouched.`,
			before.state,
		);
	}
	const desired = { ...document.value, hooks: codexDesiredHooks(existingHooks ?? {}) };
	const rendered = `${JSON.stringify(desired, null, 2)}\n`;
	const trust = [
		"  Codex: review and trust the three AIDR hooks with /hooks. Codex drops an untrusted",
		"         hook silently (fails open), so protection starts only after trust.",
	];
	if (
		document.raw !== null &&
		JSON.stringify(JSON.parse(document.raw.toString("utf8"))) === JSON.stringify(desired)
	) {
		return result(
			"codex",
			label,
			"already_installed",
			"AIDR hooks already registered in ~/.codex/hooks.json.",
			before.state,
			[],
			trust,
		);
	}
	const binary = findExecutable(AIDR_CODEX_HOOK, hostEnv(deps));
	if (!binary) {
		return result(
			"codex",
			label,
			"manual",
			`${AIDR_CODEX_HOOK} is not on PATH, so registering it would leave Codex running a missing hook (Codex fails open).`,
			before.state,
			[],
			[
				`  Codex: install @singularityrd/aidr-codex@${deps.version} from the private registry, then rerun 'aidr setup'.`,
			],
		);
	}
	const update = before.state === "installed" || before.state === "installed_but_degraded";
	if (dryRun) {
		return result(
			"codex",
			label,
			update ? "would_update" : "would_install",
			`would register ${AIDR_CODEX_HOOK} (${binary}) for PreToolUse, UserPromptSubmit and PostToolUse in ${path}.`,
			before.state,
			[],
			trust,
		);
	}
	try {
		const changes = writeWithBackup(path, rendered, document.raw, deps, "setup");
		const after = measure(deps, "codex");
		return result(
			"codex",
			label,
			after.state === "installed" ? (update ? "updated" : "installed") : "failed",
			after.state === "installed"
				? `registered ${AIDR_CODEX_HOOK} in ${path}.`
				: `wrote ${path} but Codex detection does not see the hook (${after.detail}).`,
			after.state,
			changes,
			trust,
		);
	} catch (error) {
		return result("codex", label, "failed", (error as Error).message, before.state);
	}
}

// ── OpenCode: npm plugin registration ──────────────────────────────────

function installOpenCode(deps: ConnectorDeps, dryRun: boolean): HostInstallResult {
	const label = "OpenCode";
	const before = measure(deps, "opencode");
	const dir = opencodeConfigDir(deps);
	const configPath = join(dir, "opencode.json");
	const manifestPath = join(dir, "package.json");
	if (!existsSync(configPath) && existsSync(join(dir, "opencode.jsonc"))) {
		return result(
			"opencode",
			label,
			"manual",
			"OpenCode is configured through opencode.jsonc, which AIDR does not rewrite (its comments would be lost).",
			before.state,
			[],
			[
				`  OpenCode: add "${AIDR_OPENCODE_PACKAGE}" to "plugin" in opencode.jsonc and`,
				`            {"dependencies":{"${AIDR_OPENCODE_PACKAGE}":"${deps.version}"}} to ${manifestPath}.`,
			],
		);
	}
	let config: ReturnType<typeof readJsonObject>;
	let manifest: ReturnType<typeof readJsonObject>;
	try {
		config = readJsonObject(configPath);
		manifest = readJsonObject(manifestPath);
	} catch (error) {
		return result("opencode", label, "manual", `${(error as Error).message}.`, before.state);
	}
	if (config.value.plugin !== undefined && !Array.isArray(config.value.plugin)) {
		return result(
			"opencode",
			label,
			"manual",
			`${configPath} has a 'plugin' value that is not an array; it was left untouched.`,
			before.state,
		);
	}
	if (manifest.value.dependencies !== undefined && !isPlainObject(manifest.value.dependencies)) {
		return result(
			"opencode",
			label,
			"manual",
			`${manifestPath} has 'dependencies' that are not an object; it was left untouched.`,
			before.state,
		);
	}
	const plugins = (config.value.plugin as unknown[] | undefined) ?? [];
	const dependencies = (manifest.value.dependencies as Record<string, unknown> | undefined) ?? {};
	const needsPlugin = !plugins.includes(AIDR_OPENCODE_PACKAGE);
	const currentVersion = dependencies[AIDR_OPENCODE_PACKAGE];
	const needsDependency = currentVersion !== deps.version;
	const followUp = [
		"  OpenCode: it installs the package at its next start; the private registry must be reachable",
		"            (docs/package-installation.md). Then run a host-side deny canary.",
	];
	if (!needsPlugin && !needsDependency) {
		return result(
			"opencode",
			label,
			"already_installed",
			`${AIDR_OPENCODE_PACKAGE}@${deps.version} already registered.`,
			before.state,
		);
	}
	const update = typeof currentVersion === "string" || !needsPlugin;
	if (dryRun) {
		return result(
			"opencode",
			label,
			update ? "would_update" : "would_install",
			`would pin ${AIDR_OPENCODE_PACKAGE}@${deps.version} in ${manifestPath} and list it in ${configPath}.`,
			before.state,
			[],
			followUp,
		);
	}
	try {
		const changes: string[] = [];
		if (needsDependency) {
			const next = {
				...manifest.value,
				dependencies: { ...dependencies, [AIDR_OPENCODE_PACKAGE]: deps.version },
			};
			changes.push(
				...writeWithBackup(
					manifestPath,
					`${JSON.stringify(next, null, 2)}\n`,
					manifest.raw,
					deps,
					"setup",
				),
			);
		}
		if (needsPlugin) {
			const next = { ...config.value, plugin: [...plugins, AIDR_OPENCODE_PACKAGE] };
			changes.push(
				...writeWithBackup(
					configPath,
					`${JSON.stringify(next, null, 2)}\n`,
					config.raw,
					deps,
					"setup",
				),
			);
		}
		const after = measure(deps, "opencode");
		return result(
			"opencode",
			label,
			after.state === "installed" ? (update ? "updated" : "installed") : "failed",
			after.state === "installed"
				? `registered ${AIDR_OPENCODE_PACKAGE}@${deps.version}.`
				: `wrote the OpenCode config but detection does not see the plugin (${after.detail}).`,
			after.state,
			changes,
			followUp,
		);
	} catch (error) {
		return result("opencode", label, "failed", (error as Error).message, before.state);
	}
}

// ── Host-CLI driven installs (OpenClaw, Cursor, VS Code, Claude Code) ───

function runHost(
	deps: ConnectorDeps,
	binary: string,
	args: readonly string[],
): ReturnType<HostCommandRunner> {
	return (deps.run ?? defaultRunner)(binary, args, {
		env: hostEnv(deps),
		timeoutMs: HOST_COMMAND_TIMEOUT_MS,
	});
}

function installOpenClaw(deps: ConnectorDeps, dryRun: boolean): HostInstallResult {
	const label = "OpenClaw";
	const before = measure(deps, "openclaw");
	const spec = `npm:@singularityrd/aidr-openclaw@${deps.version}`;
	if (before.state === "installed") {
		return result(
			"openclaw",
			label,
			"already_installed",
			"AIDR plugin already enabled in ~/.openclaw/openclaw.json.",
			before.state,
		);
	}
	if (before.state === "installed_but_degraded") {
		return result(
			"openclaw",
			label,
			"manual",
			before.detail,
			before.state,
			[],
			[`  OpenClaw: ${before.remedy ?? "enable aidr-openclaw in the OpenClaw plugin policy"}.`],
		);
	}
	const binary = findExecutable("openclaw", hostEnv(deps));
	const manual = [
		`  OpenClaw: openclaw plugins install ${spec}`,
		"            then run a host-side deny canary.",
	];
	if (!binary)
		return result(
			"openclaw",
			label,
			"manual",
			"the openclaw CLI is not on PATH.",
			before.state,
			[],
			manual,
		);
	if (dryRun)
		return result(
			"openclaw",
			label,
			"would_install",
			`would run: openclaw plugins install ${spec}`,
			before.state,
		);
	const outcome = runHost(deps, binary, ["plugins", "install", spec]);
	const after = measure(deps, "openclaw");
	const command = `ran: ${binary} plugins install ${spec}`;
	if (outcome.status === 0 && after.state === "installed") {
		return result(
			"openclaw",
			label,
			"installed",
			`installed ${spec}.`,
			after.state,
			[command],
			["  OpenClaw: run a host-side deny canary."],
		);
	}
	return result(
		"openclaw",
		label,
		"failed",
		`openclaw plugins install did not register AIDR (${outcome.status === 0 ? after.detail : summarizeFailure(outcome)}).`,
		after.state,
		[command],
		manual,
	);
}

function installEditor(
	host: "cursor" | "vscode",
	deps: ConnectorDeps,
	dryRun: boolean,
	vsix: string | undefined,
): HostInstallResult {
	const label = host === "cursor" ? "Cursor" : "VS Code";
	const before = measure(deps, host);
	const artifact = host === "cursor" ? "aidr-cursor.vsix" : "aidr-vscode.vsix";
	const cliName = EDITOR_CLIS[host];
	const enable = `  ${label}: run 'Singularity AIDR: Enable protection' from the command palette.`;
	if (!vsix) {
		return before.state === "installed"
			? result(
					host,
					label,
					"already_installed",
					`${before.detail}; pass --${host}-vsix <file> to update it.`,
					before.state,
				)
			: result(
					host,
					label,
					"manual",
					`no verified ${artifact} was given (--${host}-vsix <file>).`,
					before.state,
					[],
					[
						`  ${label}: ${cliName} --install-extension ./${artifact} (from the verified release bundle)`,
						enable,
					],
				);
	}
	const file = resolve(vsix);
	if (!existsSync(file) || !statSync(file).isFile()) {
		return result(host, label, "failed", `${file} is not a file.`, before.state);
	}
	const binary = findExecutable(cliName, hostEnv(deps));
	if (!binary) {
		return result(
			host,
			label,
			"manual",
			`the ${cliName} CLI is not on PATH.`,
			before.state,
			[],
			[`  ${label}: ${cliName} --install-extension ${file}`, enable],
		);
	}
	const update = before.state === "installed";
	if (dryRun)
		return result(
			host,
			label,
			update ? "would_update" : "would_install",
			`would run: ${cliName} --install-extension ${file} --force`,
			before.state,
		);
	const outcome = runHost(deps, binary, ["--install-extension", file, "--force"]);
	const after = measure(deps, host);
	const command = `ran: ${binary} --install-extension ${file} --force`;
	if (outcome.status === 0 && after.state === "installed") {
		return result(
			host,
			label,
			update ? "updated" : "installed",
			`installed ${EXTENSION_IDS[host]} from ${file}.`,
			after.state,
			[command],
			[enable],
		);
	}
	return result(
		host,
		label,
		"failed",
		`the extension install did not register AIDR (${outcome.status === 0 ? after.detail : summarizeFailure(outcome)}).`,
		after.state,
		[command],
	);
}

const CLAUDE_MANUAL = [
	"  Claude Code:  verify the publisher-signed release bundle and extract aidr-claude-plugin-<version>.tar.gz,",
	"                provision the release Ed25519 public key in ~/.singularity-aidr/config.json, then run",
	"                aidr setup --claude-plugin-dir /absolute/path/to/extracted/aidr-claude-plugin",
	"                (or from the Claude Code prompt: /plugin marketplace add <dir> and /plugin install aidr@aidr).",
];

function installClaude(
	deps: ConnectorDeps,
	dryRun: boolean,
	pluginDir: string | undefined,
): HostInstallResult {
	const label = "Claude Code";
	const before = measure(deps, "claude-code");
	if (before.state === "installed") {
		return result("claude-code", label, "already_installed", before.detail, before.state);
	}
	if (!pluginDir) {
		return result(
			"claude-code",
			label,
			"manual",
			"no verified plugin directory was given (--claude-plugin-dir <dir>).",
			before.state,
			[],
			CLAUDE_MANUAL,
		);
	}
	const dir = resolve(pluginDir);
	if (
		!existsSync(join(dir, ".claude-plugin", "marketplace.json")) &&
		!existsSync(join(dir, ".claude-plugin", "plugin.json"))
	) {
		return result(
			"claude-code",
			label,
			"failed",
			`${dir} is not an extracted AIDR Claude Code plugin (no .claude-plugin manifest).`,
			before.state,
		);
	}
	const binary = findExecutable("claude", hostEnv(deps));
	if (!binary)
		return result(
			"claude-code",
			label,
			"manual",
			"the claude CLI is not on PATH.",
			before.state,
			[],
			CLAUDE_MANUAL,
		);
	if (dryRun) {
		return result(
			"claude-code",
			label,
			"would_install",
			`would run: claude plugin marketplace add ${dir}; claude plugin install aidr@aidr`,
			before.state,
		);
	}
	const changes: string[] = [];
	for (const args of [
		["plugin", "marketplace", "add", dir],
		["plugin", "install", "aidr@aidr"],
	]) {
		const outcome = runHost(deps, binary, args);
		changes.push(`ran: ${binary} ${args.join(" ")}`);
		if (outcome.status !== 0) {
			return result(
				"claude-code",
				label,
				"failed",
				`claude ${args.join(" ")} failed (${summarizeFailure(outcome)}).`,
				measure(deps, "claude-code").state,
				changes,
				CLAUDE_MANUAL,
			);
		}
	}
	const after = measure(deps, "claude-code");
	return after.state === "installed"
		? result(
				"claude-code",
				label,
				"installed",
				"installed aidr@aidr from the verified plugin directory.",
				after.state,
				changes,
				["  Claude Code: restart it and confirm the plugin is active (/plugin)."],
			)
		: result(
				"claude-code",
				label,
				"failed",
				`the plugin install did not register AIDR (${after.detail}).`,
				after.state,
				changes,
				CLAUDE_MANUAL,
			);
}

// ── Install entry point ───────────────────────────────────────────────

/** Hosts present in the home directory: the same measurement `aidr status` prints. */
function detectedHosts(deps: Pick<ConnectorDeps, "home" | "env">): HostId[] {
	return HOST_IDS.filter((host) => measure(deps, host).state !== "not_detected");
}

/**
 * Install or update the connector of every selected host. With no explicit
 * selection that is every host found in the home directory; the others are
 * reported as `skipped_not_detected`. Never throws for a single host's failure.
 */
export function installConnectors(
	deps: ConnectorDeps,
	options: ConnectorInstallOptions = {},
): HostInstallResult[] {
	const selected = new Set(options.hosts ?? detectedHosts(deps));
	const dryRun = options.dryRun === true;
	return HOST_IDS.map((host) => {
		if (!selected.has(host)) {
			const status = measure(deps, host);
			return result(
				host,
				status.label,
				"skipped_not_detected",
				options.hosts ? "not selected." : status.detail,
				status.state,
			);
		}
		try {
			switch (host) {
				case "codex":
					return installCodex(deps, dryRun);
				case "opencode":
					return installOpenCode(deps, dryRun);
				case "openclaw":
					return installOpenClaw(deps, dryRun);
				case "cursor":
					return installEditor("cursor", deps, dryRun, options.cursorVsix);
				case "vscode":
					return installEditor("vscode", deps, dryRun, options.vscodeVsix);
				default:
					return installClaude(deps, dryRun, options.claudePluginDir);
			}
		} catch (error) {
			const status = measure(deps, host);
			return result(
				host,
				status.label,
				"failed",
				error instanceof Error ? error.message : String(error),
				status.state,
			);
		}
	});
}

// ── Removal ───────────────────────────────────────────────────────────

type HostRemovalAction =
	| "removed"
	| "nothing_to_remove"
	| "would_remove"
	| "manual"
	| "failed";

export interface HostRemovalResult {
	host: HostId;
	label: string;
	action: HostRemovalAction;
	detail: string;
	changes: string[];
	followUp: string[];
	/** Measured state after this run. */
	state: ConnectorState;
}

function removal(
	host: HostId,
	label: string,
	action: HostRemovalAction,
	detail: string,
	state: ConnectorState,
	changes: string[] = [],
	followUp: string[] = [],
): HostRemovalResult {
	return { host, label, action, detail, changes, followUp, state };
}

/**
 * Remove AIDR handlers from a Codex `config.toml`, preserving every other line.
 *
 * Works on table blocks: an `[[hooks.<Event>.hooks]]` block whose `command`
 * names aidr-codex-hook is dropped; its `[[hooks.<Event>]]` parent is dropped
 * too when every handler under it was AIDR's.
 */
export function stripCodexToml(raw: string): { text: string; removed: number } {
	const lines = raw.split(/(?<=\n)/);
	const blocks: Array<{ header: string | null; lines: string[] }> = [{ header: null, lines: [] }];
	for (const line of lines) {
		const header = line.match(/^[ \t]*(\[\[?[^\]\r\n]+\]\]?)[ \t]*(?:#.*)?\r?\n?$/);
		if (header) blocks.push({ header: (header[1] as string).replace(/\s+/g, ""), lines: [line] });
		else (blocks[blocks.length - 1] as { lines: string[] }).lines.push(line);
	}
	const isHandler = (block: { header: string | null }, event: string) =>
		block.header === `[[hooks.${event}.hooks]]`;
	const isAidrHandler = (block: { lines: string[] }) =>
		block.lines.some((line) => {
			const match = line.match(/^[ \t]*command[ \t]*=[ \t]*(?:"([^"\r\n]*)"|'([^'\r\n]*)')/);
			return CODEX_HOOK_PATTERN.test(match?.[1] ?? match?.[2] ?? "");
		});
	const drop = new Set<number>();
	let removed = 0;
	blocks.forEach((block, index) => {
		const parent = block.header?.match(/^\[\[hooks\.([A-Za-z]+)\]\]$/);
		if (!parent) return;
		const event = parent[1] as string;
		const handlers: number[] = [];
		for (let next = index + 1; next < blocks.length; next++) {
			const header = blocks[next]?.header ?? "";
			if (!header.startsWith(`[[hooks.${event}.`) && !header.startsWith(`[hooks.${event}.`)) break;
			if (isHandler(blocks[next] as { header: string | null }, event)) handlers.push(next);
		}
		const ours = handlers.filter((at) => isAidrHandler(blocks[at] as { lines: string[] }));
		for (const at of ours) drop.add(at);
		removed += ours.length;
		if (ours.length > 0 && ours.length === handlers.length) drop.add(index);
	});
	return {
		text: blocks
			.filter((_, index) => !drop.has(index))
			.flatMap((block) => block.lines)
			.join(""),
		removed,
	};
}

function removeCodex(deps: ConnectorDeps, dryRun: boolean): HostRemovalResult {
	const label = "Codex";
	const before = measure(deps, "codex");
	const changes: string[] = [];
	let found = 0;
	const jsonPath = join(deps.home, ".codex", "hooks.json");
	const tomlPath = join(deps.home, ".codex", "config.toml");
	try {
		const document = readJsonObject(jsonPath);
		if (isPlainObject(document.value.hooks)) {
			const stripped = stripCodexHooks(document.value.hooks);
			found += stripped.removed;
			if (stripped.removed > 0 && !dryRun) {
				const next = { ...document.value, hooks: stripped.hooks };
				changes.push(
					...writeWithBackup(
						jsonPath,
						`${JSON.stringify(next, null, 2)}\n`,
						document.raw,
						deps,
						"uninstall",
					),
				);
			}
		}
		if (existsSync(tomlPath)) {
			const raw = readFileSync(tomlPath);
			const stripped = stripCodexToml(raw.toString("utf8"));
			found += stripped.removed;
			if (stripped.removed > 0 && !dryRun) {
				changes.push(...writeWithBackup(tomlPath, stripped.text, raw, deps, "uninstall"));
			}
		}
	} catch (error) {
		return removal("codex", label, "failed", (error as Error).message, before.state, changes, [
			"  Codex: remove the aidr-codex-hook handlers from ~/.codex/hooks.json / config.toml by hand.",
		]);
	}
	if (found === 0)
		return removal("codex", label, "nothing_to_remove", "no AIDR hook registered.", before.state);
	if (dryRun)
		return removal(
			"codex",
			label,
			"would_remove",
			`would remove ${found} aidr-codex-hook handler(s).`,
			before.state,
		);
	const after = measure(deps, "codex");
	return removal(
		"codex",
		label,
		after.state === "installed" ? "failed" : "removed",
		`removed ${found} aidr-codex-hook handler(s).`,
		after.state,
		changes,
		[
			"  Codex: the global @singularityrd/aidr-codex package is left installed; remove it with npm uninstall --global @singularityrd/aidr-codex.",
		],
	);
}

function removeOpenCode(deps: ConnectorDeps, dryRun: boolean): HostRemovalResult {
	const label = "OpenCode";
	const before = measure(deps, "opencode");
	const dir = opencodeConfigDir(deps);
	const configPath = join(dir, "opencode.json");
	const manifestPath = join(dir, "package.json");
	const changes: string[] = [];
	const found: string[] = [];
	try {
		const config = readJsonObject(configPath);
		const manifest = readJsonObject(manifestPath);
		const plugins = Array.isArray(config.value.plugin) ? (config.value.plugin as unknown[]) : null;
		const dependencies = isPlainObject(manifest.value.dependencies)
			? manifest.value.dependencies
			: null;
		const localFiles: string[] = [];
		for (const sub of ["plugins", "plugin"]) {
			const pluginDir = join(dir, sub);
			if (!existsSync(pluginDir)) continue;
			for (const name of readdirSync(pluginDir)) {
				const path = join(pluginDir, name);
				const info = lstatSync(path);
				if (
					info.isFile() &&
					!info.isSymbolicLink() &&
					/aidr|singularity/i.test(name) &&
					readFileSync(path, "utf8").includes(OPENCODE_LOCAL_MARKER)
				) {
					localFiles.push(path);
				}
			}
		}
		if (plugins?.includes(AIDR_OPENCODE_PACKAGE)) found.push(configPath);
		if (dependencies && AIDR_OPENCODE_PACKAGE in dependencies) found.push(manifestPath);
		found.push(...localFiles);
		if (found.length === 0)
			return removal(
				"opencode",
				label,
				"nothing_to_remove",
				"no AIDR plugin registered.",
				before.state,
			);
		if (dryRun)
			return removal(
				"opencode",
				label,
				"would_remove",
				`would remove AIDR from ${found.join(", ")}.`,
				before.state,
			);
		if (plugins?.includes(AIDR_OPENCODE_PACKAGE)) {
			const next = {
				...config.value,
				plugin: plugins.filter((entry) => entry !== AIDR_OPENCODE_PACKAGE),
			};
			changes.push(
				...writeWithBackup(
					configPath,
					`${JSON.stringify(next, null, 2)}\n`,
					config.raw,
					deps,
					"uninstall",
				),
			);
		}
		if (dependencies && AIDR_OPENCODE_PACKAGE in dependencies) {
			const { [AIDR_OPENCODE_PACKAGE]: _removed, ...rest } = dependencies;
			const next = { ...manifest.value, dependencies: rest };
			changes.push(
				...writeWithBackup(
					manifestPath,
					`${JSON.stringify(next, null, 2)}\n`,
					manifest.raw,
					deps,
					"uninstall",
				),
			);
		}
		for (const path of localFiles) {
			unlinkSync(path);
			changes.push(`deleted ${path}`);
		}
	} catch (error) {
		return removal("opencode", label, "failed", (error as Error).message, before.state, changes, [
			`  OpenCode: remove "${AIDR_OPENCODE_PACKAGE}" from opencode.json "plugin" and package.json by hand.`,
		]);
	}
	const after = measure(deps, "opencode");
	return removal(
		"opencode",
		label,
		after.state === "installed" ? "failed" : "removed",
		`removed AIDR from ${found.join(", ")}.`,
		after.state,
		changes,
	);
}

function removeViaHostCli(
	host: "openclaw" | "cursor" | "vscode" | "claude-code",
	deps: ConnectorDeps,
	dryRun: boolean,
	cliName: string,
	commands: string[][],
	manual: string[],
): HostRemovalResult {
	const before = measure(deps, host);
	const label = before.label;
	if (before.state !== "installed" && before.state !== "installed_but_degraded") {
		return removal(host, label, "nothing_to_remove", before.detail, before.state);
	}
	const binary = findExecutable(cliName, hostEnv(deps));
	if (!binary)
		return removal(
			host,
			label,
			"manual",
			`the ${cliName} CLI is not on PATH.`,
			before.state,
			[],
			manual,
		);
	if (dryRun)
		return removal(
			host,
			label,
			"would_remove",
			`would run: ${commands.map((args) => `${cliName} ${args.join(" ")}`).join("; ")}`,
			before.state,
		);
	const changes: string[] = [];
	let lastFailure = "";
	for (const args of commands) {
		const outcome = runHost(deps, binary, args);
		changes.push(`ran: ${binary} ${args.join(" ")}`);
		if (outcome.status !== 0) lastFailure = summarizeFailure(outcome);
	}
	const after = measure(deps, host);
	if (after.state === "installed" || after.state === "installed_but_degraded") {
		return removal(
			host,
			label,
			"failed",
			`AIDR is still registered after the host CLI ran${lastFailure ? ` (${lastFailure})` : ""}.`,
			after.state,
			changes,
			manual,
		);
	}
	return removal(host, label, "removed", "the host CLI removed AIDR.", after.state, changes);
}

function claudeHasMarketplacePlugin(home: string): boolean {
	try {
		const settings = JSON.parse(readFileSync(join(home, ".claude", "settings.json"), "utf8")) as {
			enabledPlugins?: Record<string, unknown>;
		};
		return Object.keys(settings.enabledPlugins ?? {}).some((name) =>
			/aidr|singularity/i.test(name),
		);
	} catch {
		return false;
	}
}

/**
 * Remove the connector of every selected host (default: all). Claude Code
 * receipt-managed hooks are handled by the caller (`uninstallAidr`); this
 * removes the marketplace plugin registration.
 */
export function removeConnectors(
	deps: ConnectorDeps,
	options: { hosts?: readonly HostId[]; dryRun?: boolean } = {},
): HostRemovalResult[] {
	const selected = new Set(options.hosts ?? HOST_IDS);
	const dryRun = options.dryRun === true;
	return HOST_IDS.filter((host) => selected.has(host)).map((host) => {
		try {
			switch (host) {
				case "codex":
					return removeCodex(deps, dryRun);
				case "opencode":
					return removeOpenCode(deps, dryRun);
				case "openclaw":
					return removeViaHostCli(
						"openclaw",
						deps,
						dryRun,
						"openclaw",
						[["plugins", "uninstall", AIDR_OPENCLAW_PLUGIN_ID]],
						[`  OpenClaw: openclaw plugins uninstall ${AIDR_OPENCLAW_PLUGIN_ID}`],
					);
				case "cursor":
				case "vscode":
					return removeViaHostCli(
						host,
						deps,
						dryRun,
						EDITOR_CLIS[host],
						[["--uninstall-extension", EXTENSION_IDS[host]]],
						[
							`  ${host === "cursor" ? "Cursor" : "VS Code"}: ${EDITOR_CLIS[host]} --uninstall-extension ${EXTENSION_IDS[host]}`,
						],
					);
				default: {
					if (!claudeHasMarketplacePlugin(deps.home)) {
						const status = measure(deps, "claude-code");
						return removal(
							"claude-code",
							status.label,
							"nothing_to_remove",
							"no AIDR marketplace plugin enabled.",
							status.state,
						);
					}
					return removeViaHostCli(
						"claude-code",
						deps,
						dryRun,
						"claude",
						[
							["plugin", "uninstall", "aidr@aidr"],
							["plugin", "marketplace", "remove", "aidr"],
						],
						["  Claude Code: /plugin uninstall aidr@aidr and /plugin marketplace remove aidr"],
					);
				}
			}
		} catch (error) {
			const status = measure(deps, host);
			return removal(
				host,
				status.label,
				"failed",
				error instanceof Error ? error.message : String(error),
				status.state,
			);
		}
	});
}
