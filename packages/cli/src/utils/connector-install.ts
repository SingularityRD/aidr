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
import { ct } from "../i18n/index.js";
import { CODEX_HOOK_PATTERN, codexDesiredHooks, stripCodexHooks } from "./codex-hooks.js";
import {
	type ConnectorState,
	type ConnectorStatus,
	detectConnectorStatuses,
} from "./connector-status.js";
import { MANAGED_HOOK_MARKER } from "./install-hooks.js";
import { type MachineHookState, machineHookStatus } from "./machine-hooks.js";
import {
	failClosedHookCommand,
	type HookProbe,
	probeHookCommand,
	quoteHookPath,
	STANDALONE_CLAUDE_HOOKS,
	STANDALONE_CODEX_HOOK,
	STANDALONE_INSTALL_KIND,
	type StandaloneBundleCheck,
	standaloneExtension,
	standaloneHookCommand,
	verifyStandaloneBundle,
} from "./standalone.js";

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
	/**
	 * Root of the standalone (SEA) bundle `aidr` runs from (desktop installers).
	 * With it, Claude Code gets the bundle's hook binaries registered directly;
	 * without it Claude Code needs a verified plugin directory. Codex gets the
	 * bundle's Codex hook, and Cursor / VS Code the VSIXs the bundle ships.
	 */
	standaloneRoot?: string;
	/**
	 * Release public keys (PEM) the bundle's signatures must verify against:
	 * the `integrity.public_keys_pem` the hooks will trust once registered.
	 */
	releaseKeys?: readonly string[];
	/** A release (commercial) bundle: its runtime manifest must be signed by a trusted key. */
	requireSignedBundle?: boolean;
	/** System-wide (machine policy) registrations; measured from the host's policy paths by default. */
	machine?: readonly MachineHookState[];
}

type HostInstallAction =
	| "already_installed"
	| "installed"
	| "updated"
	| "would_install"
	| "would_update"
	| "manual"
	| "failed"
	| "skipped_not_detected"
	/** Found in the home directory, but left out by an explicit `--host` selection. */
	| "skipped_not_selected";

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
const OPENCODE_LOCAL_MARKER = "Singularity AIDR OpenCode plugin";
const EXTENSION_IDS: Record<"cursor" | "vscode", string> = {
	cursor: "singularityrd.aidr-cursor",
	vscode: "singularityrd.aidr-vscode",
};
const EDITOR_CLIS: Record<"cursor" | "vscode", string> = { cursor: "cursor", vscode: "code" };
const HOST_COMMAND_TIMEOUT_MS = 180_000;

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

function measure(
	deps: Pick<ConnectorDeps, "home" | "env" | "machine">,
	host: HostId,
): ConnectorStatus {
	return detectConnectorStatuses(
		deps.home,
		deps.env ?? process.env,
		deps.machine ?? machineHookStatus(),
	).find((status) => status.id === host) as ConnectorStatus;
}

/**
 * The host already runs AIDR's hooks from its system-wide managed policy
 * (`aidr machine-hooks install`, run by the per-machine installers). A user
 * registration on top would inspect every call twice, so setup leaves the
 * user's files alone.
 */
function machinePolicyResult(
	deps: ConnectorDeps,
	host: "claude-code" | "codex",
	label: string,
): HostInstallResult | null {
	const machine = (deps.machine ?? machineHookStatus()).find((entry) => entry.host === host);
	if (!machine?.registered) return null;
	return result(
		host,
		label,
		"already_installed",
		ct("install.machinePolicy", { path: machine.path }),
		"installed",
	);
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
		changes.push(ct("install.backedUp", { path, backup }));
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
	changes.push(ct("install.wrote", { path }));
	return changes;
}

/** {@link writeWithBackup} for a JSON document, rendered the way every host config is written. */
function writeJsonWithBackup(
	path: string,
	value: Record<string, unknown>,
	original: Buffer | null,
	deps: ConnectorDeps,
	purpose: string,
): string[] {
	return writeWithBackup(path, `${JSON.stringify(value, null, 2)}\n`, original, deps, purpose);
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

/** One verification of the standalone bundle per install run, shared by every host. */
const bundleChecks = new WeakMap<ConnectorDeps, StandaloneBundleCheck>();
function standaloneBundle(deps: ConnectorDeps): StandaloneBundleCheck {
	const cached = bundleChecks.get(deps);
	if (cached) return cached;
	const check = verifyStandaloneBundle(deps.standaloneRoot as string, {
		trustKeys: deps.releaseKeys ?? [],
		requireSignature: deps.requireSignedBundle === true,
	});
	bundleChecks.set(deps, check);
	return check;
}

function bundleFailure(deps: ConnectorDeps, check: StandaloneBundleCheck): string {
	return ct("install.bundleFailed", {
		root: String(deps.standaloneRoot),
		problems: check.problems.slice(0, 3).join("; "),
	});
}

/** Why a canary probe failed, in one sentence. */
function probeFailure(probe: { canary: HookProbe; benign: HookProbe | null }): string {
	return probe.benign === null
		? ct("install.probeDecision", {
				decision: probe.canary.decision,
				detail: probe.canary.detail,
			})
		: ct("install.probeBenign", { detail: probe.benign.detail });
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

/** A Codex PreToolUse payload for a shell command (the fields Codex always sends). */
function codexPayload(cwd: string): (shellCommand: string) => Record<string, unknown> {
	return (shellCommand) => ({
		session_id: "aidr-setup-canary",
		turn_id: "aidr-setup-canary",
		hook_event_name: "PreToolUse",
		cwd,
		model: "aidr-setup",
		permission_mode: "default",
		transcript_path: null,
		tool_name: "Bash",
		tool_use_id: "aidr-setup-canary-call",
		tool_input: { command: shellCommand },
	});
}

/** A Claude Code PreToolUse payload for a shell command. */
function claudePayload(cwd: string): (shellCommand: string) => Record<string, unknown> {
	return (shellCommand) => ({
		hook_event_name: "PreToolUse",
		session_id: "aidr-setup-canary",
		cwd,
		tool_name: "Bash",
		tool_input: { command: shellCommand },
	});
}

function installCodex(deps: ConnectorDeps, dryRun: boolean): HostInstallResult {
	const label = "Codex";
	const fromPolicy = machinePolicyResult(deps, "codex", label);
	if (fromPolicy) return fromPolicy;
	const before = measure(deps, "codex");
	if (before.state === "installed" && before.detail === ct("conn.codex.toml")) {
		return result(
			"codex",
			label,
			"already_installed",
			ct("install.codex.tomlRegistered"),
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
			[ct("install.codex.byHand")],
		);
	}
	const existingHooks = document.value.hooks;
	if (existingHooks !== undefined && !isPlainObject(existingHooks)) {
		return result(
			"codex",
			label,
			"manual",
			ct("install.notObject", { path, field: "hooks" }),
			before.state,
		);
	}
	// From the standalone bundle the hook is the bundle's binary
	// (`"<bundle>/bin/aidr" hook aidr-codex-hook`); otherwise the npm bin found on
	// PATH, registered by absolute path: Codex started from a GUI or a service has
	// a different PATH, and a hook it cannot find fails open.
	const root = deps.standaloneRoot;
	const onPath = root ? null : findExecutable(AIDR_CODEX_HOOK, hostEnv(deps));
	const command = root
		? standaloneHookCommand(root, STANDALONE_CODEX_HOOK)
		: onPath
			? failClosedHookCommand(quoteHookPath(onPath))
			: AIDR_CODEX_HOOK;
	if (root) {
		const bundle = standaloneBundle(deps);
		if (!bundle.ok)
			return result("codex", label, "failed", bundleFailure(deps, bundle), before.state);
	}
	const desired = { ...document.value, hooks: codexDesiredHooks(existingHooks ?? {}, command) };
	const trust = [ct("install.codex.trust1"), ct("install.codex.trust2")];
	if (document.raw !== null && JSON.stringify(document.value) === JSON.stringify(desired)) {
		return result(
			"codex",
			label,
			"already_installed",
			ct("install.codex.jsonRegistered"),
			before.state,
			[],
			trust,
		);
	}
	const binary = root ? command : onPath;
	if (!binary) {
		return result(
			"codex",
			label,
			"manual",
			ct("install.codex.notOnPath", { hook: AIDR_CODEX_HOOK }),
			before.state,
			[],
			[ct("install.codex.installPackage", { version: deps.version })],
		);
	}
	const update = before.state === "installed" || before.state === "installed_but_degraded";
	if (dryRun) {
		return result(
			"codex",
			label,
			update ? "would_update" : "would_install",
			ct("install.codex.wouldRegister", { hook: AIDR_CODEX_HOOK, binary, path }),
			before.state,
			[],
			trust,
		);
	}
	if (root) {
		// The canary is data on the hook's stdin; nothing is executed.
		const probe = probeHookCommand(command, codexPayload(deps.home), {
			home: deps.home,
			cwd: deps.home,
			env: deps.env,
		});
		if (!probe.ok) {
			return result(
				"codex",
				label,
				"failed",
				ct("install.codex.probeFailed", { reason: probeFailure(probe) }),
				before.state,
			);
		}
	}
	try {
		const changes = writeJsonWithBackup(path, desired, document.raw, deps, "setup");
		const after = measure(deps, "codex");
		return result(
			"codex",
			label,
			after.state === "installed" ? (update ? "updated" : "installed") : "failed",
			after.state === "installed"
				? ct("install.codex.registered", { hook: AIDR_CODEX_HOOK, path })
				: ct("install.codex.notSeen", { path, detail: after.detail }),
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
			ct("install.opencode.jsonc"),
			before.state,
			[],
			[
				ct("install.opencode.jsoncStep1", { package: AIDR_OPENCODE_PACKAGE }),
				ct("install.opencode.jsoncStep2", {
					dependencies: JSON.stringify({ dependencies: { [AIDR_OPENCODE_PACKAGE]: deps.version } }),
					path: manifestPath,
				}),
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
			ct("install.notArray", { path: configPath, field: "plugin" }),
			before.state,
		);
	}
	if (manifest.value.dependencies !== undefined && !isPlainObject(manifest.value.dependencies)) {
		return result(
			"opencode",
			label,
			"manual",
			ct("install.notObject", { path: manifestPath, field: "dependencies" }),
			before.state,
		);
	}
	const plugins = (config.value.plugin as unknown[] | undefined) ?? [];
	const dependencies = (manifest.value.dependencies as Record<string, unknown> | undefined) ?? {};
	const needsPlugin = !plugins.includes(AIDR_OPENCODE_PACKAGE);
	const currentVersion = dependencies[AIDR_OPENCODE_PACKAGE];
	const needsDependency = currentVersion !== deps.version;
	const followUp = [ct("install.opencode.follow1"), ct("install.opencode.follow2")];
	if (!needsPlugin && !needsDependency) {
		return result(
			"opencode",
			label,
			"already_installed",
			ct("install.opencode.already", { package: AIDR_OPENCODE_PACKAGE, version: deps.version }),
			before.state,
		);
	}
	const update = typeof currentVersion === "string" || !needsPlugin;
	if (dryRun) {
		return result(
			"opencode",
			label,
			update ? "would_update" : "would_install",
			ct("install.opencode.wouldPin", {
				package: AIDR_OPENCODE_PACKAGE,
				version: deps.version,
				manifest: manifestPath,
				config: configPath,
			}),
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
			changes.push(...writeJsonWithBackup(manifestPath, next, manifest.raw, deps, "setup"));
		}
		if (needsPlugin) {
			const next = { ...config.value, plugin: [...plugins, AIDR_OPENCODE_PACKAGE] };
			changes.push(...writeJsonWithBackup(configPath, next, config.raw, deps, "setup"));
		}
		const after = measure(deps, "opencode");
		return result(
			"opencode",
			label,
			after.state === "installed" ? (update ? "updated" : "installed") : "failed",
			after.state === "installed"
				? ct("install.opencode.registered", {
						package: AIDR_OPENCODE_PACKAGE,
						version: deps.version,
					})
				: ct("install.opencode.notSeen", { detail: after.detail }),
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
			ct("install.openclaw.already"),
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
			[`  OpenClaw: ${before.remedy ?? ct("install.openclaw.enablePolicy")}.`],
		);
	}
	const binary = findExecutable("openclaw", hostEnv(deps));
	const manual = [
		`  OpenClaw: openclaw plugins install ${spec}`,
		ct("install.openclaw.thenCanary"),
	];
	if (!binary)
		return result(
			"openclaw",
			label,
			"manual",
			ct("install.notOnPath", { cli: "openclaw" }),
			before.state,
			[],
			manual,
		);
	if (dryRun)
		return result(
			"openclaw",
			label,
			"would_install",
			ct("install.wouldRun", { command: `openclaw plugins install ${spec}` }),
			before.state,
		);
	const outcome = runHost(deps, binary, ["plugins", "install", spec]);
	const after = measure(deps, "openclaw");
	const command = ct("install.ran", { command: `${binary} plugins install ${spec}` });
	if (outcome.status === 0 && after.state === "installed") {
		return result(
			"openclaw",
			label,
			"installed",
			ct("install.openclaw.installed", { spec }),
			after.state,
			[command],
			[ct("install.openclaw.canary")],
		);
	}
	return result(
		"openclaw",
		label,
		"failed",
		ct("install.openclaw.notRegistered", {
			reason: outcome.status === 0 ? after.detail : summarizeFailure(outcome),
		}),
		after.state,
		[command],
		manual,
	);
}

function installEditor(
	host: "cursor" | "vscode",
	deps: ConnectorDeps,
	dryRun: boolean,
	operatorVsix: string | undefined,
): HostInstallResult {
	const label = host === "cursor" ? "Cursor" : "VS Code";
	const before = measure(deps, host);
	const artifact = host === "cursor" ? "aidr-cursor.vsix" : "aidr-vscode.vsix";
	const cliName = EDITOR_CLIS[host];
	const enable = ct("install.editor.enable", { label });
	// The installer's own VSIX, used only once the signed bundle that lists it
	// verified; an operator-supplied --<host>-vsix always wins (and was confirmed).
	const bundled =
		!operatorVsix && deps.standaloneRoot
			? standaloneExtension(deps.standaloneRoot, artifact)
			: null;
	if (bundled) {
		const bundle = standaloneBundle(deps);
		if (!bundle.ok) return result(host, label, "failed", bundleFailure(deps, bundle), before.state);
	}
	const vsix = operatorVsix ?? bundled ?? undefined;
	if (!vsix) {
		return before.state === "installed"
			? result(
					host,
					label,
					"already_installed",
					ct("install.editor.passVsix", { detail: before.detail, host }),
					before.state,
				)
			: result(
					host,
					label,
					"manual",
					ct("install.editor.noVsix", { artifact, host }),
					before.state,
					[],
					[ct("install.editor.fromBundle", { label, cli: cliName, artifact }), enable],
				);
	}
	const file = resolve(vsix);
	if (!existsSync(file) || !statSync(file).isFile()) {
		return result(host, label, "failed", ct("install.notAFile", { path: file }), before.state);
	}
	const binary = findExecutable(cliName, hostEnv(deps));
	if (!binary) {
		return result(
			host,
			label,
			"manual",
			ct("install.notOnPath", { cli: cliName }),
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
			ct("install.wouldRun", { command: `${cliName} --install-extension ${file} --force` }),
			before.state,
		);
	const outcome = runHost(deps, binary, ["--install-extension", file, "--force"]);
	const after = measure(deps, host);
	const command = ct("install.ran", { command: `${binary} --install-extension ${file} --force` });
	if (outcome.status === 0 && after.state === "installed") {
		return result(
			host,
			label,
			update ? "updated" : "installed",
			ct("install.editor.installed", { extension: EXTENSION_IDS[host], path: file }),
			after.state,
			[command],
			[enable],
		);
	}
	return result(
		host,
		label,
		"failed",
		ct("install.editor.notRegistered", {
			reason: outcome.status === 0 ? after.detail : summarizeFailure(outcome),
		}),
		after.state,
		[command],
	);
}

/** The manual Claude Code install steps, in the current locale. */
function claudeManual(): string[] {
	return [
		ct("install.claude.manual1"),
		ct("install.claude.manual2"),
		ct("install.claude.manual3"),
		ct("install.claude.manual4"),
	];
}

function installClaude(
	deps: ConnectorDeps,
	dryRun: boolean,
	pluginDir: string | undefined,
): HostInstallResult {
	const label = "Claude Code";
	const fromPolicy = machinePolicyResult(deps, "claude-code", label);
	if (fromPolicy) return fromPolicy;
	if (!pluginDir && deps.standaloneRoot) return installClaudeStandalone(deps, dryRun);
	const before = measure(deps, "claude-code");
	if (before.state === "installed") {
		return result("claude-code", label, "already_installed", before.detail, before.state);
	}
	if (!pluginDir) {
		return result(
			"claude-code",
			label,
			"manual",
			ct("install.claude.noDir"),
			before.state,
			[],
			claudeManual(),
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
			ct("install.claude.notPlugin", { dir }),
			before.state,
		);
	}
	const binary = findExecutable("claude", hostEnv(deps));
	if (!binary)
		return result(
			"claude-code",
			label,
			"manual",
			ct("install.notOnPath", { cli: "claude" }),
			before.state,
			[],
			claudeManual(),
		);
	if (dryRun) {
		return result(
			"claude-code",
			label,
			"would_install",
			ct("install.wouldRun", {
				command: `claude plugin marketplace add ${dir}; claude plugin install aidr@aidr`,
			}),
			before.state,
		);
	}
	const changes: string[] = [];
	for (const args of [
		["plugin", "marketplace", "add", dir],
		["plugin", "install", "aidr@aidr"],
	]) {
		const outcome = runHost(deps, binary, args);
		changes.push(ct("install.ran", { command: `${binary} ${args.join(" ")}` }));
		if (outcome.status !== 0) {
			return result(
				"claude-code",
				label,
				"failed",
				ct("install.claude.cmdFailed", { args: args.join(" "), reason: summarizeFailure(outcome) }),
				measure(deps, "claude-code").state,
				changes,
				claudeManual(),
			);
		}
	}
	const after = measure(deps, "claude-code");
	return after.state === "installed"
		? result(
				"claude-code",
				label,
				"installed",
				ct("install.claude.installed"),
				after.state,
				changes,
				[ct("install.claude.restartPlugin")],
			)
		: result(
				"claude-code",
				label,
				"failed",
				ct("install.claude.notRegistered", { detail: after.detail }),
				after.state,
				changes,
				claudeManual(),
			);
}

// ── Claude Code from the standalone (SEA) bundle ─────────────────────

/**
 * Settings with every AIDR-marked hook replaced by the standalone bundle's hooks.
 * Exported so the desktop app can preview exactly what `aidr setup` will write.
 */
export function standaloneClaudeSettings(
	settings: Record<string, unknown>,
	root: string,
): Record<string, unknown> {
	if (settings.hooks !== undefined && !isPlainObject(settings.hooks)) {
		throw new Error("~/.claude/settings.json has a 'hooks' value that is not an object");
	}
	const hooks: Record<string, unknown> = { ...((settings.hooks as Record<string, unknown>) ?? {}) };
	for (const { event, hook: name, timeout } of STANDALONE_CLAUDE_HOOKS) {
		const current = hooks[event] ?? [];
		if (!Array.isArray(current)) {
			throw new Error(`~/.claude/settings.json: ${event} is not an array`);
		}
		const kept = current.flatMap((entry: unknown) => {
			if (!isPlainObject(entry) || !Array.isArray(entry.hooks)) return [entry];
			const remaining = entry.hooks.filter(
				(hook: unknown) => !isPlainObject(hook) || hook.statusMessage !== MANAGED_HOOK_MARKER,
			);
			if (remaining.length === entry.hooks.length) return [entry];
			return remaining.length > 0 ? [{ ...entry, hooks: remaining }] : [];
		});
		kept.push({
			...(event === "SessionStart" ? {} : { matcher: "*" }),
			hooks: [
				{
					type: "command",
					command: standaloneHookCommand(root, name),
					timeout,
					statusMessage: MANAGED_HOOK_MARKER,
				},
			],
		});
		hooks[event] = kept;
	}
	return { ...settings, hooks };
}

/**
 * Claude Code from the standalone bundle: verify the bundle against its
 * manifest, prove the bundle's PreToolUse binary denies the canary for this
 * home, then register the bundle's hook binaries in ~/.claude/settings.json
 * (only AIDR-marked entries change) and write the installation receipt that
 * `aidr uninstall` verifies before removing them.
 */
function installClaudeStandalone(deps: ConnectorDeps, dryRun: boolean): HostInstallResult {
	const label = "Claude Code";
	const root = deps.standaloneRoot as string;
	const before = measure(deps, "claude-code");
	const settingsPath = join(deps.home, ".claude", "settings.json");
	const receiptPath = join(deps.home, ".singularity-aidr", "installation.json");
	let settings: ReturnType<typeof readJsonObject>;
	try {
		settings = readJsonObject(settingsPath);
	} catch (error) {
		return result("claude-code", label, "manual", `${(error as Error).message}.`, before.state);
	}
	if (settings.value.disableAllHooks === true) {
		return result(
			"claude-code",
			label,
			"manual",
			ct("install.claude.disableAll"),
			before.state,
			[],
			[ct("install.claude.disableAllStep")],
		);
	}
	const plugins = settings.value.enabledPlugins;
	if (
		isPlainObject(plugins) &&
		Object.entries(plugins).some(
			([name, enabled]) => /aidr|singularity/i.test(name) && enabled === true,
		)
	) {
		return result(
			"claude-code",
			label,
			"already_installed",
			ct("install.claude.pluginEnabled"),
			before.state,
		);
	}
	const bundle = standaloneBundle(deps);
	if (!bundle.ok || !bundle.manifestSha256) {
		return result("claude-code", label, "failed", bundleFailure(deps, bundle), before.state);
	}
	let desired: Record<string, unknown>;
	try {
		desired = standaloneClaudeSettings(settings.value, root);
	} catch (error) {
		return result("claude-code", label, "manual", `${(error as Error).message}.`, before.state);
	}
	let previousReceipt: Record<string, unknown> | null = null;
	try {
		previousReceipt = readJsonObject(receiptPath).value;
	} catch {
		previousReceipt = null;
	}
	if (
		settings.raw !== null &&
		JSON.stringify(settings.value) === JSON.stringify(desired) &&
		previousReceipt?.install_kind === STANDALONE_INSTALL_KIND &&
		previousReceipt.path === root &&
		previousReceipt.artifact_sha256 === bundle.manifestSha256
	) {
		return result(
			"claude-code",
			label,
			"already_installed",
			ct("install.claude.standaloneAlready", { root }),
			before.state,
		);
	}
	const update = before.state === "installed";
	if (dryRun) {
		return result(
			"claude-code",
			label,
			update ? "would_update" : "would_install",
			ct("install.claude.wouldRegister", { root, path: settingsPath }),
			before.state,
		);
	}
	// The canary is data on the hook's stdin; nothing is executed. Its benign
	// twin must pass too: a hook that blocks everything (e.g. a release hook
	// that cannot verify its files) is not a working installation.
	const probe = probeHookCommand(
		standaloneHookCommand(root, "pre-tool-use"),
		claudePayload(deps.home),
		{ home: deps.home, cwd: deps.home, env: deps.env },
	);
	if (!probe.ok) {
		return result(
			"claude-code",
			label,
			"failed",
			ct("install.claude.probeFailed", { reason: probeFailure(probe) }),
			before.state,
		);
	}
	try {
		const changes = writeJsonWithBackup(settingsPath, desired, settings.raw, deps, "setup");
		const receipt = {
			schema_version: 1,
			installed_at: new Date((deps.now ?? Date.now)()).toISOString(),
			connector: "claude-code",
			install_kind: STANDALONE_INSTALL_KIND,
			artifact_sha256: bundle.manifestSha256,
			artifact_version: bundle.version,
			package_integrity:
				bundle.signature === "verified" ? "signature_verified" : "digests_verified_unsigned",
			path: root,
			settings_path: settingsPath,
			local_canary: "deny",
			host_execution: "unverified",
		};
		const rawReceipt = existsSync(receiptPath) ? readFileSync(receiptPath) : null;
		changes.push(...writeJsonWithBackup(receiptPath, receipt, rawReceipt, deps, "setup"));
		const after = measure(deps, "claude-code");
		return result(
			"claude-code",
			label,
			after.state === "installed" ? (update ? "updated" : "installed") : "failed",
			after.state === "installed"
				? ct("install.claude.registered", { root })
				: ct("install.claude.notSeen", { path: settingsPath, detail: after.detail }),
			after.state,
			changes,
			[ct("install.claude.restartHooks")],
		);
	} catch (error) {
		return result("claude-code", label, "failed", (error as Error).message, before.state);
	}
}

// ── Install entry point ───────────────────────────────────────────────

/** Hosts present in the home directory: the same measurement `aidr status` prints. */
function detectedHosts(deps: Pick<ConnectorDeps, "home" | "env">): HostId[] {
	return HOST_IDS.filter((host) => measure(deps, host).state !== "not_detected");
}

/**
 * Install or update the connector of every selected host. With no explicit
 * selection that is every host found in the home directory; the others are
 * reported as `skipped_not_detected`, or `skipped_not_selected` when an explicit
 * selection left out a host that is present. Never throws for a single host's failure.
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
			// Left out by --host while present: say so, never "not detected".
			return status.state !== "not_detected" && options.hosts
				? result(host, status.label, "skipped_not_selected", "", status.state)
				: result(host, status.label, "skipped_not_detected", status.detail, status.state);
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

type HostRemovalAction = "removed" | "nothing_to_remove" | "would_remove" | "manual" | "failed";

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
				changes.push(...writeJsonWithBackup(jsonPath, next, document.raw, deps, "uninstall"));
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
			ct("remove.codex.byHand"),
		]);
	}
	if (found === 0)
		return removal("codex", label, "nothing_to_remove", ct("remove.codex.none"), before.state);
	if (dryRun)
		return removal(
			"codex",
			label,
			"would_remove",
			ct("remove.codex.would", { count: found }),
			before.state,
		);
	const after = measure(deps, "codex");
	return removal(
		"codex",
		label,
		after.state === "installed" ? "failed" : "removed",
		ct("remove.codex.removed", { count: found }),
		after.state,
		changes,
		[ct("remove.codex.package")],
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
				ct("remove.opencode.none"),
				before.state,
			);
		if (dryRun)
			return removal(
				"opencode",
				label,
				"would_remove",
				ct("remove.would", { files: found.join(", ") }),
				before.state,
			);
		if (plugins?.includes(AIDR_OPENCODE_PACKAGE)) {
			const next = {
				...config.value,
				plugin: plugins.filter((entry) => entry !== AIDR_OPENCODE_PACKAGE),
			};
			changes.push(...writeJsonWithBackup(configPath, next, config.raw, deps, "uninstall"));
		}
		if (dependencies && AIDR_OPENCODE_PACKAGE in dependencies) {
			const { [AIDR_OPENCODE_PACKAGE]: _removed, ...rest } = dependencies;
			const next = { ...manifest.value, dependencies: rest };
			changes.push(...writeJsonWithBackup(manifestPath, next, manifest.raw, deps, "uninstall"));
		}
		for (const path of localFiles) {
			unlinkSync(path);
			changes.push(ct("remove.deleted", { path }));
		}
	} catch (error) {
		return removal("opencode", label, "failed", (error as Error).message, before.state, changes, [
			ct("remove.opencode.byHand", { package: AIDR_OPENCODE_PACKAGE }),
		]);
	}
	const after = measure(deps, "opencode");
	return removal(
		"opencode",
		label,
		after.state === "installed" ? "failed" : "removed",
		ct("remove.removedFrom", { files: found.join(", ") }),
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
			ct("install.notOnPath", { cli: cliName }),
			before.state,
			[],
			manual,
		);
	if (dryRun)
		return removal(
			host,
			label,
			"would_remove",
			ct("install.wouldRun", {
				command: commands.map((args) => `${cliName} ${args.join(" ")}`).join("; "),
			}),
			before.state,
		);
	const changes: string[] = [];
	let lastFailure = "";
	for (const args of commands) {
		const outcome = runHost(deps, binary, args);
		changes.push(ct("install.ran", { command: `${binary} ${args.join(" ")}` }));
		if (outcome.status !== 0) lastFailure = summarizeFailure(outcome);
	}
	const after = measure(deps, host);
	if (after.state === "installed" || after.state === "installed_but_degraded") {
		return removal(
			host,
			label,
			"failed",
			ct("remove.stillRegistered", { reason: lastFailure ? ` (${lastFailure})` : "" }),
			after.state,
			changes,
			manual,
		);
	}
	return removal(host, label, "removed", ct("remove.hostRemoved"), after.state, changes);
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
							ct("remove.claude.none"),
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
						[ct("remove.claude.manual")],
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
