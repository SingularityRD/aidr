import { spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	lstatSync,
	mkdirSync,
	readFileSync,
	renameSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { CODEX_HOOK_PATTERN, codexDesiredHooks, stripCodexHooks } from "./codex-hooks.js";
import {
	STANDALONE_CLAUDE_HOOKS,
	STANDALONE_CODEX_HOOK,
	standaloneHookCommand,
} from "./standalone.js";

/**
 * System-wide ("machine policy") hook deployment for the hosts that load hooks
 * from a root-owned location and do not let a user switch them off.
 *
 * ## Why this exists (C10)
 *
 * `aidr setup` registers hooks in the user's own files (~/.claude/settings.json,
 * ~/.codex/hooks.json, the editor's hooks file). The user can delete those
 * entries, set `disableAllHooks`, run the editor's "Disable protection" command,
 * or simply never trust the Codex hook, and nobody is told. A per-machine
 * install (MSI / .deb / .rpm, run as administrator) can instead place the hooks
 * where the host reads organisation policy:
 *
 * - **Claude Code** reads `managed-settings.json` plus every `*.json` drop-in in
 *   `managed-settings.d/` from `/etc/claude-code/` (Linux, WSL) or
 *   `C:\Program Files\ClaudeCode\` (Windows). Managed hooks always run: a user's
 *   `disableAllHooks` does not turn them off, and only managed settings can.
 *   With `--lock-other-hooks` the drop-in also sets `allowManagedHooksOnly`, so
 *   user, project and plugin hooks stop loading.
 *   Verified against https://code.claude.com/docs/en/managed-settings and
 *   /docs/en/settings-reference (2026-10-14).
 * - **Codex** loads the system config layer `/etc/codex/` (Unix) or
 *   `%ProgramData%\OpenAI\Codex\` (Windows), including its `hooks.json`, and
 *   treats hooks from that layer as managed: trusted without `/hooks` review and
 *   not disableable from user config. `--lock-other-hooks` adds
 *   `allow_managed_hooks_only = true` to the system `requirements.toml`.
 *   Verified in the codex-rs source at rust-v0.141.0 (hooks/src/engine/
 *   discovery.rs `hook_metadata_for_config_layer_source`, config/src/loader).
 *
 * Cursor reads an enterprise `hooks.json` (`/etc/cursor/hooks.json` is
 * corroborated by Cursor's own log output; the Windows path is only reported by
 * third parties), but AIDR's Cursor hook runner ships inside the per-user
 * extension, so there is no machine-wide command to register yet. VS Code has
 * no system-wide hook location; its Local hooks read the Claude settings files.
 * Both editors are covered by the machine-policy protection lock and the
 * heartbeat instead (docs/operations/hook-tamper-resistance.md).
 *
 * The files written here are owned entirely by AIDR (Claude drop-in) or merged
 * so that only AIDR's handlers change (Codex hooks.json). Nothing here can
 * replace the host's own fail-open behaviour for a crashed or killed hook.
 */

type MachineHookHost = "claude-code" | "codex";

export interface MachineHookPaths {
	/** Claude Code managed-settings drop-in owned by AIDR. */
	claudeDropIn: string;
	/** Codex system-layer hooks.json. */
	codexHooks: string;
	/** Codex system requirements.toml (admin-enforced constraints). */
	codexRequirements: string;
	/** Cursor enterprise hooks.json (read-only here: reported, never written). */
	cursorHooks: string;
	/** systemd user units (Linux) for the hourly heartbeat. */
	systemdUserDir: string;
}

/** Marker in the Claude drop-in (statusMessage) and the Codex requirements line. */
export const MACHINE_HOOK_MARKER = "Singularity AIDR machine policy";
const CLAUDE_DROP_IN_NAME = "50-singularity-aidr.json";
const CODEX_REQUIREMENTS_LINE = `allow_managed_hooks_only = true # ${MACHINE_HOOK_MARKER}`;
const HEARTBEAT_UNIT = "aidr-heartbeat";
const WINDOWS_HEARTBEAT_TASK = "\\Singularity AIDR\\Heartbeat";

/** The system locations each host reads policy from on this platform. */
export function machineHookPaths(
	platform: NodeJS.Platform = process.platform,
	env: NodeJS.ProcessEnv = process.env,
): MachineHookPaths {
	if (platform === "win32") {
		// Claude Code reads the fixed C:\Program Files\ClaudeCode path (the
		// legacy ProgramData location is ignored).
		const programData = env.ProgramData?.trim() || "C:\\ProgramData";
		return {
			claudeDropIn: `C:\\Program Files\\ClaudeCode\\managed-settings.d\\${CLAUDE_DROP_IN_NAME}`,
			codexHooks: `${programData}\\OpenAI\\Codex\\hooks.json`,
			codexRequirements: `${programData}\\OpenAI\\Codex\\requirements.toml`,
			cursorHooks: `${programData}\\Cursor\\hooks.json`,
			systemdUserDir: "",
		};
	}
	if (platform === "darwin") {
		return {
			claudeDropIn: `/Library/Application Support/ClaudeCode/managed-settings.d/${CLAUDE_DROP_IN_NAME}`,
			codexHooks: "/etc/codex/hooks.json",
			codexRequirements: "/etc/codex/requirements.toml",
			cursorHooks: "/Library/Application Support/Cursor/hooks.json",
			systemdUserDir: "",
		};
	}
	return {
		claudeDropIn: `/etc/claude-code/managed-settings.d/${CLAUDE_DROP_IN_NAME}`,
		codexHooks: "/etc/codex/hooks.json",
		codexRequirements: "/etc/codex/requirements.toml",
		cursorHooks: "/etc/cursor/hooks.json",
		systemdUserDir: "/etc/systemd/user",
	};
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readJson(path: string): {
	value: Record<string, unknown> | null;
	raw: string | null;
	error?: string;
} {
	let raw: string;
	try {
		const info = lstatSync(path);
		if (info.isSymbolicLink() || !info.isFile())
			return { value: null, raw: null, error: `${path} is not a regular file` };
		raw = readFileSync(path, "utf8");
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		if (code === "ENOENT" || code === "ENOTDIR") return { value: null, raw: null };
		return { value: null, raw: null, error: `${path} could not be read (${code ?? "error"})` };
	}
	try {
		const parsed = JSON.parse(raw);
		return isPlainObject(parsed)
			? { value: parsed, raw }
			: { value: null, raw, error: `${path} is not a JSON object` };
	} catch {
		return { value: null, raw, error: `${path} is not valid JSON` };
	}
}

/** The Claude Code drop-in: AIDR's hooks, and optionally the managed-hooks-only lock. */
export function claudeMachineDocument(
	root: string,
	options: { lockOtherHooks: boolean; platform?: NodeJS.Platform },
): Record<string, unknown> {
	const hooks: Record<string, unknown> = {};
	for (const { event, hook, timeout } of STANDALONE_CLAUDE_HOOKS) {
		hooks[event] = [
			{
				...(event === "SessionStart" ? {} : { matcher: "*" }),
				hooks: [
					{
						type: "command",
						command: standaloneHookCommand(root, hook, options.platform),
						timeout,
						statusMessage: MACHINE_HOOK_MARKER,
					},
				],
			},
		];
	}
	return { hooks, ...(options.lockOtherHooks ? { allowManagedHooksOnly: true } : {}) };
}

/** True when a parsed drop-in is AIDR's (every hook carries the machine marker). */
function isAidrClaudeDropIn(value: Record<string, unknown> | null): boolean {
	if (!value || !isPlainObject(value.hooks)) return false;
	const pre = (value.hooks as Record<string, unknown>).PreToolUse;
	return (
		Array.isArray(pre) &&
		pre.some(
			(entry) =>
				isPlainObject(entry) &&
				Array.isArray(entry.hooks) &&
				entry.hooks.some(
					(hook) => isPlainObject(hook) && hook.statusMessage === MACHINE_HOOK_MARKER,
				),
		)
	);
}

function codexHasAidr(value: Record<string, unknown> | null): boolean {
	if (!value || !isPlainObject(value.hooks)) return false;
	const pre = (value.hooks as Record<string, unknown>).PreToolUse;
	return (
		Array.isArray(pre) &&
		pre.some(
			(entry) =>
				isPlainObject(entry) &&
				Array.isArray(entry.hooks) &&
				entry.hooks.some(
					(hook) =>
						isPlainObject(hook) &&
						typeof hook.command === "string" &&
						CODEX_HOOK_PATTERN.test(hook.command),
				),
		)
	);
}

/** Whether a POSIX file and its directory can only be changed by root. Null where not measurable. */
function rootOnlyWritable(
	path: string,
	platform: NodeJS.Platform = process.platform,
): boolean | null {
	if (platform === "win32") return null;
	try {
		for (const target of [path, dirname(path)]) {
			const info = statSync(target);
			if (info.uid !== 0 || (info.mode & 0o022) !== 0) return false;
		}
		return true;
	} catch {
		return null;
	}
}

export interface MachineHookState {
	host: MachineHookHost;
	path: string;
	/** AIDR's hooks are present in the host's system-wide policy file. */
	registered: boolean;
	/** Other (user/project/plugin) hooks are blocked by the host. */
	otherHooksLocked: boolean;
	/** The file and its directory can only be changed by an administrator (null: not measured). */
	tamperResistant: boolean | null;
	problems: string[];
}

export interface MachineHookDeps {
	platform?: NodeJS.Platform;
	env?: NodeJS.ProcessEnv;
	/** Override the system locations (tests). */
	paths?: Partial<MachineHookPaths>;
}

function resolvedPaths(deps: MachineHookDeps): MachineHookPaths {
	return { ...machineHookPaths(deps.platform, deps.env), ...deps.paths };
}

/** Measure the machine-policy registration of every supported host. Never writes. */
export function machineHookStatus(deps: MachineHookDeps = {}): MachineHookState[] {
	const paths = resolvedPaths(deps);
	const platform = deps.platform ?? process.platform;
	const claude = readJson(paths.claudeDropIn);
	const codex = readJson(paths.codexHooks);
	const claudeRegistered = isAidrClaudeDropIn(claude.value);
	const codexRegistered = codexHasAidr(codex.value);
	let requirements = "";
	try {
		requirements = readFileSync(paths.codexRequirements, "utf8");
	} catch {
		requirements = "";
	}
	return [
		{
			host: "claude-code",
			path: paths.claudeDropIn,
			registered: claudeRegistered,
			otherHooksLocked: claudeRegistered && claude.value?.allowManagedHooksOnly === true,
			tamperResistant: claudeRegistered ? rootOnlyWritable(paths.claudeDropIn, platform) : null,
			problems: claude.error ? [claude.error] : [],
		},
		{
			host: "codex",
			path: paths.codexHooks,
			registered: codexRegistered,
			otherHooksLocked: /^\s*allow_managed_hooks_only\s*=\s*true\b/m.test(requirements),
			tamperResistant: codexRegistered ? rootOnlyWritable(paths.codexHooks, platform) : null,
			problems: codex.error ? [codex.error] : [],
		},
	];
}

type MachineHookAction =
	| "installed"
	| "updated"
	| "already_installed"
	| "removed"
	| "nothing_to_remove"
	| "would_install"
	| "would_remove"
	| "failed";

export interface MachineHookResult {
	host: MachineHookHost | "heartbeat";
	action: MachineHookAction;
	path: string;
	detail: string;
	changes: string[];
}

/** Write a world-readable, admin-owned file atomically (the host runs as every user). */
function writeSystemFile(path: string, content: string): void {
	mkdirSync(dirname(path), { recursive: true, mode: 0o755 });
	const temporary = `${path}.aidr-${process.pid}.tmp`;
	writeFileSync(temporary, content, { flag: "w", mode: 0o644 });
	try {
		chmodSync(temporary, 0o644);
		renameSync(temporary, path);
	} catch (error) {
		try {
			unlinkSync(temporary);
		} catch {
			/* nothing left behind */
		}
		throw error;
	}
}

function failure(host: MachineHookResult["host"], path: string, error: unknown): MachineHookResult {
	const code = (error as NodeJS.ErrnoException).code;
	const detail =
		code === "EACCES" || code === "EPERM"
			? `${path} needs administrator rights; run this command as root (Linux) or from an elevated prompt (Windows).`
			: (error as Error).message;
	return { host, action: "failed", path, detail, changes: [] };
}

function installClaude(
	paths: MachineHookPaths,
	root: string,
	options: { lockOtherHooks: boolean; dryRun: boolean; platform?: NodeJS.Platform },
): MachineHookResult {
	const path = paths.claudeDropIn;
	const current = readJson(path);
	if (current.raw !== null && !isAidrClaudeDropIn(current.value)) {
		return {
			host: "claude-code",
			action: "failed",
			path,
			detail: `${path} exists and is not AIDR's drop-in; it was left untouched.`,
			changes: [],
		};
	}
	const desired = `${JSON.stringify(claudeMachineDocument(root, options), null, 2)}\n`;
	if (current.raw === desired) {
		return {
			host: "claude-code",
			action: "already_installed",
			path,
			detail: `AIDR hooks already in ${path}.`,
			changes: [],
		};
	}
	if (options.dryRun) {
		return {
			host: "claude-code",
			action: "would_install",
			path,
			detail: `would write ${path}.`,
			changes: [],
		};
	}
	try {
		writeSystemFile(path, desired);
	} catch (error) {
		return failure("claude-code", path, error);
	}
	return {
		host: "claude-code",
		action: current.raw === null ? "installed" : "updated",
		path,
		detail: `wrote ${path}${options.lockOtherHooks ? " (allowManagedHooksOnly: only managed hooks run)" : ""}.`,
		changes: [`wrote ${path}`],
	};
}

function codexRequirementsWithLock(raw: string | null, lock: boolean): string | null {
	const lines = (raw ?? "").split(/\r?\n/);
	const withoutOurs = lines.filter((line) => line.trim() !== CODEX_REQUIREMENTS_LINE);
	if (!lock) {
		if (raw === null || withoutOurs.length === lines.length) return raw;
		const next = withoutOurs.join("\n");
		return next.trim() === "" ? "" : next;
	}
	// An administrator's own setting wins; never add a second key.
	if (withoutOurs.some((line) => /^\s*allow_managed_hooks_only\s*=/.test(line))) return raw;
	if (raw !== null && withoutOurs.length !== lines.length) return raw;
	// Top-level keys must precede the first table, so the line goes first.
	return `${CODEX_REQUIREMENTS_LINE}\n${raw ?? ""}`;
}

function installCodex(
	paths: MachineHookPaths,
	root: string,
	options: { lockOtherHooks: boolean; dryRun: boolean; platform?: NodeJS.Platform },
): MachineHookResult {
	const path = paths.codexHooks;
	const current = readJson(path);
	if (current.error) {
		return {
			host: "codex",
			action: "failed",
			path,
			detail: `${current.error}; it was left untouched.`,
			changes: [],
		};
	}
	const existingHooks = current.value?.hooks;
	if (existingHooks !== undefined && !isPlainObject(existingHooks)) {
		return {
			host: "codex",
			action: "failed",
			path,
			detail: `${path} has a 'hooks' value that is not an object.`,
			changes: [],
		};
	}
	const command = standaloneHookCommand(root, STANDALONE_CODEX_HOOK, options.platform);
	const desired = `${JSON.stringify({ ...(current.value ?? {}), hooks: codexDesiredHooks(existingHooks ?? {}, command) }, null, 2)}\n`;
	let requirementsRaw: string | null = null;
	try {
		requirementsRaw = readFileSync(paths.codexRequirements, "utf8");
	} catch {
		requirementsRaw = null;
	}
	const requirements = codexRequirementsWithLock(requirementsRaw, options.lockOtherHooks);
	const hooksChanged = current.raw !== desired;
	const requirementsChanged = requirements !== requirementsRaw;
	if (!hooksChanged && !requirementsChanged) {
		return {
			host: "codex",
			action: "already_installed",
			path,
			detail: `AIDR hooks already in ${path}.`,
			changes: [],
		};
	}
	if (options.dryRun) {
		return {
			host: "codex",
			action: "would_install",
			path,
			detail: `would update ${path}.`,
			changes: [],
		};
	}
	const changes: string[] = [];
	try {
		if (hooksChanged) {
			writeSystemFile(path, desired);
			changes.push(`wrote ${path}`);
		}
		if (requirementsChanged && requirements !== null) {
			writeSystemFile(paths.codexRequirements, requirements);
			changes.push(`wrote ${paths.codexRequirements}`);
		}
	} catch (error) {
		return failure("codex", path, error);
	}
	return {
		host: "codex",
		action: current.raw === null ? "installed" : "updated",
		path,
		detail: `registered ${STANDALONE_CODEX_HOOK} in the Codex system layer ${path} (managed: trusted without /hooks review)${options.lockOtherHooks ? "; only managed hooks run" : ""}.`,
		changes,
	};
}

export interface MachineInstallOptions {
	/** Root of the installed standalone bundle whose hook binaries the hosts run. */
	bundleRoot: string;
	lockOtherHooks?: boolean;
	dryRun?: boolean;
	hosts?: readonly MachineHookHost[];
}

/** Register AIDR's hooks in every selected host's system-wide policy. */
export function installMachineHooks(
	options: MachineInstallOptions,
	deps: MachineHookDeps = {},
): MachineHookResult[] {
	const paths = resolvedPaths(deps);
	const hosts = options.hosts ?? (["claude-code", "codex"] as const);
	const settings = {
		lockOtherHooks: options.lockOtherHooks === true,
		dryRun: options.dryRun === true,
		platform: deps.platform,
	};
	return hosts.map((host) =>
		host === "claude-code"
			? installClaude(paths, options.bundleRoot, settings)
			: installCodex(paths, options.bundleRoot, settings),
	);
}

/** Remove only AIDR's machine-policy registrations; everything else is kept. */
export function removeMachineHooks(
	options: { dryRun?: boolean } = {},
	deps: MachineHookDeps = {},
): MachineHookResult[] {
	const paths = resolvedPaths(deps);
	const results: MachineHookResult[] = [];
	const claude = readJson(paths.claudeDropIn);
	if (claude.raw === null || !isAidrClaudeDropIn(claude.value)) {
		results.push({
			host: "claude-code",
			action: "nothing_to_remove",
			path: paths.claudeDropIn,
			detail: "no AIDR drop-in.",
			changes: [],
		});
	} else if (options.dryRun) {
		results.push({
			host: "claude-code",
			action: "would_remove",
			path: paths.claudeDropIn,
			detail: `would delete ${paths.claudeDropIn}.`,
			changes: [],
		});
	} else {
		try {
			unlinkSync(paths.claudeDropIn);
			results.push({
				host: "claude-code",
				action: "removed",
				path: paths.claudeDropIn,
				detail: `deleted ${paths.claudeDropIn}.`,
				changes: [`deleted ${paths.claudeDropIn}`],
			});
		} catch (error) {
			results.push(failure("claude-code", paths.claudeDropIn, error));
		}
	}

	const codex = readJson(paths.codexHooks);
	let requirementsRaw: string | null = null;
	try {
		requirementsRaw = readFileSync(paths.codexRequirements, "utf8");
	} catch {
		requirementsRaw = null;
	}
	const requirements = codexRequirementsWithLock(requirementsRaw, false);
	const hooks =
		codex.value && isPlainObject(codex.value.hooks)
			? stripCodexHooks(codex.value.hooks as Record<string, unknown>)
			: null;
	if ((!hooks || hooks.removed === 0) && requirements === requirementsRaw) {
		results.push({
			host: "codex",
			action: "nothing_to_remove",
			path: paths.codexHooks,
			detail: "no AIDR handler.",
			changes: [],
		});
	} else if (options.dryRun) {
		results.push({
			host: "codex",
			action: "would_remove",
			path: paths.codexHooks,
			detail: `would remove AIDR's handlers from ${paths.codexHooks}.`,
			changes: [],
		});
	} else {
		const changes: string[] = [];
		try {
			if (hooks && hooks.removed > 0 && codex.value) {
				writeSystemFile(
					paths.codexHooks,
					`${JSON.stringify({ ...codex.value, hooks: hooks.hooks }, null, 2)}\n`,
				);
				changes.push(`removed ${hooks.removed} AIDR handler(s) from ${paths.codexHooks}`);
			}
			if (requirements !== requirementsRaw && requirements !== null) {
				writeSystemFile(paths.codexRequirements, requirements);
				changes.push(`removed the AIDR lock line from ${paths.codexRequirements}`);
			}
			results.push({
				host: "codex",
				action: "removed",
				path: paths.codexHooks,
				detail: changes.join("; "),
				changes,
			});
		} catch (error) {
			results.push(failure("codex", paths.codexHooks, error));
		}
	}
	return results;
}

// ── Heartbeat schedule ──────────────────────────────────────────────────

/** Command runner for systemctl / schtasks; injectable so tests never touch the host. */
export type ScheduleRunner = (
	command: string,
	args: readonly string[],
) => { status: number | null; stderr?: string };

const defaultScheduleRunner: ScheduleRunner = (command, args) => {
	const result = spawnSync(command, [...args], {
		encoding: "utf8",
		timeout: 60_000,
		windowsHide: true,
	});
	return { status: result.status, stderr: result.stderr ?? result.error?.message ?? "" };
};

function heartbeatCommand(root: string, platform: NodeJS.Platform): string {
	return platform === "win32" ? join(root, "bin", "aidr.exe") : join(root, "bin", "aidr");
}

/** systemd user units that run `aidr heartbeat` hourly in every user session. */
function systemdHeartbeatUnits(root: string): { service: string; timer: string } {
	const binary = heartbeatCommand(root, "linux");
	return {
		service: [
			"[Unit]",
			"Description=Singularity AIDR connector heartbeat (reports whether each AI tool's AIDR hook is in place)",
			"",
			"[Service]",
			"Type=oneshot",
			`ExecStart="${binary}" heartbeat --quiet`,
			"",
		].join("\n"),
		timer: [
			"[Unit]",
			"Description=Hourly Singularity AIDR connector heartbeat",
			"",
			"[Timer]",
			"OnStartupSec=5min",
			"OnUnitActiveSec=1h",
			"RandomizedDelaySec=10min",
			"Persistent=true",
			"",
			"[Install]",
			"WantedBy=timers.target",
			"",
		].join("\n"),
	};
}

/**
 * Task Scheduler definition: hourly and at logon, for whichever member of
 * BUILTIN\Users is logged on (S-1-5-32-545, interactive token), so each user's
 * own hosts are measured with that user's files.
 */
export function windowsHeartbeatTaskXml(root: string): string {
	const binary = heartbeatCommand(root, "win32").replaceAll("&", "&amp;").replaceAll("<", "&lt;");
	return [
		'<?xml version="1.0" encoding="UTF-16"?>',
		'<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
		"  <RegistrationInfo><Description>Singularity AIDR connector heartbeat</Description></RegistrationInfo>",
		"  <Triggers>",
		"    <LogonTrigger><Enabled>true</Enabled><Delay>PT5M</Delay></LogonTrigger>",
		"    <TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>true</Enabled>",
		"      <Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>",
		"      <RandomDelay>PT10M</RandomDelay></TimeTrigger>",
		"  </Triggers>",
		'  <Principals><Principal id="Users"><GroupId>S-1-5-32-545</GroupId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>',
		"  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><StartWhenAvailable>true</StartWhenAvailable>",
		"    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit><Hidden>true</Hidden></Settings>",
		'  <Actions Context="Users"><Exec>',
		`    <Command>${binary}</Command><Arguments>heartbeat --quiet</Arguments>`,
		"  </Exec></Actions>",
		"</Task>",
		"",
	].join("\r\n");
}

export interface ScheduleDeps extends MachineHookDeps {
	run?: ScheduleRunner;
	/** Where the Windows task XML is staged before schtasks reads it. */
	stagingDir?: string;
}

/** Install (or with `remove`, delete) the hourly heartbeat for every user of the machine. */
export function scheduleHeartbeat(
	options: { bundleRoot: string; remove?: boolean; dryRun?: boolean },
	deps: ScheduleDeps = {},
): MachineHookResult {
	const platform = deps.platform ?? process.platform;
	const run = deps.run ?? defaultScheduleRunner;
	const paths = resolvedPaths(deps);
	if (platform === "win32") {
		if (options.dryRun) {
			return {
				host: "heartbeat",
				action: options.remove ? "would_remove" : "would_install",
				path: WINDOWS_HEARTBEAT_TASK,
				detail: `would ${options.remove ? "delete" : "register"} the scheduled task ${WINDOWS_HEARTBEAT_TASK}.`,
				changes: [],
			};
		}
		if (options.remove) {
			const outcome = run("schtasks", ["/Delete", "/TN", WINDOWS_HEARTBEAT_TASK, "/F"]);
			return outcome.status === 0
				? {
						host: "heartbeat",
						action: "removed",
						path: WINDOWS_HEARTBEAT_TASK,
						detail: `deleted ${WINDOWS_HEARTBEAT_TASK}.`,
						changes: [`schtasks /Delete ${WINDOWS_HEARTBEAT_TASK}`],
					}
				: {
						host: "heartbeat",
						action: "nothing_to_remove",
						path: WINDOWS_HEARTBEAT_TASK,
						detail: "no scheduled heartbeat task.",
						changes: [],
					};
		}
		const staging = join(
			deps.stagingDir ?? ((deps.env ?? process.env).ProgramData?.trim() || "C:\\ProgramData"),
			"Singularity AIDR",
		);
		const xmlPath = join(staging, "aidr-heartbeat-task.xml");
		try {
			mkdirSync(staging, { recursive: true });
			// UTF-16LE with BOM, as the XML declaration says.
			writeFileSync(
				xmlPath,
				Buffer.concat([
					Buffer.from([0xff, 0xfe]),
					Buffer.from(windowsHeartbeatTaskXml(options.bundleRoot), "utf16le"),
				]),
			);
		} catch (error) {
			return failure("heartbeat", xmlPath, error);
		}
		const outcome = run("schtasks", [
			"/Create",
			"/TN",
			WINDOWS_HEARTBEAT_TASK,
			"/XML",
			xmlPath,
			"/F",
		]);
		return outcome.status === 0
			? {
					host: "heartbeat",
					action: "installed",
					path: WINDOWS_HEARTBEAT_TASK,
					detail: `registered ${WINDOWS_HEARTBEAT_TASK} (hourly and at logon, for every user).`,
					changes: [`schtasks /Create ${WINDOWS_HEARTBEAT_TASK}`],
				}
			: {
					host: "heartbeat",
					action: "failed",
					path: WINDOWS_HEARTBEAT_TASK,
					detail: `schtasks failed: ${(outcome.stderr ?? "").trim().slice(0, 200) || `exit ${outcome.status}`}`,
					changes: [],
				};
	}
	if (!paths.systemdUserDir) {
		return {
			host: "heartbeat",
			action: "failed",
			path: "",
			detail:
				"no system-wide scheduler location on this platform; schedule 'aidr heartbeat' with your device management tool.",
			changes: [],
		};
	}
	const service = join(paths.systemdUserDir, `${HEARTBEAT_UNIT}.service`);
	const timer = join(paths.systemdUserDir, `${HEARTBEAT_UNIT}.timer`);
	if (options.remove) {
		if (!existsSync(service) && !existsSync(timer)) {
			return {
				host: "heartbeat",
				action: "nothing_to_remove",
				path: timer,
				detail: "no heartbeat units.",
				changes: [],
			};
		}
		if (options.dryRun)
			return {
				host: "heartbeat",
				action: "would_remove",
				path: timer,
				detail: `would delete ${timer} and ${service}.`,
				changes: [],
			};
		run("systemctl", ["--global", "disable", `${HEARTBEAT_UNIT}.timer`]);
		const changes: string[] = [];
		for (const file of [timer, service]) {
			try {
				unlinkSync(file);
				changes.push(`deleted ${file}`);
			} catch {
				/* already gone */
			}
		}
		return {
			host: "heartbeat",
			action: "removed",
			path: timer,
			detail: changes.join("; "),
			changes,
		};
	}
	const units = systemdHeartbeatUnits(options.bundleRoot);
	const same = (file: string, content: string) => {
		try {
			return readFileSync(file, "utf8") === content;
		} catch {
			return false;
		}
	};
	if (same(service, units.service) && same(timer, units.timer)) {
		return {
			host: "heartbeat",
			action: "already_installed",
			path: timer,
			detail: `${timer} already installed.`,
			changes: [],
		};
	}
	if (options.dryRun)
		return {
			host: "heartbeat",
			action: "would_install",
			path: timer,
			detail: `would write ${timer} and ${service}.`,
			changes: [],
		};
	try {
		writeSystemFile(service, units.service);
		writeSystemFile(timer, units.timer);
	} catch (error) {
		return failure("heartbeat", timer, error);
	}
	const enabled = run("systemctl", ["--global", "enable", `${HEARTBEAT_UNIT}.timer`]);
	return {
		host: "heartbeat",
		action: "installed",
		path: timer,
		detail:
			enabled.status === 0
				? `installed ${timer} for every user session (starts at the next login).`
				: `wrote ${timer}, but 'systemctl --global enable' failed (${(enabled.stderr ?? "").trim().slice(0, 160) || `exit ${enabled.status}`}); enable it with your device management tool.`,
		changes: [`wrote ${service}`, `wrote ${timer}`],
	};
}
