import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { standaloneClaudeSettings } from "../../../cli/src/utils/connector-install.js";
import { type MachineHookState, machineHookStatus } from "../../../cli/src/utils/machine-hooks.js";
import {
	STANDALONE_CLAUDE_HOOKS,
	standaloneHookCommand,
} from "../../../cli/src/utils/standalone.js";
import type { ActionResult, ConnectPreview, Lang } from "../shared/contract.js";
import { lineDiff } from "./diff.js";
import type { Runner } from "./exec.js";
import { aidrHooks, parseHookCommand, readSettingsObject } from "./hooks.js";
import { claudeSettingsPath, receiptPath, runtimeBinary } from "./paths.js";
import { checkRuntime, ensureInstalledRuntime, installedRuntimeDir } from "./runtime.js";

/**
 * Connecting and disconnecting Claude Code.
 *
 * Nothing here edits `~/.claude/settings.json` itself. Connecting runs
 * `aidr setup --host claude-code` from the per-user runtime copy, which is the
 * supported installation path of the standalone bundle (the same code the
 * product's desktop installers run): it verifies the bundle, proves the hook
 * denies a canary and allows a harmless command, backs the settings up,
 * replaces only AIDR-marked hooks and writes the installation receipt.
 * Disconnecting runs `aidr uninstall --hooks-only`, which verifies that receipt
 * and removes only the hooks carrying AIDR's marker, again with a backup.
 *
 * The preview is computed with the CLI's own `standaloneClaudeSettings`, the
 * function `aidr setup` uses to build the document it writes.
 */

export interface ClaudeDeps {
	home: string;
	/** The AIDR runtime shipped with the app. */
	bundledRuntime: string;
	run: Runner;
	language: Lang;
	/** System-wide hook registrations (tests); default: measured by the CLI. */
	machine?: readonly MachineHookState[];
	env?: NodeJS.ProcessEnv;
}

function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorText(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

/** What `aidr setup --host claude-code` would write, without writing anything. */
export function previewConnect(deps: ClaudeDeps): ConnectPreview {
	const settingsPath = claudeSettingsPath(deps.home);
	const check = checkRuntime(deps.bundledRuntime);
	const base = {
		settingsPath,
		settingsExists: existsSync(settingsPath),
		runtimeRoot: "",
		changed: false,
		diff: [],
		commands: [],
	};
	if (!check.ok || !check.manifestSha256) {
		return {
			...base,
			blocker: `The AIDR runtime shipped with the app failed verification: ${check.problems.slice(0, 2).join("; ")}`,
		};
	}
	const root = installedRuntimeDir(deps.home, check);
	const commands = STANDALONE_CLAUDE_HOOKS.map(({ hook }) => standaloneHookCommand(root, hook));
	const machine = (deps.machine ?? machineHookStatus()).find((entry) => entry.host === "claude-code");
	if (machine?.registered) {
		return {
			...base,
			runtimeRoot: root,
			commands,
			blocker: `AIDR hooks are already deployed for every user by machine policy (${machine.path}); the user settings are left as they are.`,
		};
	}
	let raw = "";
	let settings: Record<string, unknown> = {};
	try {
		if (base.settingsExists) {
			raw = readFileSync(settingsPath, "utf8");
			const parsed: unknown = JSON.parse(raw);
			if (!isObject(parsed)) throw new Error(`${settingsPath} is not a JSON object`);
			settings = parsed;
		}
	} catch (error) {
		return {
			...base,
			runtimeRoot: root,
			commands,
			blocker: `${settingsPath} cannot be read as JSON (${errorText(error)}); it will not be changed.`,
		};
	}
	if (settings.disableAllHooks === true) {
		return {
			...base,
			runtimeRoot: root,
			commands,
			blocker:
				'Claude Code has "disableAllHooks": true in its settings, so no hook would run. Remove it first.',
		};
	}
	const plugins = settings.enabledPlugins;
	if (
		isObject(plugins) &&
		Object.entries(plugins).some(([name, on]) => /aidr|singularity/i.test(name) && on === true)
	) {
		return {
			...base,
			runtimeRoot: root,
			commands,
			blocker:
				"The AIDR Claude Code plugin is already enabled; adding the hooks as well would inspect every call twice.",
		};
	}
	let desired: Record<string, unknown>;
	try {
		desired = standaloneClaudeSettings(settings, root);
	} catch (error) {
		return { ...base, runtimeRoot: root, commands, blocker: `${errorText(error)}.` };
	}
	const after = `${JSON.stringify(desired, null, 2)}\n`;
	return {
		...base,
		runtimeRoot: root,
		commands,
		blocker: null,
		changed: raw !== after,
		diff: lineDiff(raw, after),
	};
}

/** True when settings register a PreToolUse hook that runs from `root`. */
function hookRunsFrom(home: string, root: string): boolean {
	let settings: Record<string, unknown> | null;
	try {
		settings = readSettingsObject(claudeSettingsPath(home));
	} catch {
		return false;
	}
	const expected = resolve(runtimeBinary(root)).toLowerCase();
	return aidrHooks(settings, "PreToolUse").some((hook) => {
		const parsed = parseHookCommand(hook.command);
		return parsed !== null && resolve(parsed.file).toLowerCase() === expected;
	});
}

function cliEnv(deps: ClaudeDeps, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
	return { ...(deps.env ?? process.env), AIDR_LOCALE: deps.language, ...extra };
}

function output(result: { stdout: string; stderr: string; error: string | null }): string {
	return [result.stdout.trim(), result.stderr.trim(), result.error ?? ""].filter(Boolean).join("\n");
}

export async function connectClaude(deps: ClaudeDeps): Promise<ActionResult> {
	let root: string;
	try {
		root = ensureInstalledRuntime(deps.bundledRuntime, deps.home).root;
	} catch (error) {
		return { ok: false, message: errorText(error), log: "" };
	}
	const result = await deps.run(runtimeBinary(root), ["setup", "--host", "claude-code"], {
		cwd: deps.home,
		env: cliEnv(deps),
		timeoutMs: 180_000,
	});
	const log = output(result);
	const registered = hookRunsFrom(deps.home, root);
	let receiptMatches = false;
	try {
		const receipt = JSON.parse(readFileSync(receiptPath(deps.home), "utf8")) as { path?: unknown };
		receiptMatches =
			typeof receipt.path === "string" && resolve(receipt.path).toLowerCase() === resolve(root).toLowerCase();
	} catch {
		receiptMatches = false;
	}
	if (result.exitCode === 0 && registered && receiptMatches) {
		return {
			ok: true,
			message: `Claude Code is connected: the AIDR hooks run from ${root}. Restart Claude Code so it loads them.`,
			log,
		};
	}
	return {
		ok: false,
		message: registered
			? `aidr setup exited with ${result.exitCode ?? result.error}; see the details.`
			: `The AIDR hooks were not registered (aidr setup exited with ${result.exitCode ?? result.error}); see the details.`,
		log,
	};
}

interface UninstallJson {
	outcome?: string;
	backup_path?: string | null;
	removed?: Array<{ event?: string }>;
	reason?: { code?: string; detail?: string };
}

export async function disconnectClaude(deps: ClaudeDeps): Promise<ActionResult> {
	// Any copy of the binary can run the removal; prefer the one the hooks use.
	let binary = runtimeBinary(deps.bundledRuntime);
	try {
		const receipt = JSON.parse(readFileSync(receiptPath(deps.home), "utf8")) as { path?: unknown };
		if (typeof receipt.path === "string" && existsSync(runtimeBinary(receipt.path))) {
			binary = runtimeBinary(receipt.path);
		}
	} catch {
		// No receipt: the bundled binary reports the refusal itself.
	}
	// The user confirmed in the app; the CLI's operator confirmation for
	// automation is `--yes` plus AIDR_OPERATOR_NONINTERACTIVE=1.
	const result = await deps.run(binary, ["uninstall", "--hooks-only", "--yes", "--json"], {
		cwd: deps.home,
		env: cliEnv(deps, { AIDR_OPERATOR_NONINTERACTIVE: "1" }),
		timeoutMs: 120_000,
	});
	const log = output(result);
	let report: UninstallJson | null = null;
	try {
		const start = result.stdout.indexOf("{");
		report = start >= 0 ? (JSON.parse(result.stdout.slice(start)) as UninstallJson) : null;
	} catch {
		report = null;
	}
	let remaining = 0;
	try {
		remaining = aidrHooks(readSettingsObject(claudeSettingsPath(deps.home)), "PreToolUse").filter(
			(hook) => hook.managed,
		).length;
	} catch {
		remaining = -1;
	}
	if (report?.outcome === "removed" && remaining === 0) {
		return {
			ok: true,
			message: `Removed ${report.removed?.length ?? 0} AIDR hook registration(s). Claude Code is no longer protected.`,
			log,
			backupPath: report.backup_path ?? null,
		};
	}
	if (report?.outcome === "nothing_to_remove" && remaining === 0) {
		return { ok: true, message: "No AIDR-managed hook was registered; nothing changed.", log };
	}
	return {
		ok: false,
		message: report?.reason?.detail
			? `Not removed: ${report.reason.detail}`
			: `aidr uninstall did not complete (exit ${result.exitCode ?? result.error}); see the details.`,
		log,
	};
}
