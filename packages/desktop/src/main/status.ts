import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { detectConnectorStatuses } from "../../../cli/src/utils/connector-status.js";
import type { MachineHookState } from "../../../cli/src/utils/machine-hooks.js";
import type {
	AuditEvent,
	ConnectorView,
	EngineFacts,
	HookFacts,
	HostId,
	StatusSnapshot,
} from "../shared/contract.js";
import type { Runner } from "./exec.js";
import { aidrHooks, parseHookCommand, programExists, readSettingsObject } from "./hooks.js";
import { configPath, dataDir, receiptPath, runtimeBinary } from "./paths.js";
import { checkRuntime, runtimeFlavor } from "./runtime.js";

/**
 * The status home: every fact is measured, never assumed. Connector state
 * comes from the CLI's own detection (`detectConnectorStatuses`, what
 * `aidr status` prints); the engine facts (rule count, mode) come from the
 * shipped `aidr status --json`, i.e. from the engine binary the hooks run.
 */

export interface StatusDeps {
	home: string;
	appVersion: string;
	bundledRuntime: string | null;
	run: Runner;
	env?: NodeJS.ProcessEnv;
	machine?: readonly MachineHookState[];
	lastVerdict?: AuditEvent | null;
}

interface CliStatus {
	detection?: { ok?: unknown; rules?: unknown; detail?: unknown };
	configuration?: { state?: unknown; mode?: unknown };
}

function readObject(path: string): Record<string, unknown> | null {
	try {
		const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
		return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
}

/** `logging.path` of the AIDR config (with `~` expanded), else the default audit log. */
export function auditLogPath(home: string): string {
	const logging = readObject(configPath(home))?.logging as { path?: unknown } | undefined;
	const configured = typeof logging?.path === "string" ? logging.path.trim() : "";
	if (configured.startsWith("~/") || configured === "~") return join(home, configured.slice(1));
	if (configured && isAbsolute(configured)) return configured;
	return join(dataDir(home), "audit.jsonl");
}

/** `logging.max_files`: how many rotated backups (`audit.jsonl.1` ...) may exist (core default 3). */
export function auditMaxFiles(home: string): number {
	const logging = readObject(configPath(home))?.logging as { max_files?: unknown } | undefined;
	const value = logging?.max_files;
	return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 100 ? value : 3;
}

function logCleanEnabled(home: string): boolean {
	const logging = readObject(configPath(home))?.logging as { log_clean?: unknown } | undefined;
	return logging?.log_clean === true;
}

/** Hook facts for a host whose AIDR hook is a command in a JSON config. */
function commandHookFacts(file: string, event: string): HookFacts {
	let settings: Record<string, unknown> | null = null;
	try {
		settings = readSettingsObject(file);
	} catch {
		return { kind: "command", registered: null, commands: [], binaryPresent: null, configPath: file };
	}
	const commands = aidrHooks(settings, event).map((hook) => hook.command);
	if (commands.length === 0) {
		return { kind: "command", registered: false, commands, binaryPresent: null, configPath: file };
	}
	const programs = commands.map((command) => parseHookCommand(command)?.file ?? null);
	return {
		kind: "command",
		registered: true,
		commands,
		binaryPresent: programs.every((program) => program !== null)
			? programs.every((program) => programExists(program as string))
			: null,
		configPath: file,
	};
}

export function hookFactsFor(id: HostId, home: string): HookFacts {
	switch (id) {
		case "claude-code":
			return commandHookFacts(join(home, ".claude", "settings.json"), "PreToolUse");
		case "codex":
			// A bare `aidr-codex-hook` (the npm bin, resolved from PATH by Codex)
			// is reported as registered with an unknown program location.
			return commandHookFacts(join(home, ".codex", "hooks.json"), "PreToolUse");
		case "cursor":
		case "vscode":
			return { kind: "extension", registered: null, commands: [], binaryPresent: null, configPath: null };
		default:
			return { kind: "in_process", registered: null, commands: [], binaryPresent: null, configPath: null };
	}
}

function connectorViews(
	home: string,
	env: NodeJS.ProcessEnv,
	machine?: readonly MachineHookState[],
): ConnectorView[] {
	const statuses = machine
		? detectConnectorStatuses(home, env, machine)
		: detectConnectorStatuses(home, env);
	return statuses
		.filter((status) => status.id === "claude-code" || status.state !== "not_detected")
		.map((status) => ({ ...status, hook: hookFactsFor(status.id, home) }));
}

async function engineFacts(deps: StatusDeps): Promise<{
	engine: EngineFacts;
	mode: StatusSnapshot["mode"];
	configState: string;
}> {
	const receipt = readObject(receiptPath(deps.home));
	const installed =
		typeof receipt?.path === "string" && existsSync(runtimeBinary(receipt.path)) ? receipt.path : null;
	const root = installed ?? deps.bundledRuntime;
	if (!root || !existsSync(runtimeBinary(root))) {
		return {
			engine: {
				ok: false,
				rules: null,
				detail: "no AIDR runtime is available to ask",
				binary: null,
				latencyMs: null,
			},
			mode: "unknown",
			configState: "unknown",
		};
	}
	const binary = runtimeBinary(root);
	const result = await deps.run(binary, ["status", "--json"], {
		cwd: deps.home,
		env: deps.env ?? process.env,
		timeoutMs: 60_000,
	});
	let parsed: CliStatus | null = null;
	try {
		const start = result.stdout.indexOf("{");
		parsed = start >= 0 ? (JSON.parse(result.stdout.slice(start)) as CliStatus) : null;
	} catch {
		parsed = null;
	}
	if (!parsed?.detection) {
		return {
			engine: {
				ok: false,
				rules: null,
				detail: `aidr status did not answer (${result.error ?? `exit ${result.exitCode}`}): ${result.stderr.trim().slice(0, 200)}`,
				binary,
				latencyMs: result.durationMs,
			},
			mode: "unknown",
			configState: "unknown",
		};
	}
	const mode = parsed.configuration?.mode;
	return {
		engine: {
			ok: parsed.detection.ok === true,
			rules: typeof parsed.detection.rules === "number" ? parsed.detection.rules : null,
			detail: typeof parsed.detection.detail === "string" ? parsed.detection.detail : "",
			binary,
			latencyMs: result.durationMs,
		},
		mode: mode === "local" || mode === "managed" ? mode : "unknown",
		configState:
			typeof parsed.configuration?.state === "string" ? parsed.configuration.state : "unknown",
	};
}

function aidrVersion(root: string | null): string | null {
	if (!root) return null;
	const version = readObject(join(root, "aidr-artifact.manifest.json"))?.artifact_version;
	return typeof version === "string" ? version : null;
}

export async function collectStatus(deps: StatusDeps): Promise<StatusSnapshot> {
	const env = deps.env ?? process.env;
	const connectors = connectorViews(deps.home, env, deps.machine);
	const { engine, mode, configState } = await engineFacts(deps);
	const bundledCheck = deps.bundledRuntime ? checkRuntime(deps.bundledRuntime) : null;
	const receipt = readObject(receiptPath(deps.home));
	const installedRoot =
		typeof receipt?.path === "string" && existsSync(resolve(receipt.path)) ? receipt.path : null;
	const flavor = deps.bundledRuntime ? runtimeFlavor(deps.bundledRuntime) : { flavor: null, signed: false };
	const claude = connectors.find((connector) => connector.id === "claude-code");
	const last = deps.lastVerdict ?? null;
	return {
		checkedAt: new Date().toISOString(),
		appVersion: deps.appVersion,
		aidrVersion: aidrVersion(installedRoot) ?? bundledCheck?.version ?? null,
		home: deps.home,
		engine,
		mode,
		configState,
		connectors,
		lastVerdict: last?.decision ? { at: last.at, decision: last.decision } : null,
		auditPath: auditLogPath(deps.home),
		logClean: logCleanEnabled(deps.home),
		configExists: existsSync(configPath(deps.home)),
		runtime: {
			bundledRoot: deps.bundledRuntime,
			bundledVersion: bundledCheck?.version ?? null,
			flavor: flavor.flavor,
			signed: flavor.signed,
			installedRoot,
			problems: bundledCheck ? bundledCheck.problems : ["no runtime is bundled with this build"],
		},
		protected:
			claude?.state === "installed" &&
			claude.hook.registered === true &&
			claude.hook.binaryPresent === true &&
			engine.ok &&
			(engine.rules ?? 0) > 0,
	};
}
