import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
	type ProtectionEvents,
	type ProtectionLock,
	readProtectionEvents,
	readProtectionLock,
} from "@singularityrd/aidr-core";
import { inspectCodexHookTrust } from "./codex-trust.js";
import { type ConnectorStatus, detectConnectorStatuses } from "./connector-status.js";
import { type MachineHookState, machineHookStatus } from "./machine-hooks.js";

/**
 * The per-connector heartbeat report (C10): what each agent host on this
 * device will actually run, measured from outside the hook.
 *
 * A removed, disabled or untrusted hook never runs, so it cannot report its
 * own absence. `aidr heartbeat` runs from the OS scheduler (installed by the
 * per-machine installers through `aidr machine-hooks install`) and sends this
 * report to the control plane, which alerts when a protected connector stops
 * being protected and when the heartbeat itself stops (`agent.offline`).
 *
 * The report carries enums and counts only: no paths, commands or user names.
 */

type HeartbeatState =
	| "protected"
	| "hook_missing"
	| "hook_disabled"
	| "hook_untrusted"
	| "hook_broken";

export interface HeartbeatConnector {
	connector: ConnectorStatus["id"];
	state: HeartbeatState;
	enforcement: "machine_policy" | "user_config" | "none";
	protection_locked: boolean;
	disable_attempts: number;
}

export interface HeartbeatDeps {
	home: string;
	env?: NodeJS.ProcessEnv;
	machine?: readonly MachineHookState[];
	connectors?: ConnectorStatus[];
	lock?: ProtectionLock;
	events?: ProtectionEvents;
}

function readJson(path: string): Record<string, unknown> | null {
	try {
		const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
		return parsed && typeof parsed === "object" && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
}

function readText(path: string): string {
	try {
		return readFileSync(path, "utf8");
	} catch {
		return "";
	}
}

/** Editor extensions register their hooks in these user files with a fixed marker. */
function editorHookRegistered(id: "cursor" | "vscode", home: string): boolean {
	return id === "cursor"
		? readText(join(home, ".cursor", "hooks.json")).includes("--managed-by aidr-cursor")
		: readText(join(home, ".claude", "settings.json")).includes("--managed-by aidr-vscode");
}

function baseState(status: ConnectorStatus): HeartbeatState | null {
	switch (status.state) {
		case "not_detected":
			return null;
		case "installed":
			return "protected";
		case "runtime_present_not_installed":
			return "hook_missing";
		default:
			return "hook_broken";
	}
}

/** Build the report for every agent host present on this device. */
export function buildHeartbeat(deps: HeartbeatDeps): HeartbeatConnector[] {
	const env = deps.env ?? process.env;
	const machine = deps.machine ?? machineHookStatus();
	const statuses = deps.connectors ?? detectConnectorStatuses(deps.home, env, machine);
	const lock = deps.lock ?? readProtectionLock();
	const events =
		deps.events ??
		readProtectionEvents(join(deps.home, ".singularity-aidr", "protection-events.json"));
	const reports: HeartbeatConnector[] = [];
	for (const status of statuses) {
		let state = baseState(status);
		if (state === null) continue;
		const byPolicy = machine.some((entry) => entry.host === status.id && entry.registered);
		if (status.id === "claude-code" && !byPolicy && state === "hook_missing") {
			if (readJson(join(deps.home, ".claude", "settings.json"))?.disableAllHooks === true)
				state = "hook_disabled";
		}
		if (status.id === "codex" && !byPolicy && state === "protected") {
			const trust = inspectCodexHookTrust(deps.home, env);
			if (trust.handlers.some((handler) => handler.trust === "disabled")) state = "hook_disabled";
			else if (trust.handlers.some((handler) => handler.trust === "untrusted"))
				state = "hook_untrusted";
		}
		let locked = false;
		let attempts = 0;
		if (status.id === "cursor" || status.id === "vscode") {
			locked = lock.locked;
			attempts = events[status.id]?.disable_attempts ?? 0;
			// The extension package alone protects nothing: its hooks must be registered.
			if (state === "protected" && !editorHookRegistered(status.id, deps.home)) {
				state = (events[status.id]?.disabled_by_user ?? 0) > 0 ? "hook_disabled" : "hook_missing";
			}
		}
		reports.push({
			connector: status.id,
			state,
			enforcement: byPolicy ? "machine_policy" : state === "protected" ? "user_config" : "none",
			protection_locked: locked,
			disable_attempts: attempts,
		});
	}
	return reports;
}
