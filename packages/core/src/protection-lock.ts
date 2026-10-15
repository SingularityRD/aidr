/**
 * Machine-policy protection lock and the local record of protection events.
 *
 * ## Why this exists (C10)
 *
 * The Cursor / VS Code extension offers "Singularity AIDR: Disable protection",
 * which removes the AIDR hooks for the current user. On a per-machine install
 * the organisation can lock that: the machine policy (the W1 contract,
 * `HKLM\SOFTWARE\Policies\Singularity AIDR` on Windows and the root-owned
 * `/etc/singularity-aidr/managed.json` on Linux) carries
 * `protection_locked = 1 / true`. When it is set the extension refuses to
 * remove its hooks, puts them back if they were deleted, and counts every
 * refused attempt here; `aidr heartbeat` reports the count, and the control
 * plane raises `agent.unprotected` (`disable_attempted`) when it rises.
 *
 * A Linux policy file that is not owned by root, or that group/other can
 * write, is ignored (reported as a problem): a user who can write it could
 * change it anyway. A local administrator can always change machine policy;
 * the heartbeat is what makes that visible.
 */

import { lstatSync, readFileSync, statSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { resolvePath } from "./config.js";
import { defaultRegQuery, WINDOWS_MDM_POLICY_KEY } from "./update/environment.js";

export const LINUX_MACHINE_POLICY_PATH = "/etc/singularity-aidr/managed.json";
export const PROTECTION_LOCKED_KEY = "protection_locked";

export interface ProtectionLock {
	locked: boolean;
	/** Where the decision came from. */
	source: "windows_registry" | "linux_policy_file" | "none";
	/** Why a present policy was not honoured. */
	problem?: string;
}

export interface ProtectionLockDeps {
	platform?: NodeJS.Platform;
	policyPath?: string;
	regQuery?: (key: string, value: string) => string | null;
	/** File owner/mode lookup (tests); defaults to fs.statSync. */
	stat?: (path: string) => { uid: number; mode: number; isFile(): boolean };
	readText?: (path: string) => string;
}

/** Read the organisation's protection lock from machine policy. Never throws. */
export function readProtectionLock(deps: ProtectionLockDeps = {}): ProtectionLock {
	const platform = deps.platform ?? process.platform;
	if (platform === "win32") {
		const output = (deps.regQuery ?? defaultRegQuery)(
			WINDOWS_MDM_POLICY_KEY,
			PROTECTION_LOCKED_KEY,
		);
		if (!output) return { locked: false, source: "none" };
		return /REG_(?:DWORD|SZ)\s+(?:0x0*1|1|true)\s*$/imu.test(output)
			? { locked: true, source: "windows_registry" }
			: { locked: false, source: "windows_registry" };
	}
	const path = deps.policyPath ?? LINUX_MACHINE_POLICY_PATH;
	const stat =
		deps.stat ??
		((target: string) =>
			lstatSync(target).isSymbolicLink() ? statSync(target) : lstatSync(target));
	let info: { uid: number; mode: number; isFile(): boolean };
	try {
		info = stat(path);
	} catch {
		return { locked: false, source: "none" };
	}
	if (!info.isFile())
		return { locked: false, source: "none", problem: `${path} is not a regular file` };
	if (info.uid !== 0 || (info.mode & 0o022) !== 0) {
		return {
			locked: false,
			source: "none",
			problem: `${path} is not root-owned and read-only for other users; ignored`,
		};
	}
	try {
		const parsed = JSON.parse(
			(deps.readText ?? ((target: string) => readFileSync(target, "utf8")))(path),
		) as unknown;
		const value =
			parsed && typeof parsed === "object" && !Array.isArray(parsed)
				? (parsed as Record<string, unknown>)[PROTECTION_LOCKED_KEY]
				: undefined;
		return { locked: value === true, source: "linux_policy_file" };
	} catch {
		return { locked: false, source: "none", problem: `${path} is not valid JSON; ignored` };
	}
}

export type ProtectionEventConnector = "cursor" | "vscode";
export type ProtectionEventKind = "disable_blocked" | "hook_restored" | "disabled_by_user";

export interface ProtectionEventCounts {
	disable_attempts: number;
	hooks_restored: number;
	disabled_by_user: number;
	last_event_at: string | null;
}

export type ProtectionEvents = Partial<Record<ProtectionEventConnector, ProtectionEventCounts>>;

export function protectionEventsPath(): string {
	return resolvePath("~/.singularity-aidr/protection-events.json");
}

const COUNTER: Record<ProtectionEventKind, keyof Omit<ProtectionEventCounts, "last_event_at">> = {
	disable_blocked: "disable_attempts",
	hook_restored: "hooks_restored",
	disabled_by_user: "disabled_by_user",
};

function count(value: unknown): number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
		? Math.min(value, 1_000_000)
		: 0;
}

function parseEvents(raw: string): ProtectionEvents {
	try {
		const parsed = JSON.parse(raw) as unknown;
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
		const result: ProtectionEvents = {};
		for (const connector of ["cursor", "vscode"] as const) {
			const entry = (parsed as Record<string, unknown>)[connector];
			if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
			const record = entry as Record<string, unknown>;
			result[connector] = {
				disable_attempts: count(record.disable_attempts),
				hooks_restored: count(record.hooks_restored),
				disabled_by_user: count(record.disabled_by_user),
				last_event_at: typeof record.last_event_at === "string" ? record.last_event_at : null,
			};
		}
		return result;
	} catch {
		return {};
	}
}

/** The local protection event counters (empty when absent or unreadable). */
export function readProtectionEvents(path: string = protectionEventsPath()): ProtectionEvents {
	try {
		return parseEvents(readFileSync(path, "utf8"));
	} catch {
		return {};
	}
}

/** Count one protection event for a connector. Best effort: a write failure is returned, never thrown. */
export async function recordProtectionEvent(
	connector: ProtectionEventConnector,
	kind: ProtectionEventKind,
	options: { path?: string; now?: () => Date } = {},
): Promise<boolean> {
	const path = options.path ?? protectionEventsPath();
	try {
		let events: ProtectionEvents = {};
		try {
			events = parseEvents(await readFile(path, "utf8"));
		} catch {
			events = {};
		}
		const current = events[connector] ?? {
			disable_attempts: 0,
			hooks_restored: 0,
			disabled_by_user: 0,
			last_event_at: null,
		};
		const field = COUNTER[kind];
		events[connector] = {
			...current,
			[field]: Math.min(current[field] + 1, 1_000_000),
			last_event_at: (options.now ?? (() => new Date()))().toISOString(),
		};
		await mkdir(dirname(path), { recursive: true, mode: 0o700 });
		const temporary = `${path}.${process.pid}.tmp`;
		await writeFile(temporary, `${JSON.stringify(events, null, 2)}\n`, { mode: 0o600 });
		await rename(temporary, path);
		return true;
	} catch {
		return false;
	}
}
