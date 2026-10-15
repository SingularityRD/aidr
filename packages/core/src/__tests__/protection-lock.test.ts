// C10: the machine-policy protection lock and the local protection event counters.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	readProtectionEvents,
	readProtectionLock,
	recordProtectionEvent,
} from "../protection-lock.js";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots) rmSync(root, { recursive: true, force: true });
	roots.length = 0;
});

const file = (uid: number, mode: number) => ({ uid, mode, isFile: () => true });

describe("readProtectionLock", () => {
	it("reads protection_locked from the Windows machine policy key", () => {
		const queried: string[][] = [];
		const lock = readProtectionLock({
			platform: "win32",
			regQuery: (key, value) => {
				queried.push([key, value]);
				return "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Singularity AIDR\r\n    protection_locked    REG_DWORD    0x1\r\n";
			},
		});
		expect(lock).toEqual({ locked: true, source: "windows_registry" });
		expect(queried).toEqual([["HKLM\\SOFTWARE\\Policies\\Singularity AIDR", "protection_locked"]]);
		expect(
			readProtectionLock({
				platform: "win32",
				regQuery: () => "    protection_locked    REG_DWORD    0x0\r\n",
			}).locked,
		).toBe(false);
		expect(readProtectionLock({ platform: "win32", regQuery: () => null })).toEqual({
			locked: false,
			source: "none",
		});
	});

	it("honours only a root-owned Linux policy file that others cannot write", () => {
		const readText = () =>
			JSON.stringify({ control_plane_url: "https://cp.example", protection_locked: true });
		expect(
			readProtectionLock({ platform: "linux", stat: () => file(0, 0o100644), readText }),
		).toEqual({
			locked: true,
			source: "linux_policy_file",
		});
		const userOwned = readProtectionLock({
			platform: "linux",
			stat: () => file(1000, 0o100644),
			readText,
		});
		expect(userOwned.locked).toBe(false);
		expect(userOwned.problem).toContain("root-owned");
		expect(
			readProtectionLock({ platform: "linux", stat: () => file(0, 0o100666), readText }).locked,
		).toBe(false);
		expect(
			readProtectionLock({ platform: "linux", stat: () => file(0, 0o100644), readText: () => "{" })
				.problem,
		).toContain("not valid JSON");
		expect(
			readProtectionLock({
				platform: "linux",
				stat: () => file(0, 0o100644),
				readText: () => '{"protection_locked":"yes"}',
			}).locked,
		).toBe(false);
		expect(
			readProtectionLock({
				platform: "linux",
				stat: () => {
					throw Object.assign(new Error("missing"), { code: "ENOENT" });
				},
			}),
		).toEqual({ locked: false, source: "none" });
	});
});

describe("protection events", () => {
	it("counts events per connector and survives a corrupt file", async () => {
		const root = mkdtempSync(join(tmpdir(), "aidr-protection-events-"));
		roots.push(root);
		const path = join(root, "protection-events.json");
		const now = () => new Date("2026-10-14T10:00:00.000Z");
		expect(await recordProtectionEvent("cursor", "disable_blocked", { path, now })).toBe(true);
		expect(await recordProtectionEvent("cursor", "disable_blocked", { path, now })).toBe(true);
		expect(await recordProtectionEvent("vscode", "hook_restored", { path, now })).toBe(true);
		expect(readProtectionEvents(path)).toEqual({
			cursor: {
				disable_attempts: 2,
				hooks_restored: 0,
				disabled_by_user: 0,
				last_event_at: "2026-10-14T10:00:00.000Z",
			},
			vscode: {
				disable_attempts: 0,
				hooks_restored: 1,
				disabled_by_user: 0,
				last_event_at: "2026-10-14T10:00:00.000Z",
			},
		});
		writeFileSync(path, "not json");
		expect(readProtectionEvents(path)).toEqual({});
		expect(await recordProtectionEvent("vscode", "disabled_by_user", { path, now })).toBe(true);
		expect(JSON.parse(readFileSync(path, "utf8")).vscode.disabled_by_user).toBe(1);
	});
});
