import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

const vscodeMocks = vi.hoisted(() => ({ getConfiguration: vi.fn() }));

vi.mock("vscode", () => ({
	workspace: {
		getConfiguration: vscodeMocks.getConfiguration,
		workspaceFolders: [],
	},
}));

import {
	getHookHealth,
	installManagedHooks,
	removeManagedHooks,
} from "../cursor_hook_installer.js";

/** Like VS Code, resolve extension-relative paths against the package root, not the cwd. */
const EXTENSION_ROOT = path.resolve(__dirname, "..", "..");

const tempHomes: string[] = [];
let home: string;

describe("Cursor managed hook configuration", () => {
	beforeEach(async () => {
		vi.clearAllMocks();
		home = await mkdtemp(path.join(os.tmpdir(), "aidr-cursor-hooks-"));
		tempHomes.push(home);
		// os.homedir() reads HOME on POSIX and USERPROFILE on Windows; stub both so the
		// installer never touches the real ~/.cursor/hooks.json of the machine running tests.
		vi.stubEnv("HOME", home);
		vi.stubEnv("USERPROFILE", home);
		expect(os.homedir()).toBe(home);
		vscodeMocks.getConfiguration.mockReturnValue({ get: () => process.execPath });
	});

	it("sets failClosed on every managed hook without changing customer hooks", async () => {
		const cursorDir = path.join(home, ".cursor");
		await mkdir(cursorDir, { recursive: true });
		await writeFile(
			path.join(cursorDir, "hooks.json"),
			JSON.stringify({
				version: 1,
				hooks: { preToolUse: [{ command: "customer-hook", failClosed: false }] },
			}),
			"utf8",
		);

		const context = {
			asAbsolutePath: (relativePath: string) => path.resolve(EXTENSION_ROOT, relativePath),
		};
		const health = await installManagedHooks({ context: context as never, scope: "user" });
		const hooksFile = JSON.parse(await readFile(health.configPath, "utf8")) as {
			hooks: Record<string, Array<Record<string, unknown>>>;
		};
		const managed = Object.values(hooksFile.hooks)
			.flat()
			.filter((entry) => String(entry.command).includes("--managed-by aidr-cursor"));

		expect(health.configPath).toBe(path.join(cursorDir, "hooks.json"));
		// Documented registration order, even though the customer's file lists preToolUse first.
		const documentedOrder = [
			"beforeSubmitPrompt",
			"beforeShellExecution",
			"preToolUse",
			"postToolUse",
			"afterAgentResponse",
			"beforeMCPExecution",
			"beforeReadFile",
		];
		expect(Object.keys(hooksFile.hooks)[0]).toBe("preToolUse");
		expect(health.installedEvents).toEqual(documentedOrder);
		expect(
			(await getHookHealth({ context: context as never, scope: "user" })).installedEvents,
		).toEqual(documentedOrder);
		expect(managed).toHaveLength(7);
		expect(managed.every((entry) => entry.failClosed === true)).toBe(true);
		expect(
			hooksFile.hooks.preToolUse.find((entry) =>
				String(entry.command).includes("--managed-by aidr-cursor"),
			)?.matcher,
		).toBeUndefined();
		// Prompt protection: one unmatched managed entry, the same runner as the tool hooks.
		const promptEntries = hooksFile.hooks.beforeSubmitPrompt ?? [];
		expect(promptEntries).toHaveLength(1);
		expect(promptEntries[0]).not.toHaveProperty("matcher");
		expect(promptEntries[0]?.command).toBe(hooksFile.hooks.beforeShellExecution?.[0]?.command);
		expect(String(promptEntries[0]?.command)).toMatch(/ cursor --managed-by aidr-cursor$/);
		expect(hooksFile.hooks.preToolUse).toContainEqual({
			command: "customer-hook",
			failClosed: false,
		});
	});

	it("keeps a customer beforeSubmitPrompt hook ahead of the managed one and removes only ours", async () => {
		const configPath = path.join(home, ".cursor", "hooks.json");
		await mkdir(path.dirname(configPath), { recursive: true });
		await writeFile(
			configPath,
			JSON.stringify({
				version: 1,
				hooks: { beforeSubmitPrompt: [{ command: "customer-audit" }] },
			}),
		);
		const context = {
			asAbsolutePath: (relativePath: string) => path.resolve(EXTENSION_ROOT, relativePath),
		};

		await installManagedHooks({ context: context as never, scope: "user" });
		await installManagedHooks({ context: context as never, scope: "user" });
		const installed = JSON.parse(await readFile(configPath, "utf8")) as {
			hooks: Record<string, Array<{ command: string }>>;
		};
		expect(installed.hooks.beforeSubmitPrompt?.map((entry) => entry.command)).toEqual([
			"customer-audit",
			expect.stringContaining("--managed-by aidr-cursor"),
		]);

		await removeManagedHooks("user");
		const removed = JSON.parse(await readFile(configPath, "utf8")) as {
			hooks: Record<string, unknown>;
		};
		expect(removed.hooks).toEqual({ beforeSubmitPrompt: [{ command: "customer-audit" }] });
	});

	it("refuses malformed customer hooks on install and removal without overwriting them", async () => {
		const configPath = path.join(home, ".cursor", "hooks.json");
		await mkdir(path.dirname(configPath), { recursive: true });
		const context = {
			asAbsolutePath: (relativePath: string) => path.resolve(EXTENSION_ROOT, relativePath),
		};

		for (const original of ['{"hooks":', '{"version":1,"hooks":[]}']) {
			await writeFile(configPath, original, "utf8");
			await expect(
				installManagedHooks({ context: context as never, scope: "user" }),
			).rejects.toThrow();
			await expect(removeManagedHooks("user")).rejects.toThrow();
			expect(await readFile(configPath, "utf8")).toBe(original);
		}
	});

	it("keeps unrelated customer fields through enable and disable", async () => {
		const configPath = path.join(home, ".cursor", "hooks.json");
		await mkdir(path.dirname(configPath), { recursive: true });
		await writeFile(
			configPath,
			JSON.stringify({ version: 1, hooks: {}, customerField: { enabled: true } }),
		);
		const context = {
			asAbsolutePath: (relativePath: string) => path.resolve(EXTENSION_ROOT, relativePath),
		};

		await installManagedHooks({ context: context as never, scope: "user" });
		expect(JSON.parse(await readFile(configPath, "utf8")).customerField).toEqual({ enabled: true });
		await removeManagedHooks("user");
		expect(JSON.parse(await readFile(configPath, "utf8")).customerField).toEqual({ enabled: true });
	});
});

afterAll(async () => {
	vi.unstubAllEnvs();
	await Promise.all(tempHomes.map((dir) => rm(dir, { recursive: true, force: true })));
});
