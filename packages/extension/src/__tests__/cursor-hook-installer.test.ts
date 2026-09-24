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

import { installManagedHooks, removeManagedHooks } from "../cursor_hook_installer.js";

const tempHomes: string[] = [];
let home: string;

describe("Cursor managed hook configuration", () => {
	beforeEach(async () => {
		vi.clearAllMocks();
		home = await mkdtemp(path.join(os.tmpdir(), "aidr-cursor-hooks-"));
		tempHomes.push(home);
		vi.stubEnv("USERPROFILE", home);
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

		const context = { asAbsolutePath: (relativePath: string) => relativePath };
		const health = await installManagedHooks({ context: context as never, scope: "user" });
		const hooksFile = JSON.parse(await readFile(health.configPath, "utf8")) as {
			hooks: Record<string, Array<Record<string, unknown>>>;
		};
		const managed = Object.values(hooksFile.hooks)
			.flat()
			.filter((entry) => String(entry.command).includes("--managed-by aidr-cursor"));

		expect(health.installedEvents).toEqual([
			"preToolUse",
			"beforeShellExecution",
			"postToolUse",
			"afterAgentResponse",
			"beforeMCPExecution",
			"beforeReadFile",
		]);
		expect(managed).toHaveLength(6);
		expect(managed.every((entry) => entry.failClosed === true)).toBe(true);
		expect(hooksFile.hooks.preToolUse).toContainEqual({
			command: "customer-hook",
			failClosed: false,
		});
	});

	it("refuses malformed customer hooks on install and removal without overwriting them", async () => {
		const configPath = path.join(home, ".cursor", "hooks.json");
		await mkdir(path.dirname(configPath), { recursive: true });
		const context = { asAbsolutePath: (relativePath: string) => relativePath };

		for (const original of ['{"hooks":', '{"version":1,"hooks":[]}']) {
			await writeFile(configPath, original, "utf8");
			await expect(installManagedHooks({ context: context as never, scope: "user" })).rejects.toThrow();
			await expect(removeManagedHooks("user")).rejects.toThrow();
			expect(await readFile(configPath, "utf8")).toBe(original);
		}
	});

	it("keeps unrelated customer fields through enable and disable", async () => {
		const configPath = path.join(home, ".cursor", "hooks.json");
		await mkdir(path.dirname(configPath), { recursive: true });
		await writeFile(configPath, JSON.stringify({ version: 1, hooks: {}, customerField: { enabled: true } }));
		const context = { asAbsolutePath: (relativePath: string) => relativePath };

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
