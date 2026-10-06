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

import { installManagedHooks, removeManagedHooks } from "../vscode_hook_installer.js";

const tempHomes: string[] = [];
let home: string;

describe("VS Code Local managed hook configuration", () => {
	beforeEach(async () => {
		home = await mkdtemp(path.join(os.tmpdir(), "aidr-vscode-hooks-"));
		tempHomes.push(home);
		vi.stubEnv("USERPROFILE", home);
		vi.stubEnv("VSCODE_NODE_EXEC_PATH", process.execPath);
		vscodeMocks.getConfiguration.mockReturnValue({ get: () => process.execPath });
	});

	it("inspects every Local tool including editFiles and MCP tools", async () => {
		const context = { asAbsolutePath: (relativePath: string) => relativePath };
		const health = await installManagedHooks({ context: context as never, scope: "user" });
		const settings = JSON.parse(await readFile(health.configPath, "utf8")) as {
			hooks: {
				PreToolUse: Array<{ matcher?: string; hooks?: Array<{ command?: string }> }>;
			};
		};

		expect(settings.hooks.PreToolUse).toContainEqual(
			expect.objectContaining({ matcher: "*" }),
		);
		expect(health.installedEvents).toContain("PreToolUse");
	});

	it("refuses malformed customer settings on install and removal without overwriting them", async () => {
		const configPath = path.join(home, ".claude", "settings.json");
		await mkdir(path.dirname(configPath), { recursive: true });
		const context = { asAbsolutePath: (relativePath: string) => relativePath };

		for (const original of ['{"hooks":', '{"hooks":{"PreToolUse":"customer-hook"}}']) {
			await writeFile(configPath, original, "utf8");
			await expect(installManagedHooks({ context: context as never, scope: "user" })).rejects.toThrow();
			await expect(removeManagedHooks("user")).rejects.toThrow();
			expect(await readFile(configPath, "utf8")).toBe(original);
		}
	});
});

afterAll(async () => {
	vi.unstubAllEnvs();
	await Promise.all(tempHomes.map((dir) => rm(dir, { recursive: true, force: true })));
});
