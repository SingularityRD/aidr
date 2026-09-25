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
		// os.homedir() reads HOME on POSIX and USERPROFILE on Windows; stub both so the
		// installer never touches the real ~/.claude/settings.json of the machine running tests.
		vi.stubEnv("HOME", home);
		vi.stubEnv("USERPROFILE", home);
		expect(os.homedir()).toBe(home);
		vi.stubEnv("VSCODE_NODE_EXEC_PATH", process.execPath);
		vscodeMocks.getConfiguration.mockReturnValue({ get: () => process.execPath });
	});

	it("registers Local editFiles with the canonical Edit adapter matcher", async () => {
		const context = { asAbsolutePath: (relativePath: string) => relativePath };
		const health = await installManagedHooks({ context: context as never, scope: "user" });
		const settings = JSON.parse(await readFile(health.configPath, "utf8")) as {
			hooks: {
				PreToolUse: Array<{ matcher?: string; hooks?: Array<{ command?: string }> }>;
			};
		};

		expect(settings.hooks.PreToolUse).toContainEqual(
			expect.objectContaining({ matcher: "Bash|WebFetch|Write|Edit|Read|Delete|editFiles" }),
		);
		expect(health.configPath).toBe(path.join(home, ".claude", "settings.json"));
		expect(health.installedEvents).toEqual(["UserPromptSubmit", "PreToolUse", "PostToolUse"]);
	});

	it("registers UserPromptSubmit prompt protection without a matcher, idempotently", async () => {
		const configPath = path.join(home, ".claude", "settings.json");
		await mkdir(path.dirname(configPath), { recursive: true });
		await writeFile(
			configPath,
			JSON.stringify({
				hooks: {
					PostToolUse: [{ hooks: [{ type: "command", command: "customer-post" }] }],
					UserPromptSubmit: [{ hooks: [{ type: "command", command: "customer-prompt" }] }],
				},
			}),
		);
		const context = { asAbsolutePath: (relativePath: string) => relativePath };

		await installManagedHooks({ context: context as never, scope: "user" });
		const health = await installManagedHooks({ context: context as never, scope: "user" });
		// Registration order, independent of the key order already in the customer's file.
		expect(health.installedEvents).toEqual(["UserPromptSubmit", "PreToolUse", "PostToolUse"]);
		const settings = JSON.parse(await readFile(configPath, "utf8")) as {
			hooks: Record<
				string,
				Array<{ matcher?: string; hooks: Array<{ command: string; timeout?: number }> }>
			>;
		};
		const prompt = settings.hooks.UserPromptSubmit ?? [];
		expect(prompt).toHaveLength(2);
		expect(prompt[0]?.hooks[0]?.command).toBe("customer-prompt");
		expect(prompt[1]).not.toHaveProperty("matcher");
		expect(prompt[1]?.hooks[0]?.command).toMatch(/ vscode --managed-by aidr-vscode$/);
		expect(prompt[1]?.hooks[0]?.timeout).toBe(30);

		await removeManagedHooks("user");
		const removed = JSON.parse(await readFile(configPath, "utf8")) as {
			hooks: Record<string, unknown>;
		};
		expect(removed.hooks).toEqual({
			PostToolUse: [{ hooks: [{ type: "command", command: "customer-post" }] }],
			UserPromptSubmit: [{ hooks: [{ type: "command", command: "customer-prompt" }] }],
		});
	});

	it("refuses malformed customer settings on install and removal without overwriting them", async () => {
		const configPath = path.join(home, ".claude", "settings.json");
		await mkdir(path.dirname(configPath), { recursive: true });
		const context = { asAbsolutePath: (relativePath: string) => relativePath };

		for (const original of ['{"hooks":', '{"hooks":{"PreToolUse":"customer-hook"}}']) {
			await writeFile(configPath, original, "utf8");
			await expect(
				installManagedHooks({ context: context as never, scope: "user" }),
			).rejects.toThrow();
			await expect(removeManagedHooks("user")).rejects.toThrow();
			expect(await readFile(configPath, "utf8")).toBe(original);
		}
	});
});

afterAll(async () => {
	vi.unstubAllEnvs();
	await Promise.all(tempHomes.map((dir) => rm(dir, { recursive: true, force: true })));
});
