import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const failures = vi.hoisted(() => ({
	integrity: undefined as unknown,
	threatLoad: undefined as unknown,
}));

vi.mock("@singularityrd/aidr-core", async (importOriginal) => {
	const actual = await importOriginal<typeof import("@singularityrd/aidr-core")>();
	return {
		...actual,
		verifyArtifactIntegrityAndLog: vi.fn(async () => {
			if (failures.integrity) throw failures.integrity;
			return { status: "ok" as const };
		}),
	};
});

vi.mock("../startup-scan.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../startup-scan.js")>()),
	createCachedSessionScanner: () => async () => {
		if (failures.threatLoad) throw failures.threatLoad;
		return undefined;
	},
}));

import { ArtifactIntegrityError } from "@singularityrd/aidr-core";
import AidrPlugin from "../index.js";

let home = "";

beforeEach(async () => {
	home = await mkdtemp(join(tmpdir(), "aidr-opencode-init-"));
	vi.stubEnv("HOME", home);
	vi.stubEnv("USERPROFILE", home);
	vi.stubEnv("SENTRY_ENABLED", "0");
});

afterEach(async () => {
	failures.integrity = undefined;
	failures.threatLoad = undefined;
	vi.unstubAllEnvs();
	await rm(home, { recursive: true, force: true });
});

async function loadPlugin() {
	return AidrPlugin({
		client: { app: { log: async () => undefined } },
		directory: home,
		worktree: home,
	} as never);
}

async function expectEveryToolBlocked(expectedCode: string) {
	const hooks = await loadPlugin();
	const before = hooks["tool.execute.before"];
	expect(before).toBeTypeOf("function");
	const message = `AIDR failed to initialise: ${expectedCode}; tool calls are blocked until fixed`;
	for (const [tool, args] of [
		["bash", { command: "ls" }],
		["read", { filePath: "README.md" }],
		["webfetch", { url: "https://example.com" }],
	] as const) {
		await expect(
			before?.({ tool, sessionID: "s", callID: "c" }, { args: { ...args } }),
		).rejects.toThrow(message);
	}
	// A plugin that failed to initialise must not expose its allowlist tools.
	expect(hooks.tool).toBeUndefined();
}

describe("OpenCode plugin initialisation fails closed", () => {
	it("registers a blocking tool hook when artifact integrity verification fails", async () => {
		failures.integrity = new ArtifactIntegrityError("opencode/dist", {
			status: "hash_mismatch",
		});
		await expectEveryToolBlocked("integrity_hash_mismatch");
	});

	it("registers a blocking tool hook when threat definitions cannot be loaded", async () => {
		failures.threatLoad = Object.assign(
			new Error("ENOENT: no such file or directory, scandir '/secret/path/threats'"),
			{ code: "ENOENT" },
		);
		const hooks = await loadPlugin();
		await expect(
			hooks["tool.execute.before"]?.(
				{ tool: "bash", sessionID: "s", callID: "c" },
				{ args: { command: "ls" } },
			),
		).rejects.toThrow("AIDR failed to initialise: ENOENT; tool calls are blocked until fixed");
		// The raw error text (local paths) is logged, never returned to the agent.
		await expect(
			hooks["tool.execute.before"]?.(
				{ tool: "bash", sessionID: "s", callID: "c" },
				{ args: { command: "ls" } },
			),
		).rejects.not.toThrow("/secret/path");
	});

	it("applies the uninspected-prompt policy to chat.message when initialisation fails", async () => {
		failures.integrity = new ArtifactIntegrityError("opencode/dist", {
			status: "hash_mismatch",
		});
		const hooks = await loadPlugin();
		const parts = [{ type: "text", text: "a clean prompt" }];
		// Default policy (secrets: block): a prompt that cannot be inspected is blocked.
		await expect(
			hooks["chat.message"]?.({ sessionID: "s" }, { message: { id: "m" }, parts } as never),
		).rejects.toThrow("could not inspect this prompt");
		expect(parts[0]?.text).not.toBe("a clean prompt");
	});

	it("registers the normal hooks when initialisation succeeds", async () => {
		const hooks = await loadPlugin();
		expect(hooks["tool.execute.before"]).toBeTypeOf("function");
		expect(hooks["chat.message"]).toBeTypeOf("function");
		expect(Object.keys(hooks.tool ?? {})).toEqual(["aidr_allowlist_add", "aidr_allowlist_remove"]);
	});
});
