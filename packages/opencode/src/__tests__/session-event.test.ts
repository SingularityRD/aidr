import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";

vi.mock("../startup-scan.js", () => ({
	createSessionScanHandler:
		(_logger: unknown, _directory?: string, onResult?: (message: string) => void) => async () => {
			onResult?.("synthetic security finding");
		},
}));

it("delivers session scan findings to the SDK session.created id", async () => {
	const isolatedHome = await mkdtemp(join(tmpdir(), "aidr-opencode-session-"));
	const names = [
		"HOME",
		"USERPROFILE",
		"APPDATA",
		"LOCALAPPDATA",
		"XDG_CONFIG_HOME",
		"XDG_CACHE_HOME",
	] as const;
	const previous = names.map((name) => [name, process.env[name]] as const);
	for (const name of names) process.env[name] = isolatedHome;
	try {
		const { AidrPlugin } = await import("../index.js");
		const hooks = await AidrPlugin({
			client: { app: { log: async () => {} } },
			directory: isolatedHome,
			worktree: isolatedHome,
		} as never);
		await hooks.event?.({
			event: { type: "session.created", properties: { info: { id: "session-1" } } },
		} as never);
		const output = {
			messages: [
				{ info: { role: "user", sessionID: "session-1", id: "message-1" }, parts: [] as unknown[] },
			],
		};
		await hooks["experimental.chat.messages.transform"]?.({} as never, output as never);
		expect(output.messages[0]?.parts).toEqual([
			expect.objectContaining({ text: expect.stringContaining("synthetic security finding") }),
		]);
	} finally {
		for (const [name, value] of previous) {
			if (value === undefined) delete process.env[name];
			else process.env[name] = value;
		}
		await rm(isolatedHome, { recursive: true, force: true });
	}
});
