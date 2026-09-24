import { afterEach, describe, expect, it, vi } from "vitest";

const failures = vi.hoisted(() => ({
	integrity: undefined as unknown,
	threatLoad: undefined as unknown,
}));

vi.mock("@singularityrd/aidr-core", async (importOriginal) => {
	const actual = await importOriginal<typeof import("@singularityrd/aidr-core")>();
	return {
		...actual,
		initSentry: vi.fn(),
		verifyArtifactIntegrityAndLog: vi.fn(async () => {
			if (failures.integrity) throw failures.integrity;
			return { status: "ok" as const };
		}),
	};
});

vi.mock("../bundled-dirs.js", () => ({
	getBundledDataDirs: () => {
		if (failures.threatLoad) throw failures.threatLoad;
		return { threatsDir: "/nonexistent/threats", allowlistsDir: "/nonexistent/allowlists" };
	},
	getSageVersion: () => "0.0.0",
}));

import { ArtifactIntegrityError } from "@singularityrd/aidr-core";
import plugin from "../index.js";

type Handler = (...args: unknown[]) => Promise<unknown>;

function register() {
	const handlers = new Map<string, Handler[]>();
	const tools: Array<Record<string, unknown>> = [];
	const errors: string[] = [];
	plugin.register({
		logger: {
			debug() {},
			info() {},
			warn() {},
			error(message: string) {
				errors.push(message);
			},
		},
		on(event: string, handler: Handler) {
			handlers.set(event, [...(handlers.get(event) ?? []), handler]);
		},
		registerTool(tool: Record<string, unknown>) {
			tools.push(tool);
		},
	});
	return { handlers, tools, errors };
}

async function expectBlocked(handlers: Map<string, Handler[]>, expectedCode: string) {
	const gates = handlers.get("before_tool_call") ?? [];
	expect(gates.length).toBeGreaterThan(0);
	const blockReason = `AIDR failed to initialise: ${expectedCode}; tool calls are blocked until fixed`;
	for (const event of [
		{ toolName: "exec", params: { command: "ls" } },
		{ toolName: "read", params: { path: "README.md" } },
		{ toolName: "web_fetch", params: { url: "https://example.com" } },
	]) {
		for (const gate of gates) {
			await expect(gate(event, { sessionKey: "s" })).resolves.toEqual({
				block: true,
				blockReason,
			});
		}
	}
}

afterEach(() => {
	failures.integrity = undefined;
	failures.threatLoad = undefined;
});

describe("OpenClaw plugin initialisation fails closed", () => {
	it("blocks every tool call when artifact integrity verification fails", async () => {
		failures.integrity = new ArtifactIntegrityError("openclaw/dist", {
			status: "bad_signature",
		});
		const { handlers } = register();
		await expectBlocked(handlers, "integrity_bad_signature");
	});

	it("still registers a blocking gate when threat resources cannot be loaded", async () => {
		failures.threatLoad = Object.assign(
			new Error("ENOENT: no such file or directory, scandir '/secret/path/threats'"),
			{ code: "ENOENT" },
		);
		const { handlers, tools, errors } = register();
		await expectBlocked(handlers, "ENOENT");
		// The failed plugin exposes no allowlist tools and no other hooks.
		expect(tools).toEqual([]);
		expect([...handlers.keys()]).toEqual(["before_tool_call"]);
		// Raw error text stays in the host log; the agent-visible reason is only the code.
		expect(errors.join("\n")).toContain("/secret/path");
		const [gate] = handlers.get("before_tool_call") ?? [];
		expect(JSON.stringify(await gate?.({ toolName: "exec", params: {} }))).not.toContain(
			"/secret/path",
		);
	});
});
