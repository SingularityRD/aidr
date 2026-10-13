import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const integrity = vi.hoisted(() => ({ fail: true, hang: false }));

vi.mock("@singularityrd/aidr-core", async (importOriginal) => {
	const actual = await importOriginal<typeof import("@singularityrd/aidr-core")>();
	return {
		...actual,
		initSentry: vi.fn(),
		verifyArtifactIntegrityAndLog: vi.fn(async (params: { artifactId: string }) => {
			if (integrity.hang) await new Promise(() => {});
			if (integrity.fail) {
				throw new actual.ArtifactIntegrityError(params.artifactId, { status: "hash_mismatch" });
			}
		}),
		scanProvisionedOutput: vi.fn(async () => undefined),
	};
});

vi.mock("../bundled-dirs.js", () => ({
	getBundledDataDirs: () => ({
		threatsDir: resolve(import.meta.dirname, "..", "..", "..", "..", "threats"),
		allowlistsDir: resolve(import.meta.dirname, "..", "..", "..", "..", "allowlists"),
	}),
	getAidrVersion: () => "0.0.0",
}));

import plugin from "../index.js";

// biome-ignore lint/suspicious/noExplicitAny: OpenClaw handler signatures vary by event
type Handler = (...args: any[]) => Promise<unknown>;

function registerPlugin() {
	const handlers = new Map<string, Handler>();
	const errors: string[] = [];
	plugin.register({
		logger: {
			info: () => undefined,
			warn: () => undefined,
			error: (message: string) => errors.push(message),
		},
		on: (event: string, handler: Handler) => handlers.set(event, handler),
		registerTool: () => undefined,
	});
	return { handlers, errors };
}

async function flush(): Promise<void> {
	await new Promise((done) => setImmediate(done));
}

describe("OpenClaw integrity failure", () => {
	afterEach(() => {
		integrity.fail = true;
		integrity.hang = false;
		vi.unstubAllEnvs();
	});

	it("blocks a tool call whose gate does not finish before the deadline", async () => {
		integrity.hang = true;
		vi.stubEnv("AIDR_TOOL_CALL_DEADLINE_MS", "100");
		const { handlers } = registerPlugin();
		const started = Date.now();
		const result = await handlers.get("before_tool_call")?.(
			{ toolName: "exec", params: { command: "ls" } },
			{},
		);
		expect(Date.now() - started).toBeGreaterThanOrEqual(90);
		expect(result).toEqual({ block: true, blockReason: expect.stringContaining("in time") });
	});

	it("does not leave an unhandled rejection when no tool call arrives", async () => {
		const unhandled: unknown[] = [];
		const listener = (reason: unknown) => unhandled.push(reason);
		process.on("unhandledRejection", listener);
		try {
			const { errors } = registerPlugin();
			await flush();
			await flush();
			expect(unhandled).toEqual([]);
			expect(errors.some((message) => message.includes("integrity verification failed"))).toBe(
				true,
			);
		} finally {
			process.off("unhandledRejection", listener);
		}
	});

	it("returns a block verdict from before_tool_call instead of throwing", async () => {
		const { handlers } = registerPlugin();
		const beforeToolCall = handlers.get("before_tool_call");
		expect(beforeToolCall).toBeTypeOf("function");
		const first = await beforeToolCall?.({ toolName: "exec", params: { command: "ls" } }, {});
		expect(first).toEqual({
			block: true,
			blockReason: expect.stringContaining("cannot verify its own installation"),
		});
		// It keeps blocking for later calls too.
		const second = await beforeToolCall?.({ toolName: "read", params: { path: "README.md" } }, {});
		expect(second).toMatchObject({ block: true });
	});

	it("other guarded surfaces still fail closed", async () => {
		const { handlers } = registerPlugin();
		await expect(handlers.get("message_sending")?.({ content: "hi" }, {})).rejects.toThrow(
			/integrity verification failed/i,
		);
	});

	it("passes through to the tool handler when integrity holds", async () => {
		integrity.fail = false;
		const { handlers } = registerPlugin();
		const result = await handlers.get("before_tool_call")?.(
			{ toolName: "read", params: { path: "README.md" } },
			{},
		);
		expect(result).toBeUndefined();
	});
});
