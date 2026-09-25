import { mkdtempSync, rmSync } from "node:fs";
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
	getAidrVersion: () => "0.0.0",
}));

import { ArtifactIntegrityError } from "@singularityrd/aidr-core";
import plugin from "../index.js";

type Handler = (...args: unknown[]) => Promise<unknown>;

function register() {
	const handlers = new Map<string, Handler[]>();
	const tools: Array<Record<string, unknown>> = [];
	const errors: string[] = [];
	const middlewares: Handler[] = [];
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
		registerAgentToolResultMiddleware(handler: Handler) {
			middlewares.push(handler);
		},
	});
	return { handlers, tools, errors, middlewares };
}

/** OpenClaw applies every middleware in order; the last replacement is what the model gets. */
async function expectQuarantined(middlewares: Handler[], expectedCode: string) {
	expect(middlewares.length).toBeGreaterThan(0);
	let result: unknown = { content: [{ type: "text", text: "aidr-benign-ok" }] };
	for (const middleware of middlewares) {
		const replaced = (await middleware(
			{ toolCallId: "call-init", toolName: "exec", result },
			{ runtime: "openclaw" },
		)) as { result?: unknown } | undefined;
		result = replaced?.result ?? result;
	}
	expect(JSON.stringify(result)).toContain(
		`Singularity AIDR quarantined this tool output before it reached the model: AIDR failed to initialise: ${expectedCode}`,
	);
	expect(JSON.stringify(result)).not.toContain("aidr-benign-ok");
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

let home = "";

beforeEach(() => {
	// The prompt gate reads the local config; never the developer's own.
	home = mkdtempSync(join(tmpdir(), "aidr-openclaw-init-"));
	vi.stubEnv("HOME", home);
	vi.stubEnv("USERPROFILE", home);
});

afterEach(() => {
	failures.integrity = undefined;
	failures.threatLoad = undefined;
	vi.unstubAllEnvs();
	rmSync(home, { recursive: true, force: true });
});

describe("OpenClaw plugin initialisation fails closed", () => {
	it("blocks every tool call when artifact integrity verification fails", async () => {
		failures.integrity = new ArtifactIntegrityError("openclaw/dist", {
			status: "bad_signature",
		});
		const { handlers, errors, middlewares } = register();
		// Only the integrity gate fails: the rest of the plugin registered normally.
		expect(errors).toEqual([]);
		await expectBlocked(handlers, "integrity_bad_signature");
		// A tool result the host produces anyway never reaches the model uninspected.
		await expectQuarantined(middlewares, "integrity_bad_signature");
		// The prompt gate cannot trust its inspection either: default policy blocks.
		const [promptGate] = handlers.get("before_agent_run") ?? [];
		await expect(promptGate?.({ prompt: "hello", messages: [] }, {})).resolves.toMatchObject({
			outcome: "block",
			reason: "aidr_prompt_protection:not_inspected",
		});
	});

	it("still registers a blocking gate when threat resources cannot be loaded", async () => {
		failures.threatLoad = Object.assign(
			new Error("ENOENT: no such file or directory, scandir '/secret/path/threats'"),
			{ code: "ENOENT" },
		);
		const { handlers, tools, errors, middlewares } = register();
		await expectBlocked(handlers, "ENOENT");
		await expectQuarantined(middlewares, "ENOENT");
		// The failed plugin exposes no allowlist tools and no hooks beyond the two gates.
		expect(tools).toEqual([]);
		expect([...handlers.keys()]).toEqual(["before_tool_call", "before_agent_run"]);
		// Prompts cannot be inspected: the default policy (secrets: block) blocks them.
		const [promptGate] = handlers.get("before_agent_run") ?? [];
		await expect(promptGate?.({ prompt: "hello", messages: [] }, {})).resolves.toMatchObject({
			outcome: "block",
			reason: "aidr_prompt_protection:not_inspected",
		});
		// Raw error text stays in the host log; the agent-visible reason is only the code.
		expect(errors.join("\n")).toContain("/secret/path");
		const [gate] = handlers.get("before_tool_call") ?? [];
		expect(JSON.stringify(await gate?.({ toolName: "exec", params: {} }))).not.toContain(
			"/secret/path",
		);
	});
});
