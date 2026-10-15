import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { runInNewContext } from "node:vm";
import type { OutputFinding } from "@singularityrd/aidr-core";
import { transformSync } from "esbuild";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { toolNameFromInputPrefix } from "../hook-input.js";
import {
	inspectCachedProvisionedToolResponse,
	postToolInspectionUnavailable,
	scanCachedProvisionedToolResponse,
	toolResponseInspectionResult,
} from "../output-inspection.js";
import {
	appendPostToolContext,
	quarantineFailedToolInspection,
	quarantineInspectedToolOutput,
} from "../tool-output-quarantine.js";

const { scanProvisionedOutput, scanCachedProvisionedOutput } = vi.hoisted(() => ({
	scanProvisionedOutput: vi.fn(),
	scanCachedProvisionedOutput: vi.fn(),
}));
vi.mock("@singularityrd/aidr-core", async (importOriginal) => ({
	...(await importOriginal<Record<string, unknown>>()),
	scanProvisionedOutput,
	scanCachedProvisionedOutput,
}));

const hookCode = transformSync(readFileSync(resolve(__dirname, "../post-tool-use.ts"), "utf8"), {
	format: "cjs",
	loader: "ts",
	target: "es2020",
}).code;

const customFinding: OutputFinding = {
	type: "secret_leak",
	severity: "critical",
	ruleId: "OUT-DLP-CUSTOM",
	reason: "Tenant output DLP policy matched",
	redactedExcerpt: "[REDACTED_DLP]",
};

interface RunHookOptions {
	toolName?: string;
	deadlineMs?: number;
	/** Canary bookkeeping never settles, after the output verdict is known. */
	hangBookkeeping?: boolean;
	/** Replaces the parsed stdin result (e.g. oversized or never-ending input). */
	readInput?: (progress: { prefix: string }) => Promise<unknown>;
}

async function runHook(toolResponse: unknown, options: RunHookOptions = {}) {
	const log = vi.fn();
	const logger = { warn: log, error: log, info: log, debug: log };
	const pino = Object.assign(() => logger, { destination: () => ({}) });
	const modules: Record<string, unknown> = {
		"@singularityrd/aidr-core": {
			verifyArtifactIntegrityAndLog: vi.fn().mockResolvedValue({ status: "skipped" }),
			scanProvisionedOutput,
			// Session-flow, canary and outcome feeds are observation only here.
			recordToolOutcome: vi.fn().mockResolvedValue(undefined),
			recordToolOutputCanaries: options.hangBookkeeping
				? () => new Promise(() => {})
				: vi.fn().mockResolvedValue(undefined),
			recordToolOutputFlow: vi.fn().mockResolvedValue(undefined),
			toolResultReportsFailure: () => false,
			// The hook exits after answering; the sandbox has no process to end.
			exitAfterStdoutFlush: vi.fn(),
			resolveHookDeadlineMs: () => options.deadlineMs ?? 4_000,
			// File quarantine is off by default and never changes this response.
			quarantineAgentWrittenFiles: vi.fn().mockResolvedValue({
				enabled: false,
				scanned: [],
				quarantined: [],
				skipped: [],
				agentNotice: null,
			}),
		},
		pino,
		"./assets.js": { resolveAssetDir: () => "/threats" },
		"./approval-tracker.js": { consumePendingApproval: async () => null },
		"./format.js": { artifactTypeLabel: (value: string) => value },
		"./hook-input.js": {
			resolvePostToolInputLimit: () => 16 * 1024 * 1024,
			toolNameFromInputPrefix,
			readPostToolStdin: async (
				_maxBytes: number,
				_stream: unknown,
				progress: { prefix: string },
			) =>
				options.readInput
					? options.readInput(progress)
					: {
							status: "parsed",
							value: {
								tool_use_id: "tool-1",
								session_id: "session-1",
								...(options.toolName ? { tool_name: options.toolName } : {}),
								tool_response: toolResponse,
							},
						},
		},
		"./output-inspection.js": {
			postToolInspectionUnavailable,
			scanCachedProvisionedToolResponse,
			toolResponseInspectionResult,
		},
		"./tool-output-quarantine.js": {
			appendPostToolContext,
			quarantineFailedToolInspection,
			quarantineInspectedToolOutput,
		},
	};
	const response = await new Promise<Record<string, unknown>>((done) => {
		const module = { exports: {} };
		runInNewContext(hookCode, {
			module,
			exports: module.exports,
			require: (name: string) => {
				if (!Object.hasOwn(modules, name)) throw new Error(`Unexpected hook import: ${name}`);
				return modules[name];
			},
			process: {
				env: {},
				stdin: {},
				stdout: { write: (chunk: string) => done(JSON.parse(chunk)) },
			},
			setTimeout,
			clearTimeout,
			__dirname: "/test",
		});
	});
	return { response, log };
}

beforeEach(() => {
	scanProvisionedOutput.mockReset();
	scanProvisionedOutput.mockResolvedValue([]);
	scanCachedProvisionedOutput.mockReset();
	scanCachedProvisionedOutput.mockReturnValue([]);
});

describe("Claude signed tenant output policy", () => {
	it("passes joined MCP text views to the cached signed scanner and deduplicates feedback", () => {
		scanCachedProvisionedOutput.mockReturnValue([customFinding, customFinding]);
		const response = inspectCachedProvisionedToolResponse({
			content: [
				{ type: "text", text: "PRIVATE_" },
				{ type: "text", text: "PROGRAM_42" },
			],
		});
		expect(scanCachedProvisionedOutput).toHaveBeenCalledWith(
			[expect.any(String), "PRIVATE_PROGRAM_42"],
			"claude-code",
		);
		expect(response?.decision).toBe("block");
		expect(String(response?.reason).match(/OUT-DLP-CUSTOM/g)).toHaveLength(1);
		expect(JSON.stringify(response)).not.toContain("PRIVATE_PROGRAM_42");
	});

	it("still verifies signed policy for an empty tool response", async () => {
		const { response } = await runHook(null);
		expect(response).toEqual({});
		expect(scanProvisionedOutput).toHaveBeenCalledWith([], "claude-code");
		expect(scanCachedProvisionedOutput).toHaveBeenCalledWith(["", ""], "claude-code");
	});

	it("awaits tenant output findings and quarantines original MCP bytes", async () => {
		scanProvisionedOutput.mockImplementation(async () => {
			await Promise.resolve();
			return [];
		});
		scanCachedProvisionedOutput.mockReturnValue([customFinding]);
		const { response, log } = await runHook({
			content: [{ type: "text", text: "PRIVATE_PROGRAM_42" }],
			isError: false,
		});
		expect(response.decision).toBe("block");
		expect(response.hookSpecificOutput).toMatchObject({
			hookEventName: "PostToolUse",
			updatedToolOutput: { isError: true, content: [{ type: "text", text: expect.any(String) }] },
		});
		expect(scanProvisionedOutput).toHaveBeenCalledOnce();
		expect(JSON.stringify(response)).not.toContain("PRIVATE_PROGRAM_42");
		expect(log).not.toHaveBeenCalled();
	});

	it("inspects the current payload after policy warmup resolves", async () => {
		const original = { stdout: "Build succeeded" };
		scanProvisionedOutput.mockImplementation(async () => {
			await Promise.resolve();
			original.stdout = "PRIVATE_PROGRAM_42";
			return [];
		});
		scanCachedProvisionedOutput.mockImplementation((views: string[]) =>
			views.some((view) => view.includes("PRIVATE_PROGRAM_42")) ? [customFinding] : [],
		);
		const { response } = await runHook(original);
		expect(response.decision).toBe("block");
		expect(response.hookSpecificOutput).toHaveProperty("updatedToolOutput.stdout");
		expect(JSON.stringify(response)).not.toContain("PRIVATE_PROGRAM_42");
	});

	it("quarantines before a microtask can change the already inspected output shape", async () => {
		const original: Record<string, unknown> = { stdout: "PRIVATE_PROGRAM_42" };
		scanCachedProvisionedOutput.mockImplementation(() => {
			queueMicrotask(() => {
				original.unknownPrivateField = "LATE_PRIVATE_PROGRAM";
			});
			return [customFinding];
		});
		const { response } = await runHook(original);
		expect(response.decision).toBe("block");
		expect(response.hookSpecificOutput).toHaveProperty("updatedToolOutput.stdout");
		expect(JSON.stringify(response)).not.toMatch(/PRIVATE_PROGRAM_42|LATE_PRIVATE_PROGRAM/);
	});

	it("quarantines Bash output when signed policy trust is unavailable", async () => {
		scanCachedProvisionedOutput.mockReturnValue([
			{
				...customFinding,
				type: "inspection_incomplete",
				ruleId: "OUT-DLP-UNAVAILABLE",
				reason: "Tenant output DLP inspection is unavailable",
			},
		]);
		const { response, log } = await runHook({ stdout: "PRIVATE_PROGRAM_42", stderr: "" });
		expect(response.decision).toBe("block");
		expect(response.hookSpecificOutput).toHaveProperty("updatedToolOutput.stdout");
		expect(JSON.stringify(response)).toContain("OUT-DLP-UNAVAILABLE");
		expect(JSON.stringify(response)).not.toContain("PRIVATE_PROGRAM_42");
		expect(log).not.toHaveBeenCalled();
	});

	it("quarantines scanner failures without exposing output or exception details", async () => {
		scanProvisionedOutput.mockRejectedValue(new Error("private-policy-reason"));
		const { response, log } = await runHook({ stdout: "PRIVATE_PROGRAM_42" });
		expect(response.decision).toBe("block");
		expect(response.hookSpecificOutput).toHaveProperty("updatedToolOutput.stdout");
		expect(JSON.stringify(response)).not.toMatch(/PRIVATE_PROGRAM_42|private-policy-reason/);
		expect(log).not.toHaveBeenCalled();
	});

	it("retains a block and reports unavailable replacement for an unsupported result schema", async () => {
		scanCachedProvisionedOutput.mockReturnValue([customFinding]);
		const { response } = await runHook({ privateField: "PRIVATE_PROGRAM_42" });
		expect(response.decision).toBe("block");
		expect(response.hookSpecificOutput).not.toHaveProperty("updatedToolOutput");
		expect(response.hookSpecificOutput).toHaveProperty(
			"additionalContext",
			expect.stringContaining("original output may remain available to the host"),
		);
		expect(JSON.stringify(response)).not.toContain("PRIVATE_PROGRAM_42");
	});
});

describe("Claude PostToolUse fails closed when inspection cannot finish (CON-9)", () => {
	const secretMarker = "PRIVATE_PROGRAM_42";

	it("withholds parsed Bash output when the deadline passes during inspection", async () => {
		// Policy warmup never resolves: only the watchdog can answer.
		scanProvisionedOutput.mockImplementation(() => new Promise(() => {}));
		const { response } = await runHook(
			{ stdout: `build log ... ${secretMarker}`, stderr: "", interrupted: false },
			{ toolName: "Bash", deadlineMs: 20 },
		);
		expect(response.decision).toBe("block");
		expect(String(response.reason)).toContain("did not finish in time");
		expect(response.hookSpecificOutput).toMatchObject({
			hookEventName: "PostToolUse",
			updatedToolOutput: { stdout: expect.stringContaining("quarantined"), interrupted: false },
		});
		expect(JSON.stringify(response)).not.toContain(secretMarker);
	});

	it("withholds MCP output of an unknown shape when the deadline passes", async () => {
		scanProvisionedOutput.mockImplementation(() => new Promise(() => {}));
		const { response } = await runHook(
			{ structured: { token: secretMarker } },
			{ toolName: "mcp__docs__lookup", deadlineMs: 20 },
		);
		expect(response.hookSpecificOutput).toMatchObject({
			updatedToolOutput: [{ type: "text", text: expect.stringContaining("quarantined") }],
		});
		expect(JSON.stringify(response)).not.toContain(secretMarker);
	});

	it("answers with the settled verdict when only later bookkeeping overruns the deadline", async () => {
		const clean = await runHook(
			{ stdout: "Build succeeded" },
			{ toolName: "Bash", deadlineMs: 20, hangBookkeeping: true },
		);
		expect(clean.response).toEqual({});

		scanCachedProvisionedOutput.mockReturnValue([customFinding]);
		const risky = await runHook(
			{ stdout: secretMarker },
			{ toolName: "Bash", deadlineMs: 20, hangBookkeeping: true },
		);
		expect(risky.response.hookSpecificOutput).toHaveProperty("updatedToolOutput.stdout");
		expect(JSON.stringify(risky.response)).toContain("OUT-DLP-CUSTOM");
		expect(JSON.stringify(risky.response)).not.toContain(secretMarker);
	});

	it("names the tool from the input prefix when stdin never finishes", async () => {
		const { response } = await runHook(undefined, {
			deadlineMs: 20,
			readInput: (progress) => {
				progress.prefix = `{"session_id":"s","tool_name":"Bash","tool_input":{},"tool_response":{"stdout":"${secretMarker}`;
				return new Promise(() => {});
			},
		});
		expect(response.decision).toBe("block");
		expect(response.hookSpecificOutput).toMatchObject({
			updatedToolOutput: { stdout: expect.any(String), stderr: "", interrupted: false },
		});
		expect(JSON.stringify(response)).not.toContain(secretMarker);
	});

	it("replaces oversized MCP input it could not parse", async () => {
		const { response } = await runHook(undefined, {
			readInput: async (progress) => {
				progress.prefix = `{"tool_name":"mcp__evil__dump","tool_response":[{"type":"text","text":"${secretMarker}`;
				return { status: "oversized" };
			},
		});
		expect(String(response.reason)).toContain("processing limit");
		expect(response.hookSpecificOutput).toMatchObject({
			updatedToolOutput: [{ type: "text", text: expect.stringContaining("quarantined") }],
		});
		expect(JSON.stringify(response)).not.toContain(secretMarker);
	});

	it("says plainly when an unparsed built-in result cannot be replaced", async () => {
		const { response } = await runHook(undefined, {
			readInput: async (progress) => {
				progress.prefix = '{"tool_name":"WebFetch","tool_response":{';
				return { status: "oversized" };
			},
		});
		expect(response.decision).toBe("block");
		expect(response.hookSpecificOutput).not.toHaveProperty("updatedToolOutput");
		expect(JSON.stringify(response)).toContain("Replacement unavailable");
	});
});
