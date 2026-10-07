import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { runInNewContext } from "node:vm";
import type { OutputFinding } from "@singularityrd/aidr-core";
import { transformSync } from "esbuild";
import { beforeEach, describe, expect, it, vi } from "vitest";
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

async function runHook(toolResponse: unknown) {
	const log = vi.fn();
	const logger = { warn: log, error: log, info: log, debug: log };
	const pino = Object.assign(() => logger, { destination: () => ({}) });
	const modules: Record<string, unknown> = {
		"@singularityrd/aidr-core": {
			verifyArtifactIntegrityAndLog: vi.fn().mockResolvedValue({ status: "skipped" }),
			scanProvisionedOutput,
			// Session-flow, canary and outcome feeds are observation only here.
			recordToolOutcome: vi.fn().mockResolvedValue(undefined),
			recordToolOutputCanaries: vi.fn().mockResolvedValue(undefined),
			recordToolOutputFlow: vi.fn().mockResolvedValue(undefined),
			toolResultReportsFailure: () => false,
			// The hook exits after answering; the sandbox has no process to end.
			exitAfterStdoutFlush: vi.fn(),
			resolveHookDeadlineMs: () => 4_000,
		},
		pino,
		"./approval-tracker.js": { consumePendingApproval: async () => null },
		"./format.js": { artifactTypeLabel: (value: string) => value },
		"./hook-input.js": {
			readStdinJson: async () => ({
				status: "parsed",
				value: { tool_use_id: "tool-1", session_id: "session-1", tool_response: toolResponse },
			}),
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
			process: { env: {}, stdout: { write: (chunk: string) => done(JSON.parse(chunk)) } },
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
