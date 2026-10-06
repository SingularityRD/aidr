import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { runInNewContext } from "node:vm";
import { transformSync } from "esbuild";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as outputInspection from "../output-inspection.js";

const mocks = vi.hoisted(() => ({ warm: vi.fn(), scan: vi.fn(), log: vi.fn() }));
vi.mock("@singularityrd/aidr-core", async (importOriginal) => ({
	...(await importOriginal<Record<string, unknown>>()),
	scanProvisionedOutput: mocks.warm,
	scanCachedProvisionedOutput: mocks.scan,
	loadConfig: vi.fn().mockResolvedValue({ logging: {} }),
	logVerdict: mocks.log,
}));

const MARKER = "TENANT-CONFIDENTIAL-MARKER";
const finding = {
	type: "secret_leak" as const,
	severity: "critical" as const,
	ruleId: "OUT-DLP-CUSTOM",
	reason: "Tenant output policy matched sensitive content",
	redactedExcerpt: "[REDACTED]",
};
const unavailable = {
	...finding,
	type: "inspection_incomplete" as const,
	ruleId: "OUT-DLP-UNAVAILABLE",
	reason: "Tenant output inspection is unavailable",
};

beforeEach(() => {
	mocks.warm.mockReset().mockResolvedValue([]);
	mocks.scan.mockReset().mockReturnValue([]);
	mocks.log.mockReset().mockResolvedValue(undefined);
});

const hookCode = transformSync(readFileSync(path.resolve(__dirname, "../aidr-hook.ts"), "utf8"), {
	format: "cjs",
	loader: "ts",
	target: "es2022",
}).code;

async function runHook(
	mode: "cursor" | "vscode",
	input: Record<string, unknown>,
	retainInputReference = false,
) {
	const stdin = new EventEmitter();
	const output: string[] = [];
	const inputJson = JSON.stringify(input);
	const module = { exports: {} as { runCli?: (args: string[]) => Promise<void> } };
	const modules: Record<string, unknown> = {
		"node:path": path,
		"@singularityrd/aidr-core": {
			createHostObservation: () => null,
			recordHostObservation: vi.fn(),
			verifyArtifactIntegrityAndLog: vi.fn().mockResolvedValue({ status: "skipped" }),
			scanProvisionedOutput: mocks.warm,
		},
		"./output-inspection.js": outputInspection,
	};
	runInNewContext(hookCode, {
		module,
		exports: module.exports,
		require: (name: string) => {
			if (!Object.hasOwn(modules, name)) throw new Error(`Unexpected import: ${name}`);
			return modules[name];
		},
		process: { stdin, stdout: { write: (chunk: string) => output.push(chunk) } },
		Buffer,
		JSON: {
			parse: (value: string) =>
				retainInputReference && value === inputJson ? input : JSON.parse(value),
			stringify: JSON.stringify,
		},
		__dirname: "/test",
	});
	const completion = module.exports.runCli?.([mode]);
	expect(completion).toBeDefined();
	await vi.waitFor(() => expect(stdin.listenerCount("end")).toBe(1));
	stdin.emit("data", Buffer.from(inputJson));
	stdin.emit("end");
	await completion;
	return JSON.parse(output.join("").trim()) as Record<string, unknown>;
}

describe("provisioned output adapter", () => {
	it("passes serialized and reconstructed adjacent MCP views with the host runtime", async () => {
		const output = {
			content: [
				{ type: "text", text: "TENANT-CONFIDENTIAL-" },
				{ type: "text", text: "MARKER" },
			],
		};
		outputInspection.inspectCachedProvisionedOutput(output, "cursor");
		expect(mocks.scan).toHaveBeenCalledWith([JSON.stringify(output), MARKER], "cursor");
	});

	it.each([new Blob(["opaque"]), "x".repeat(256 * 1024 + 1)])(
		"retains incomplete coverage for uninspectable or oversized outputs",
		async (output) => {
			expect(outputInspection.inspectCachedProvisionedOutput(output, "vscode").status).toBe(
				"coverage_limited",
			);
			expect(mocks.scan).not.toHaveBeenCalled();
		},
	);

	it("masks synchronous scanner failures", () => {
		mocks.scan.mockImplementation(() => {
			throw new Error(MARKER);
		});
		const result = outputInspection.inspectCachedProvisionedOutput(MARKER, "vscode");
		expect(result.status).toBe("coverage_limited");
		expect(JSON.stringify(result)).not.toContain(MARKER);
	});
});

describe("provisioned output hook routing", () => {
	it("quarantines Cursor MCP tenant findings and audits only safe metadata", async () => {
		mocks.scan.mockReturnValue([finding]);
		const response = await runHook("cursor", {
			hook_event_name: "postToolUse",
			conversation_id: "cursor-session",
			tool_name: "MCP:fetch",
			tool_output: MARKER,
		});
		expect(mocks.scan).toHaveBeenCalledWith([MARKER, ""], "cursor");
		expect(mocks.warm).toHaveBeenCalledWith([], "cursor");
		expect(response.updated_mcp_tool_output).toMatchObject({ isError: true });
		expect(JSON.stringify(response)).not.toContain(MARKER);
		expect(mocks.log).toHaveBeenCalledWith(
			{},
			"cursor-session",
			"ModelOutput",
			expect.objectContaining({ host: "cursor", tool: "MCP:fetch" }),
			expect.objectContaining({ decision: "deny", matchedThreatId: "OUT-DLP-CUSTOM" }),
		);
		expect(JSON.stringify(mocks.log.mock.calls)).not.toContain(MARKER);
	});

	it.each([finding, unavailable])("blocks VS Code processing for rule $ruleId", async (rule) => {
		mocks.scan.mockReturnValue([rule]);
		const response = await runHook("vscode", {
			hook_event_name: "PostToolUse",
			session_id: "vscode-session",
			tool_name: "fetch",
			tool_response: MARKER,
		});
		expect(mocks.scan).toHaveBeenCalledWith([MARKER, ""], "vscode");
		expect(mocks.warm).toHaveBeenCalledWith([], "vscode");
		expect(response).toMatchObject({ decision: "block" });
		expect(response.reason).toContain("does not replace output bytes");
		expect(JSON.stringify(response)).not.toContain(MARKER);
	});

	it("keeps Cursor assistant inspection explicitly observe-only", async () => {
		mocks.scan.mockReturnValue([finding]);
		const response = await runHook("cursor", {
			hook_event_name: "afterAgentResponse",
			text: MARKER,
		});
		expect(mocks.scan).toHaveBeenCalledWith([MARKER, ""], "cursor");
		expect(response.additional_context).toContain("observe_only");
		expect(response.additional_context).toContain("cannot block or rewrite");
		expect(JSON.stringify(response)).not.toContain(MARKER);
	});

	it("fails closed on scanner exceptions in the actual VS Code output hook", async () => {
		mocks.scan.mockImplementation(() => {
			throw new Error(MARKER);
		});
		const response = await runHook("vscode", {
			hook_event_name: "PostToolUse",
			tool_response: "output",
		});
		expect(response).toMatchObject({ decision: "block" });
		expect(response.reason).toContain("scanner failed");
		expect(JSON.stringify(response)).not.toContain(MARKER);
	});

	it("collects the current mutable output after the trust warmup finishes", async () => {
		const output = { content: [{ type: "text", text: "benign" }] };
		mocks.warm.mockImplementation(async () => {
			await Promise.resolve();
			output.content[0].text = MARKER;
			return [];
		});
		mocks.scan.mockImplementation((views: string[]) =>
			views.some((view) => view.includes(MARKER)) ? [finding] : [],
		);
		// Retain the parsed payload reference to model a live mutable host result.
		const response = await runHook(
			"cursor",
			{ hook_event_name: "postToolUse", tool_name: "MCP:fetch", tool_output: output },
			true,
		);
		expect(mocks.scan).toHaveBeenCalledWith([JSON.stringify(output), MARKER], "cursor");
		expect(response.updated_mcp_tool_output).toMatchObject({ isError: true });
		expect(JSON.stringify(response)).not.toContain(MARKER);
	});
});
