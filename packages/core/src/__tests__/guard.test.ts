import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ApprovalStore } from "../approval-store.js";
import {
	addToAllowlist,
	approveAction,
	formatAskMessage,
	formatDenyMessage,
	guardToolCall,
	removeFromAllowlist,
	summarizeArtifacts,
} from "../guard.js";
import type { Verdict } from "../types.js";

// Mock evaluator
vi.mock("../evaluator.js", async (importOriginal) => {
	const original = (await importOriginal()) as Record<string, unknown>;
	return {
		...original,
		evaluateToolCall: vi.fn(),
	};
});

// Mock config
vi.mock("../config.js", async (importOriginal) => {
	const original = (await importOriginal()) as Record<string, unknown>;
	return {
		...original,
		loadConfig: vi.fn(),
	};
});

// Mock allowlist
vi.mock("../allowlist.js", async (importOriginal) => {
	const original = (await importOriginal()) as Record<string, unknown>;
	return {
		...original,
		loadAllowlist: vi.fn(),
		saveAllowlist: vi.fn(),
		addUrl: vi.fn(),
		addCommand: vi.fn(),
		addFilePath: vi.fn(),
		removeUrl: vi.fn(),
		removeCommand: vi.fn(),
		removeFilePath: vi.fn(),
	};
});

const { evaluateToolCall } = await import("../evaluator.js");
const { loadConfig } = await import("../config.js");
const { loadAllowlist, saveAllowlist, removeUrl, removeCommand, removeFilePath } = await import(
	"../allowlist.js"
);

// Every `ask` is recorded in the operator approval store under $HOME; keep the
// suite away from the real ~/.singularity-aidr.
let isolatedHome: string;
let originalHome: string | undefined;
beforeAll(async () => {
	originalHome = process.env.HOME;
	isolatedHome = await mkdtemp(join(tmpdir(), "aidr-guard-home-"));
	process.env.HOME = isolatedHome;
});
afterAll(async () => {
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	await rm(isolatedHome, { recursive: true, force: true });
});

const mockEvaluate = vi.mocked(evaluateToolCall);
const mockLoadConfig = vi.mocked(loadConfig);
const mockLoadAllowlist = vi.mocked(loadAllowlist);
const mockSaveAllowlist = vi.mocked(saveAllowlist);
const mockRemoveUrl = vi.mocked(removeUrl);
const mockRemoveCommand = vi.mocked(removeCommand);
const mockRemoveFilePath = vi.mocked(removeFilePath);

function makeRequest(toolName = "bash", toolInput: Record<string, unknown> = { command: "ls" }) {
	return {
		sessionId: "s1",
		toolName,
		toolInput,
		artifacts: [{ type: "command" as const, value: "ls" }],
	};
}

function makeContext() {
	return { threatsDir: "/threats", allowlistsDir: "/allowlists" };
}

function makeVerdict(overrides: Partial<Verdict> = {}): Verdict {
	return {
		decision: "allow",
		category: "test",
		confidence: 0.9,
		severity: "info",
		source: "test",
		artifacts: [],
		matchedThreatId: null,
		reasons: ["test reason"],
		...overrides,
	};
}

describe("guardToolCall", () => {
	it("returns allow when action is already approved", async () => {
		const store = new ApprovalStore();
		const request = makeRequest();
		const actionId = ApprovalStore.actionId(request.toolName, request.toolInput, request.sessionId);

		// Pre-approve the action
		store.setPending(actionId, { artifacts: request.artifacts, createdAt: Date.now() });
		store.approve(actionId);
		mockEvaluate.mockResolvedValueOnce(makeVerdict({ decision: "ask" }));
		mockLoadConfig.mockResolvedValueOnce({} as Awaited<ReturnType<typeof loadConfig>>);

		const { verdict } = await guardToolCall(request, makeContext(), store);
		expect(verdict.decision).toBe("allow");
		expect(verdict.source).toBe("approved");
		expect(mockEvaluate).toHaveBeenCalledOnce();
	});

	it("runs the snapshot and signed audit path for an approved destructive retry", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-approved-response-"));
		try {
			const target = join(dir, "protected.txt");
			const chain = join(dir, "response-audit.jsonl");
			await writeFile(target, "original bytes", "utf8");
			const store = new ApprovalStore();
			const request = makeRequest("Delete", { file_path: target });
			const actionId = ApprovalStore.actionId(
				request.toolName,
				request.toolInput,
				request.sessionId,
			);
			store.setPending(actionId, { artifacts: request.artifacts, createdAt: Date.now() });
			store.approve(actionId);
			mockEvaluate.mockResolvedValueOnce(makeVerdict({ decision: "ask" }));
			mockLoadConfig.mockResolvedValueOnce({
				response: {
					actions: {
						snapshot_before_destructive: true,
						protect_paths: [dir],
						snapshot_root_dir: join(dir, "snapshots"),
					},
					audit: { signed_chain: true, path: chain },
				},
			} as Awaited<ReturnType<typeof loadConfig>>);

			const result = await guardToolCall(request, makeContext(), store);
			expect(result.verdict).toMatchObject({ decision: "allow", source: "approved" });
			expect(result.responseActions?.[0]).toMatchObject({ action: "snapshot", outcome: "success" });
			expect(result.snapshot?.target).toBe(target);
			expect(result.signedChain?.written).toBe(true);
			expect(await readFile(target, "utf8")).toBe("original bytes");
			expect(await readFile(chain, "utf8")).toContain('"action":"snapshot"');
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("consumes an approval after one matching retry", async () => {
		mockEvaluate.mockClear();
		const store = new ApprovalStore();
		const request = makeRequest();
		const actionId = ApprovalStore.actionId(request.toolName, request.toolInput, request.sessionId);
		store.setPending(actionId, { artifacts: request.artifacts, createdAt: Date.now() });
		store.approve(actionId);
		mockEvaluate
			.mockResolvedValueOnce(makeVerdict({ decision: "ask" }))
			.mockResolvedValueOnce(makeVerdict({ decision: "ask" }));
		mockLoadConfig
			.mockResolvedValueOnce({} as Awaited<ReturnType<typeof loadConfig>>)
			.mockResolvedValueOnce({} as Awaited<ReturnType<typeof loadConfig>>);

		const approvedRetry = await guardToolCall(request, makeContext(), store);
		const replay = await guardToolCall(request, makeContext(), store);

		expect(approvedRetry.verdict).toMatchObject({ decision: "allow", source: "approved" });
		expect(replay.verdict.decision).toBe("ask");
		expect(mockEvaluate).toHaveBeenCalledTimes(2);
	});

	it("does not let a prior approval override or survive a changed deny verdict", async () => {
		mockEvaluate.mockClear();
		const store = new ApprovalStore();
		const request = makeRequest();
		const actionId = ApprovalStore.actionId(request.toolName, request.toolInput, request.sessionId);
		store.setPending(actionId, { artifacts: request.artifacts, createdAt: Date.now() });
		store.approve(actionId);
		mockEvaluate
			.mockResolvedValueOnce(makeVerdict({ decision: "deny" }))
			.mockResolvedValueOnce(makeVerdict({ decision: "ask" }));
		mockLoadConfig
			.mockResolvedValueOnce({} as Awaited<ReturnType<typeof loadConfig>>)
			.mockResolvedValueOnce({} as Awaited<ReturnType<typeof loadConfig>>);

		const changedPolicy = await guardToolCall(request, makeContext(), store);
		const laterAsk = await guardToolCall(request, makeContext(), store);

		expect(changedPolicy.verdict.decision).toBe("deny");
		expect(laterAsk.verdict.decision).toBe("ask");
		expect(mockEvaluate).toHaveBeenCalledTimes(2);
	});

	it("delegates to evaluateToolCall and returns allow verdict", async () => {
		const store = new ApprovalStore();
		mockEvaluate.mockResolvedValueOnce(makeVerdict({ decision: "allow" }));

		const { verdict } = await guardToolCall(makeRequest(), makeContext(), store);
		expect(verdict.decision).toBe("allow");
		expect(mockEvaluate).toHaveBeenCalled();
	});

	it("returns deny verdict from evaluateToolCall", async () => {
		const store = new ApprovalStore();
		mockEvaluate.mockResolvedValueOnce(makeVerdict({ decision: "deny" }));

		const { verdict } = await guardToolCall(makeRequest(), makeContext(), store);
		expect(verdict.decision).toBe("deny");
	});

	it("promotes ask to deny in paranoid mode", async () => {
		const store = new ApprovalStore();
		mockEvaluate.mockResolvedValueOnce(makeVerdict({ decision: "ask" }));
		mockLoadConfig.mockResolvedValueOnce({ sensitivity: "paranoid" } as ReturnType<
			typeof loadConfig
		> extends Promise<infer T>
			? T
			: never);

		const { verdict } = await guardToolCall(makeRequest(), makeContext(), store);
		expect(verdict.decision).toBe("deny");
	});

	it("does not setPending when paranoid promotes ask to deny", async () => {
		const store = new ApprovalStore();
		const request = makeRequest();
		const actionId = ApprovalStore.actionId(request.toolName, request.toolInput, request.sessionId);

		mockEvaluate.mockResolvedValueOnce(makeVerdict({ decision: "ask" }));
		mockLoadConfig.mockResolvedValueOnce({ sensitivity: "paranoid" } as ReturnType<
			typeof loadConfig
		> extends Promise<infer T>
			? T
			: never);

		await guardToolCall(request, makeContext(), store);
		// Should not have a pending entry
		expect(store.approve(actionId)).toBeNull();
	});

	it("sets pending for ask verdict in non-paranoid mode", async () => {
		const store = new ApprovalStore();
		const request = makeRequest();
		const actionId = ApprovalStore.actionId(request.toolName, request.toolInput, request.sessionId);

		mockEvaluate.mockResolvedValueOnce(makeVerdict({ decision: "ask" }));
		mockLoadConfig.mockResolvedValueOnce({ sensitivity: "balanced" } as ReturnType<
			typeof loadConfig
		> extends Promise<infer T>
			? T
			: never);

		const { verdict, actionId: returnedActionId } = await guardToolCall(
			request,
			makeContext(),
			store,
		);
		expect(verdict.decision).toBe("ask");
		expect(returnedActionId).toBe(actionId);

		// Should have a pending entry
		const entry = store.approve(actionId);
		expect(entry).not.toBeNull();
	});
});

describe("formatDenyMessage", () => {
	it("formats deny message with reasons", () => {
		const msg = formatDenyMessage(makeVerdict({ decision: "deny", reasons: ["bad stuff"] }));
		expect(msg).toContain("Singularity AIDR blocked this action.");
		expect(msg).toContain("bad stuff");
	});

	it("falls back to category when no reasons", () => {
		const msg = formatDenyMessage(
			makeVerdict({ decision: "deny", reasons: [], category: "exfil" }),
		);
		expect(msg).toContain("exfil");
	});
});

describe("formatAskMessage", () => {
	it("formats ask message with an operator-only approval reference", () => {
		const msg = formatAskMessage("abc123", makeVerdict({ decision: "ask" }), [
			{ type: "command", value: "chmod 777 ./x" },
		]);
		expect(msg).toContain("abc123");
		expect(msg).toContain("command 'chmod 777 ./x'");
		expect(msg).toContain("stopped this action until you approve it");
		// The agent must not be handed a callable approval tool: an agent that can
		// approve its own blocked action defeats the gate entirely.
		expect(msg).not.toContain("aidr_approve");
		expect(msg).toContain("you cannot approve this action");
		expect(msg).not.toMatch(/call:\s*\n/);
	});
});

describe("summarizeArtifacts", () => {
	it("formats artifacts", () => {
		expect(
			summarizeArtifacts([
				{ type: "url", value: "https://x.com" },
				{ type: "command", value: "ls" },
			]),
		).toBe("url 'https://x.com', command 'ls'");
	});

	it("returns none for empty", () => {
		expect(summarizeArtifacts([])).toBe("none");
	});

	it("truncates at 3 artifacts", () => {
		const arts = Array.from({ length: 5 }, (_, i) => ({
			type: "url" as const,
			value: `http://${i}`,
		}));
		const result = summarizeArtifacts(arts);
		expect(result.split(", ")).toHaveLength(3);
	});

	it("truncates long artifact values", () => {
		const longValue = "x".repeat(200);
		const result = summarizeArtifacts([{ type: "command", value: longValue }]);
		expect(result.length).toBeLessThan(200);
		expect(result).toContain("…");
	});

	it("replaces newlines with escaped \\n in artifact values", () => {
		const result = summarizeArtifacts([{ type: "command", value: "line1\nline2\nline3" }]);
		expect(result).not.toContain("\n");
		expect(result).toContain("line1\\nline2\\nline3");
	});
});

describe("approveAction", () => {
	it("approves pending action", async () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			artifacts: [{ type: "command", value: "chmod 777 ./x" }],
			createdAt: Date.now(),
		});

		const msg = await approveAction(store, "a1");
		expect(msg).toContain("Approved action a1");
		expect(msg).toContain("Do NOT add it to the allowlist");
		expect(store.isApproved("a1")).toBe(true);
	});

	it("returns error for unknown actionId", async () => {
		const store = new ApprovalStore();
		const msg = await approveAction(store, "nonexistent");
		expect(msg).toContain("No pending Singularity AIDR approval");
	});
});

describe("addToAllowlist", () => {
	it("rejects when no approved artifact exists", async () => {
		const store = new ApprovalStore();
		const msg = await addToAllowlist(store, "url", "https://evil.test");
		expect(msg).toContain("no recent user approval");
	});

	it("adds to allowlist when artifact is approved", async () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			artifacts: [{ type: "url", value: "https://example.com" }],
			createdAt: Date.now(),
		});
		store.approve("a1");

		mockLoadConfig.mockResolvedValueOnce({
			allowlist: { path: "~/.singularity-aidr/allowlist.json" },
		} as ReturnType<typeof loadConfig> extends Promise<infer T> ? T : never);
		mockLoadAllowlist.mockResolvedValueOnce({ urls: {}, commands: {}, filePaths: {} });
		mockSaveAllowlist.mockResolvedValueOnce(true);

		const msg = await addToAllowlist(store, "url", "https://example.com");
		expect(msg).toContain("Added url to Singularity AIDR allowlist");
		// Artifact consumed
		expect(store.hasApprovedArtifact("url", "https://example.com")).toBe(false);
	});

	it("preserves approval token when save fails", async () => {
		const store = new ApprovalStore();
		store.setPending("a1", {
			artifacts: [{ type: "url", value: "https://example.com" }],
			createdAt: Date.now(),
		});
		store.approve("a1");

		mockLoadConfig.mockResolvedValueOnce({
			allowlist: { path: "~/.singularity-aidr/allowlist.json" },
		} as ReturnType<typeof loadConfig> extends Promise<infer T> ? T : never);
		mockLoadAllowlist.mockResolvedValueOnce({ urls: {}, commands: {}, filePaths: {} });
		mockSaveAllowlist.mockResolvedValueOnce(false);

		const msg = await addToAllowlist(store, "url", "https://example.com");
		expect(msg).toContain("Failed to save allowlist");
		// Approval token preserved for retry
		expect(store.hasApprovedArtifact("url", "https://example.com")).toBe(true);
	});
});

describe("removeFromAllowlist", () => {
	it("returns not found when entry doesn't exist", async () => {
		mockLoadConfig.mockResolvedValueOnce({
			allowlist: { path: "~/.singularity-aidr/allowlist.json" },
		} as ReturnType<typeof loadConfig> extends Promise<infer T> ? T : never);
		mockLoadAllowlist.mockResolvedValueOnce({ urls: {}, commands: {}, filePaths: {} });
		mockRemoveUrl.mockReturnValueOnce(false);

		const msg = await removeFromAllowlist("url", "https://nope.test");
		expect(msg).toContain("not found");
	});

	it("removes existing url entry", async () => {
		mockLoadConfig.mockResolvedValueOnce({
			allowlist: { path: "~/.singularity-aidr/allowlist.json" },
		} as ReturnType<typeof loadConfig> extends Promise<infer T> ? T : never);
		mockLoadAllowlist.mockResolvedValueOnce({ urls: {}, commands: {}, filePaths: {} });
		mockRemoveUrl.mockReturnValueOnce(true);
		mockSaveAllowlist.mockResolvedValueOnce(true);

		const msg = await removeFromAllowlist("url", "https://example.com");
		expect(msg).toContain("Removed url from Singularity AIDR allowlist");
	});

	it("tries hash fallback for command removal", async () => {
		mockLoadConfig.mockResolvedValueOnce({
			allowlist: { path: "~/.singularity-aidr/allowlist.json" },
		} as ReturnType<typeof loadConfig> extends Promise<infer T> ? T : never);
		mockLoadAllowlist.mockResolvedValueOnce({ urls: {}, commands: {}, filePaths: {} });
		mockRemoveCommand.mockReturnValueOnce(false); // first try: value itself
		mockRemoveCommand.mockReturnValueOnce(true); // second try: hash
		mockSaveAllowlist.mockResolvedValueOnce(true);

		const msg = await removeFromAllowlist("command", "chmod 777 ./x");
		expect(msg).toContain("Removed command from Singularity AIDR allowlist");
		expect(mockRemoveCommand).toHaveBeenCalledTimes(2);
	});

	it("removes file_path entry", async () => {
		mockLoadConfig.mockResolvedValueOnce({
			allowlist: { path: "~/.singularity-aidr/allowlist.json" },
		} as ReturnType<typeof loadConfig> extends Promise<infer T> ? T : never);
		mockLoadAllowlist.mockResolvedValueOnce({ urls: {}, commands: {}, filePaths: {} });
		mockRemoveFilePath.mockReturnValueOnce(true);
		mockSaveAllowlist.mockResolvedValueOnce(true);

		const msg = await removeFromAllowlist("file_path", "/etc/passwd");
		expect(msg).toContain("Removed file_path from Singularity AIDR allowlist");
	});

	it("returns failure message when save fails", async () => {
		mockLoadConfig.mockResolvedValueOnce({
			allowlist: { path: "~/.singularity-aidr/allowlist.json" },
		} as ReturnType<typeof loadConfig> extends Promise<infer T> ? T : never);
		mockLoadAllowlist.mockResolvedValueOnce({ urls: {}, commands: {}, filePaths: {} });
		mockRemoveUrl.mockReturnValueOnce(true);
		mockSaveAllowlist.mockResolvedValueOnce(false);

		const msg = await removeFromAllowlist("url", "https://example.com");
		expect(msg).toContain("Failed to save allowlist after removal");
	});

	it("renders command value directly when matched without hashing", async () => {
		mockLoadConfig.mockResolvedValueOnce({
			allowlist: { path: "~/.singularity-aidr/allowlist.json" },
		} as ReturnType<typeof loadConfig> extends Promise<infer T> ? T : never);
		mockLoadAllowlist.mockResolvedValueOnce({ urls: {}, commands: {}, filePaths: {} });
		// Value matched directly (e.g., it's already a hash in the allowlist)
		mockRemoveCommand.mockReturnValueOnce(true);
		mockSaveAllowlist.mockResolvedValueOnce(true);

		const hash = "abcdef012345678901234567890123456789";
		const msg = await removeFromAllowlist("command", hash);
		// Should render the value itself (truncated), not hash-of-hash
		expect(msg).toContain("abcdef012345...");
	});
});
