import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	AIDRMiddlewareError,
	createMiddleware,
	createSyncCompatibleMiddleware,
	type MiddlewareOptions,
} from "../adapters/generic.js";
import type { AIDRClient } from "../client.js";

const { scanCachedProvisionedOutput, scanProvisionedOutput } = vi.hoisted(() => ({
	scanCachedProvisionedOutput: vi.fn(),
	scanProvisionedOutput: vi.fn(),
}));

vi.mock("@singularityrd/aidr-core", async (importOriginal) => ({
	...(await importOriginal<typeof import("@singularityrd/aidr-core")>()),
	scanCachedProvisionedOutput,
	scanProvisionedOutput,
}));

const tenantFinding = {
	type: "secret_leak",
	severity: "critical",
	reason: "Tenant document is restricted",
	redactedExcerpt: "[REDACTED_DLP_SECRET]",
	ruleId: "tenant-document-dlp",
};
const output = {
	content: [
		{ type: "text", text: "tenant document 9Y" },
		{ type: "text", text: "47" },
	],
};
const context = {
	tool: "lookup",
	input: "query",
	metadata: { agentRuntime: "codex" },
};

function allowClient(): AIDRClient {
	return {
		check: vi.fn(async () => ({ allowed: true, decision: "allow", confidence: 1 })),
		assertCallerOperationAllowed: vi.fn(async () => {}),
	} as unknown as AIDRClient;
}

describe("provisioned middleware output policy", () => {
	beforeEach(() => {
		scanProvisionedOutput.mockReset();
		scanProvisionedOutput.mockResolvedValue([]);
		scanCachedProvisionedOutput.mockReset();
		scanCachedProvisionedOutput.mockReturnValue([tenantFinding]);
	});

	it.each([
		{ kind: "async", action: "block" },
		{ kind: "async", action: "redact" },
		{ kind: "sync", action: "block" },
		{ kind: "sync", action: "redact" },
	] as const)("$kind applies tenant DLP $action before delivery", async ({ kind, action }) => {
		const afterCheck = vi.fn();
		const options: MiddlewareOptions = {
			agentRuntime: "cursor",
			outputGuard: { maxBytes: 256, findingAction: action },
			afterCheck,
		};
		const middleware =
			kind === "async"
				? createMiddleware(allowClient(), options)
				: createSyncCompatibleMiddleware(allowClient(), options);
		options.agentRuntime = "codex";
		const delivered =
			typeof middleware === "function"
				? middleware(context, async () => output)
				: middleware.sync(context, () => output);

		if (action === "block") {
			await expect(delivered).rejects.toThrow(AIDRMiddlewareError);
			expect(afterCheck).toHaveBeenCalledWith(
				context,
				expect.objectContaining({ allowed: false, decision: "deny" }),
				undefined,
			);
			expect(afterCheck.mock.calls[0]?.[1].reason).toContain(tenantFinding.ruleId);
		} else {
			await expect(delivered).resolves.toBe("[AIDR REDACTED: findings]");
			expect(afterCheck.mock.calls[0]?.[2]).toBe("[AIDR REDACTED: findings]");
		}
		expect(afterCheck).toHaveBeenCalledTimes(1);
		expect(scanProvisionedOutput).toHaveBeenCalledExactlyOnceWith([], "cursor");
		expect(scanCachedProvisionedOutput).toHaveBeenCalledExactlyOnceWith(
			expect.arrayContaining(["tenant document 9Y47"]),
			"cursor",
		);
	});

	it("requires a runtime at construction even when request metadata spoofs one", async () => {
		const options: MiddlewareOptions = {};
		const middleware = createMiddleware(allowClient(), options);
		options.agentRuntime = "cursor";

		await expect(middleware(context, async () => output)).resolves.toBe(output);
		expect(scanProvisionedOutput).not.toHaveBeenCalled();
		expect(scanCachedProvisionedOutput).not.toHaveBeenCalled();
	});

	it("rejects oversized output after warmup without calling the cached scanner", async () => {
		const middleware = createSyncCompatibleMiddleware(allowClient(), {
			agentRuntime: "cursor",
			outputGuard: { maxBytes: 4 },
		});

		await expect(middleware.sync(context, () => output)).rejects.toThrow(AIDRMiddlewareError);
		expect(scanProvisionedOutput).toHaveBeenCalledExactlyOnceWith([], "cursor");
		expect(scanCachedProvisionedOutput).not.toHaveBeenCalled();
	});

	it("scans the output changed while provisioned policy is warming", async () => {
		let releaseWarm!: () => void;
		let markWarming!: () => void;
		const warming = new Promise<void>((resolve) => {
			markWarming = resolve;
		});
		const warmGate = new Promise<void>((resolve) => {
			releaseWarm = resolve;
		});
		scanProvisionedOutput.mockImplementationOnce(async () => {
			markWarming();
			await warmGate;
			return [];
		});
		scanCachedProvisionedOutput.mockImplementationOnce((views: string[]) =>
			views.includes("tenant document 9Y47") ? [tenantFinding] : [],
		);
		const firstBlock = { type: "text", text: "public document" };
		const secondBlock = { type: "text", text: " ok" };
		const mutableOutput = { content: [firstBlock, secondBlock] };
		const middleware = createMiddleware(allowClient(), { agentRuntime: "cursor" });
		const delivered = middleware(context, async () => mutableOutput);
		const blocked = expect(delivered).rejects.toThrow(AIDRMiddlewareError);

		await warming;
		firstBlock.text = "tenant document 9Y";
		secondBlock.text = "47";
		releaseWarm();
		await blocked;
		expect(scanProvisionedOutput).toHaveBeenCalledExactlyOnceWith([], "cursor");
		expect(scanCachedProvisionedOutput).toHaveBeenCalledExactlyOnceWith(
			expect.arrayContaining(["tenant document 9Y47"]),
			"cursor",
		);
	});

	it("fails closed when the warmed cached policy reports unavailable coverage", async () => {
		const unavailableFinding = {
			type: "inspection_incomplete",
			severity: "critical",
			reason: "Tenant output policy is unavailable",
			redactedExcerpt: "[REDACTED_UNINSPECTED_OUTPUT]",
			ruleId: "DLP-POLICY-UNAVAILABLE",
		};
		scanProvisionedOutput.mockResolvedValueOnce([unavailableFinding]);
		scanCachedProvisionedOutput.mockReturnValueOnce([unavailableFinding]);
		const afterCheck = vi.fn();
		const middleware = createMiddleware(allowClient(), { agentRuntime: "cursor", afterCheck });

		await expect(middleware(context, async () => output)).rejects.toThrow(AIDRMiddlewareError);
		expect(scanProvisionedOutput).toHaveBeenCalledExactlyOnceWith([], "cursor");
		expect(scanCachedProvisionedOutput).toHaveBeenCalledExactlyOnceWith(
			expect.arrayContaining(["tenant document 9Y47"]),
			"cursor",
		);
		expect(afterCheck.mock.calls[0]?.[1].reason).toContain(unavailableFinding.ruleId);
		expect(afterCheck.mock.calls[0]?.[2]).toBeUndefined();
	});

	it("blocks scanner failures without exposing the error or output to hooks", async () => {
		const sensitiveError = "SECRET_document_9Y47";
		scanProvisionedOutput.mockRejectedValueOnce(new Error(sensitiveError));
		const afterCheck = vi.fn();
		const middleware = createMiddleware(allowClient(), { agentRuntime: "cursor", afterCheck });

		await expect(middleware(context, async () => output)).rejects.toThrow(AIDRMiddlewareError);
		expect(afterCheck).toHaveBeenCalledWith(
			context,
			expect.objectContaining({
				allowed: false,
				decision: "deny",
				reason: expect.not.stringContaining(sensitiveError),
			}),
			undefined,
		);
		expect(afterCheck).toHaveBeenCalledTimes(1);
		expect(scanCachedProvisionedOutput).not.toHaveBeenCalled();
	});
});
