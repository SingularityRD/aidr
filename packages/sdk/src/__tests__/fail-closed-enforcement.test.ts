/**
 * Fail-closed enforcement tests for the AIDR SDK.
 *
 * These lock in the semantic documented in `packages/sdk/README.md` and
 * implemented in `src/enforcement.ts`: a wrapped function, tool, agent message
 * or HTTP request executes ONLY on an explicit `allow` verdict — or on an `ask`
 * verdict that a caller-supplied `onAsk` callback explicitly approved. `deny`
 * is never approvable, and an indeterminate (failed / inconsistent) check is
 * never approvable by default.
 *
 * This file is the permanent replacement for the reproduction test that
 * demonstrated the original defect (`ask` and failed checks executed the
 * wrapped function). One test per adapter, per the AIDR-018 acceptance
 * criteria.
 */

import { describe, expect, it, vi } from "vitest";
import { AIDRSpeaker } from "../adapters/autogen.js";
import {
	AIDRCrewSecurityError,
	AIDRCrewTool,
	wrapCrewAgentWithAIDR,
} from "../adapters/crewai.js";
import {
	AIDRMiddlewareError,
	createMiddleware as createGenericMiddleware,
} from "../adapters/generic.js";
import { AIDRSecurityError, withAIDR } from "../adapters/langchain.js";
import { AIDRLlamaIndexError, withAIDRLlamaIndex } from "../adapters/llamaindex.js";
import { AIDRClient } from "../client.js";
import type { CheckRequest, CheckResult, SDKConfig } from "../config.js";
import { createMiddleware } from "../middleware.js";

const ALLOW: CheckResult = { allowed: true, decision: "allow", confidence: 0.95 };
const ASK: CheckResult = {
	allowed: false,
	decision: "ask",
	confidence: 0.8,
	reason: "Suspicious pattern",
};
const DENY: CheckResult = {
	allowed: false,
	decision: "deny",
	confidence: 0.95,
	reason: "Malicious input detected",
};
const INDETERMINATE: CheckResult = {
	allowed: false,
	decision: "ask",
	confidence: 0.5,
	reason: "Check failed after 3 attempts: socket hang up",
	metadata: { indeterminate: true, attempts: 3 },
};
const INCONSISTENT: CheckResult = {
	allowed: true,
	decision: "ask",
	confidence: 0.8,
	reason: "allowed and decision disagree",
};

class MockAIDRClient {
	result: CheckResult;
	responder?: (request: CheckRequest) => CheckResult;
	check = vi.fn(
		async (request: CheckRequest): Promise<CheckResult> =>
			this.responder ? this.responder(request) : this.result,
	);

	constructor(result: CheckResult = ALLOW) {
		this.result = result;
	}
}

function asClient(client: MockAIDRClient): AIDRClient {
	return client as unknown as AIDRClient;
}

function expressHarness() {
	const json = vi.fn();
	const res = { status: vi.fn().mockReturnValue({ json }) };
	const next = vi.fn();
	return { res, next, json };
}

describe("SDK middleware: wrap() is fail-closed", () => {
	function wrapWith(result: CheckResult, options?: Parameters<typeof createMiddleware>[1]) {
		const client = new MockAIDRClient(result);
		const middleware = createMiddleware(asClient(client), options);
		const executed = vi.fn().mockReturnValue("EXECUTED");
		const wrapped = middleware.wrap(executed, () => ({
			action: "execute",
			resource: "suspicious-command",
		}));
		return { wrapped, executed };
	}

	it("does not execute the wrapped function on an ask verdict", async () => {
		const { wrapped, executed } = wrapWith(ASK);

		await expect(wrapped()).rejects.toThrow(/requires explicit human approval/);
		expect(executed).not.toHaveBeenCalled();
	});

	it("executes on an ask verdict only when the caller-supplied onAsk approves", async () => {
		const onAsk = vi.fn().mockResolvedValue(true);
		const { wrapped, executed } = wrapWith(ASK, { onAsk });

		await expect(wrapped()).resolves.toBe("EXECUTED");
		expect(onAsk).toHaveBeenCalledTimes(1);
		expect(onAsk.mock.calls[0]?.[0]).toMatchObject({ decision: "ask" });
		expect(executed).toHaveBeenCalledTimes(1);
	});

	it("blocks when onAsk declines", async () => {
		const { wrapped, executed } = wrapWith(ASK, { onAsk: async () => false });

		await expect(wrapped()).rejects.toThrow(/was not granted/);
		expect(executed).not.toHaveBeenCalled();
	});

	it("never executes a deny verdict, even with an approving onAsk", async () => {
		const onAsk = vi.fn().mockResolvedValue(true);
		const { wrapped, executed } = wrapWith(DENY, { onAsk });

		await expect(wrapped()).rejects.toThrow("Security check denied");
		expect(onAsk).not.toHaveBeenCalled();
		expect(executed).not.toHaveBeenCalled();
	});

	it("does not approve an indeterminate (failed check) result by default", async () => {
		const onAsk = vi.fn().mockResolvedValue(true);
		const { wrapped, executed } = wrapWith(INDETERMINATE, { onAsk });

		await expect(wrapped()).rejects.toThrow(/could not be completed/);
		expect(onAsk).not.toHaveBeenCalled();
		expect(executed).not.toHaveBeenCalled();
	});

	it("blocks an indeterminate result when no approval callback is configured", async () => {
		const { wrapped, executed } = wrapWith(INDETERMINATE);

		await expect(wrapped()).rejects.toThrow(/could not be completed/);
		expect(executed).not.toHaveBeenCalled();
	});

	it("approves an indeterminate result only with the explicit opt-in", async () => {
		const onAsk = vi.fn().mockResolvedValue(true);
		const { wrapped, executed } = wrapWith(INDETERMINATE, {
			onAsk,
			allowApprovalOfIndeterminateResults: true,
		});

		await expect(wrapped()).resolves.toBe("EXECUTED");
		expect(onAsk).toHaveBeenCalledTimes(1);
		expect(executed).toHaveBeenCalledTimes(1);
	});

	it("never executes an inconsistent result (allowed disagrees with decision)", async () => {
		const { wrapped, executed } = wrapWith(INCONSISTENT, { onAsk: async () => true });

		await expect(wrapped()).rejects.toThrow(/inconsistent result/);
		expect(executed).not.toHaveBeenCalled();
	});

	it("never executes after the real client exhausts its retries on a failed check", async () => {
		const config: SDKConfig = {
			apiKey: "test-key",
			timeout: 5000,
			retries: 0,
			cache: false,
			cacheTtl: 300000,
			environment: "production",
		};
		const client = new AIDRClient(config);

		// Force the internal check to fail so the real retry loop and the real
		// fail-closed fallback construction run. init() is stubbed to keep this
		// test independent of the working directory's threat data.
		const internal = client as unknown as {
			initialized: boolean;
			init: () => Promise<void>;
			_performCheck: () => Promise<CheckResult>;
		};
		internal.initialized = true;
		internal.init = async () => {};
		internal._performCheck = async () => {
			throw new Error("socket hang up");
		};

		const fallback = await client.check({ action: "execute", resource: "rm -rf /" });
		expect(fallback.allowed).toBe(false);
		expect(fallback.decision).toBe("ask");
		expect(fallback.metadata?.indeterminate).toBe(true);

		const executed = vi.fn().mockReturnValue("EXECUTED");
		const wrapped = createMiddleware(client).wrap(executed, () => ({
			action: "execute",
			resource: "rm -rf /",
		}));

		await expect(wrapped()).rejects.toThrow(/could not be completed/);
		expect(executed).not.toHaveBeenCalled();
		client.dispose();
	});
});

describe("SDK middleware: express()/nextjs() are fail-closed", () => {
	it("returns 403 with an approval reason for an ask verdict", async () => {
		const client = new MockAIDRClient(ASK);
		const middleware = createMiddleware(asClient(client));
		const { res, next, json } = expressHarness();

		await middleware.express()({ method: "POST", url: "/api/admin" }, res, next);

		expect(next).not.toHaveBeenCalled();
		expect(res.status).toHaveBeenCalledWith(403);
		expect(json.mock.calls[0]?.[0]).toMatchObject({
			error: "Security check failed",
			reason: expect.stringMatching(/requires explicit human approval/),
		});
	});

	it("lets an ask verdict through when onAsk approves", async () => {
		const client = new MockAIDRClient(ASK);
		const middleware = createMiddleware(asClient(client), { onAsk: async () => true });
		const { res, next } = expressHarness();

		await middleware.express()({ method: "POST", url: "/api/admin" }, res, next);

		expect(res.status).not.toHaveBeenCalled();
		expect(next).toHaveBeenCalledWith();
	});

	it("returns 403 for an indeterminate (failed check) result", async () => {
		const client = new MockAIDRClient(INDETERMINATE);
		const middleware = createMiddleware(asClient(client));
		const { res, next, json } = expressHarness();

		await middleware.express()({ method: "GET", url: "/api/data" }, res, next);

		expect(next).not.toHaveBeenCalled();
		expect(res.status).toHaveBeenCalledWith(403);
		expect(json.mock.calls[0]?.[0]).toMatchObject({
			reason: expect.stringMatching(/could not be completed/),
		});
	});

	it("returns a 403 response for an ask verdict", async () => {
		const client = new MockAIDRClient(ASK);
		const middleware = createMiddleware(asClient(client));

		const response = await middleware.nextjs()(
			new Request("https://example.com/api/admin", { method: "POST" }),
		);

		expect(response).toBeInstanceOf(Response);
		expect(response?.status).toBe(403);
		await expect(response?.json()).resolves.toMatchObject({
			reason: expect.stringMatching(/requires explicit human approval/),
		});
	});

	it("continues to the handler when onAsk approves (nextjs)", async () => {
		const client = new MockAIDRClient(ASK);
		const middleware = createMiddleware(asClient(client), { onAsk: async () => true });

		const response = await middleware.nextjs()(
			new Request("https://example.com/api/admin", { method: "POST" }),
		);

		expect(response).toBeNull();
	});
});

describe("LangChain adapter is fail-closed", () => {
	class MockTool {
		name = "MockTool";
		description = "A mock tool for testing";
		lc_namespace = ["mock"];
		invoke = vi.fn(async (args: unknown) => `executed:${JSON.stringify(args)}`);
	}

	function makeTool(result: CheckResult, options?: Parameters<typeof withAIDR>[2]) {
		const client = new MockAIDRClient(result);
		const inner = new MockTool();
		const secureTool = withAIDR(
			inner as unknown as import("@langchain/core/tools").BaseTool,
			asClient(client),
			options,
		);
		return { secureTool, inner };
	}

	it("blocks an ask verdict without executing the inner tool", async () => {
		const { secureTool, inner } = makeTool(ASK);

		const result = await secureTool.invoke("suspicious");

		expect(result.allowed).toBe(false);
		expect(result.output).toMatch(/^\[DENIED\]/);
		expect(inner.invoke).not.toHaveBeenCalled();
	});

	it("executes an ask verdict when onAsk approves", async () => {
		const { secureTool, inner } = makeTool(ASK, { onAsk: async () => true });

		const result = await secureTool.invoke("suspicious");

		expect(result.allowed).toBe(true);
		expect(inner.invoke).toHaveBeenCalledTimes(1);
	});

	it("never executes a deny verdict, even with an approving onAsk", async () => {
		const onAsk = vi.fn().mockResolvedValue(true);
		const { secureTool, inner } = makeTool(DENY, { onAsk });

		await expect(secureTool.invoke("malicious")).rejects.toThrow(AIDRSecurityError);
		expect(onAsk).not.toHaveBeenCalled();
		expect(inner.invoke).not.toHaveBeenCalled();
	});

	it("does not approve an indeterminate result by default", async () => {
		const { secureTool, inner } = makeTool(INDETERMINATE, { onAsk: async () => true });

		const result = await secureTool.invoke("unknown");

		expect(result.allowed).toBe(false);
		expect(inner.invoke).not.toHaveBeenCalled();
	});
});

describe("generic middleware adapter is fail-closed", () => {
	const context = { tool: "bash", input: "chmod 777 ./x" };

	it("throws and never calls next() for an ask verdict", async () => {
		const client = new MockAIDRClient(ASK);
		const middleware = createGenericMiddleware(asClient(client));
		const next = vi.fn().mockResolvedValue("EXECUTED");

		await expect(middleware(context, next)).rejects.toThrow(AIDRMiddlewareError);
		expect(next).not.toHaveBeenCalled();
	});

	it("calls next() when onAsk approves an ask verdict", async () => {
		const client = new MockAIDRClient(ASK);
		const onAsk = vi.fn().mockReturnValue(true);
		const middleware = createGenericMiddleware(asClient(client), { onAsk });
		const next = vi.fn().mockResolvedValue("EXECUTED");

		await expect(middleware(context, next)).resolves.toBe("EXECUTED");
		expect(onAsk).toHaveBeenCalledTimes(1);
		expect(next).toHaveBeenCalledTimes(1);
	});

	it("does not approve an indeterminate result by default", async () => {
		const client = new MockAIDRClient(INDETERMINATE);
		const next = vi.fn().mockResolvedValue("EXECUTED");
		const middleware = createGenericMiddleware(asClient(client), { onAsk: () => true });

		await expect(middleware(context, next)).rejects.toThrow(AIDRMiddlewareError);
		expect(next).not.toHaveBeenCalled();
	});
});

describe("LlamaIndex adapter is fail-closed", () => {
	function makeEngine(result: CheckResult, options?: Parameters<typeof withAIDRLlamaIndex>[2]) {
		const client = new MockAIDRClient(result);
		const query = vi.fn(async (_q: string) => ({ response: "answer" }));
		const engine = withAIDRLlamaIndex({ query }, asClient(client), options);
		return { engine, query };
	}

	it("blocks an ask verdict without querying the engine", async () => {
		const { engine, query } = makeEngine(ASK);

		await expect(engine.query("suspicious question")).rejects.toThrow(AIDRLlamaIndexError);
		expect(query).not.toHaveBeenCalled();
	});

	it("queries the engine when onAsk approves", async () => {
		const { engine, query } = makeEngine(ASK, { onAsk: async () => true });

		await expect(engine.query("question")).resolves.toMatchObject({ response: "answer" });
		expect(query).toHaveBeenCalledTimes(1);
	});

	it("does not approve an indeterminate result by default", async () => {
		const { engine, query } = makeEngine(INDETERMINATE, { onAsk: async () => true });

		await expect(engine.query("question")).rejects.toThrow(AIDRLlamaIndexError);
		expect(query).not.toHaveBeenCalled();
	});
});

describe("AutoGen adapter is fail-closed", () => {
	const sender = { name: "agent", role: "assistant" };

	it("does not synthesize an allow for an ask content verdict", async () => {
		const client = new MockAIDRClient(ASK);
		const speaker = new AIDRSpeaker(asClient(client));

		const result = await speaker.onMessage({ content: "suspicious", role: "assistant" }, sender);

		expect(result.allowed).toBe(false);
		expect(result.verdict.decision).toBe("ask");
	});

	it("reports allowed only when onAsk approves an ask verdict", async () => {
		const client = new MockAIDRClient(ASK);
		const onAsk = vi.fn().mockResolvedValue(true);
		const speaker = new AIDRSpeaker(asClient(client), { onAsk });

		const result = await speaker.onMessage({ content: "suspicious", role: "assistant" }, sender);

		expect(onAsk).toHaveBeenCalledTimes(1);
		expect(result.allowed).toBe(true);
		expect(result.verdict.decision).toBe("allow");
		expect(result.verdict.reason).toContain("approved by onAsk");
	});

	it("blocks an ask function-call verdict instead of reporting 'all checks passed'", async () => {
		const client = new MockAIDRClient(ALLOW);
		client.responder = (request) =>
			request.action === "execute" && request.resource.startsWith("my_tool(") ? ASK : ALLOW;
		const speaker = new AIDRSpeaker(asClient(client));

		const result = await speaker.onMessage(
			{
				content: "hello",
				role: "assistant",
				function_call: { name: "my_tool", arguments: '{"x":1}' },
			},
			sender,
		);

		expect(result.allowed).toBe(false);
		expect(result.verdict.decision).toBe("ask");
	});

	it("blocks an ask function response", async () => {
		const client = new MockAIDRClient(ASK);
		const speaker = new AIDRSpeaker(asClient(client));

		const result = await speaker.validateFunctionResponse("my_tool", "suspicious output", sender);

		expect(result.allowed).toBe(false);
		expect(result.verdict.decision).toBe("ask");
	});

	it("does not approve an indeterminate result by default", async () => {
		const client = new MockAIDRClient(INDETERMINATE);
		const speaker = new AIDRSpeaker(asClient(client), { onAsk: async () => true });

		const result = await speaker.onMessage({ content: "suspicious", role: "assistant" }, sender);

		expect(result.allowed).toBe(false);
	});
});

describe("CrewAI adapter is fail-closed", () => {
	function makeTool(result: CheckResult, options?: ConstructorParameters<typeof AIDRCrewTool>[2]) {
		const client = new MockAIDRClient(result);
		const inner = {
			name: "dangerous_tool",
			description: "does dangerous things",
			run: vi.fn().mockResolvedValue("EXECUTED"),
		};
		return { tool: new AIDRCrewTool(inner, asClient(client), options), inner };
	}

	it("throws on an ask verdict without running the inner tool", async () => {
		const { tool, inner } = makeTool(ASK);

		await expect(tool.run("payload")).rejects.toThrow(AIDRCrewSecurityError);
		expect(inner.run).not.toHaveBeenCalled();
	});

	it("runs the inner tool when onAsk approves", async () => {
		const { tool, inner } = makeTool(ASK, { onAsk: async () => true });

		await expect(tool.run("payload")).resolves.toBe("EXECUTED");
		expect(inner.run).toHaveBeenCalledTimes(1);
	});

	it("does not approve an indeterminate result by default", async () => {
		const { tool, inner } = makeTool(INDETERMINATE, { onAsk: async () => true });

		await expect(tool.run("payload")).rejects.toThrow(AIDRCrewSecurityError);
		expect(inner.run).not.toHaveBeenCalled();
	});

	it("blocks ask task-delegation without running the original executor", async () => {
		const client = new MockAIDRClient(ASK);
		const executeTask = vi.fn().mockResolvedValue("DELEGATED");
		const agent = { name: "researcher", role: "Researcher", executeTask };

		wrapCrewAgentWithAIDR(agent, asClient(client));

		await expect(agent.executeTask?.("do something")).rejects.toThrow(AIDRCrewSecurityError);
		expect(executeTask).not.toHaveBeenCalled();
	});

	it("delegates when onAsk approves the task", async () => {
		const client = new MockAIDRClient(ASK);
		const executeTask = vi.fn().mockResolvedValue("DELEGATED");
		const agent = { name: "researcher", role: "Researcher", executeTask };

		wrapCrewAgentWithAIDR(agent, asClient(client), { onAsk: async () => true });

		await expect(agent.executeTask?.("do something")).resolves.toBe("DELEGATED");
		expect(executeTask).toHaveBeenCalledTimes(1);
	});
});
