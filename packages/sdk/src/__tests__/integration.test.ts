import { describe, expect, it, vi } from "vitest";
import { AIDRClient } from "../client.js";
import type { CheckRequest, CheckResult, SDKConfig } from "../config.js";
import { SDKConfigSchema } from "../config.js";
import { createMiddleware } from "../middleware.js";

class MockClient {
	constructor(private readonly result: CheckResult) {}
	check = vi.fn(async (_request: CheckRequest) => this.result);
}

describe("SDK integration", () => {
	it("validates configuration and applies defaults", () => {
		const parsed = SDKConfigSchema.parse({ apiKey: "test-key" });

		expect(parsed).toMatchObject({
			timeout: 5000,
			retries: 2,
			cache: true,
			environment: "production",
			urlReputationEnabled: false,
			includeUrlQueryParameters: false,
		});
		expect(SDKConfigSchema.safeParse({ apiKey: "", timeout: 50, retries: 10 }).success).toBe(false);
	});

	it("constructs and disposes a client with validated configuration", () => {
		const config: SDKConfig = SDKConfigSchema.parse({ apiKey: "test-key" });
		const client = new AIDRClient(config);

		expect(client).toBeInstanceOf(AIDRClient);
		client.dispose();
	});

	it("matches typed artifacts supplied by the generic tool wrapper", async () => {
		const client = new AIDRClient({ apiKey: "test-key", cache: false, retries: 0 });
		const match = vi.fn(() => []);
		const internal = client as unknown as {
			initialized: boolean;
			heuristics: { match: typeof match };
		};
		internal.initialized = true;
		internal.heuristics = { match };

		await client.check({
			action: "custom_tool",
			resource: "opaque serialized args",
			artifacts: [{ type: "file_path", value: "/workspace/.ssh/authorized_keys" }],
		});

		expect(match).toHaveBeenCalledWith(
			expect.arrayContaining([
				expect.objectContaining({ type: "content", value: "opaque serialized args" }),
				expect.objectContaining({ type: "file_path", value: "/workspace/.ssh/authorized_keys" }),
			]),
		);
		client.dispose();
	});

	it("runs middleware and wrapped functions on an allow verdict", async () => {
		const result: CheckResult = { allowed: true, decision: "allow", confidence: 0.95 };
		const client = new MockClient(result) as unknown as AIDRClient;
		const observed = vi.fn();
		const execute = vi.fn().mockResolvedValue("done");
		const middleware = createMiddleware(client).use(observed);
		const wrapped = middleware.wrap(execute, (resource: string) => ({
			action: "execute",
			resource,
		}));

		await expect(wrapped("safe command")).resolves.toBe("done");
		expect(observed).toHaveBeenCalledOnce();
		expect(execute).toHaveBeenCalledWith("safe command");
	});
});
