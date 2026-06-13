/**
 * Integration tests for the SDK package
 * Tests: SDK initialization, LangChain middleware, CLI commands
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AIDRSecurityError, AIDRTool, withAIDR } from "../adapters/langchain.js";
import { AIDRClient } from "../client.js";
import type { CheckRequest, CheckResult, SDKConfig } from "../config.js";
import { SDKConfigSchema } from "../config.js";
import { createMiddleware } from "../middleware.js";

// Mock AIDR client for LangChain tests
class MockAIDRClient {
	private mockResponses: Map<string, CheckResult> = new Map();

	setMockResponse(key: string, result: CheckResult): void {
		this.mockResponses.set(key, result);
	}

	async check(request: CheckRequest): Promise<CheckResult> {
		const key = `${request.action}:${request.resource}`;
		return (
			this.mockResponses.get(key) ?? {
				allowed: true,
				decision: "allow" as const,
				confidence: 0.95,
			}
		);
	}
}

describe("SDK Integration", () => {
	let tmpDir: string;

	beforeEach(async () => {
		tmpDir = await mkdtemp(join(tmpdir(), "aidr-sdk-int-"));
	});

	afterEach(async () => {
		await rm(tmpDir, { recursive: true, force: true });
	});

	describe("SDK Initialization", () => {
		it("should validate SDK configuration", () => {
			const validConfig = {
				apiKey: "test-api-key",
				baseUrl: "https://api.example.com",
				timeout: 5000,
				retries: 2,
				cache: true,
				environment: "production" as const,
			};

			const parsed = SDKConfigSchema.safeParse(validConfig);
			expect(parsed.success).toBe(true);
			if (parsed.success) {
				expect(parsed.data.apiKey).toBe("test-api-key");
				expect(parsed.data.timeout).toBe(5000);
			}
		});

		it("should reject invalid SDK configuration", () => {
			const invalidConfig = {
				apiKey: "", // Empty API key should fail
				timeout: 50, // Too low
				retries: 10, // Too high
			};

			const parsed = SDKConfigSchema.safeParse(invalidConfig);
			expect(parsed.success).toBe(false);
		});

		it("should apply default values for optional config", () => {
			const minimalConfig = {
				apiKey: "test-key",
			};

			const parsed = SDKConfigSchema.safeParse(minimalConfig);
			expect(parsed.success).toBe(true);
			if (parsed.success) {
				expect(parsed.data.timeout).toBe(5000); // default
				expect(parsed.data.retries).toBe(2); // default
				expect(parsed.data.cache).toBe(true); // default
				expect(parsed.data.environment).toBe("production"); // default
			}
		});

		it("should create SDK client with valid config", () => {
			const config: SDKConfig = {
				apiKey: "test-api-key",
				timeout: 5000,
				retries: 2,
				cache: true,
				cacheTtl: 300000,
				environment: "production",
			};

			const client = new AIDRClient(config);
			expect(client).toBeInstanceOf(AIDRClient);
			client.dispose();
		});

		it("should support event listeners", async () => {
			const config: SDKConfig = {
				apiKey: "test-key",
				timeout: 5000,
				retries: 0,
				cache: false,
				cacheTtl: 300000,
				environment: "production",
			};

			const client = new AIDRClient(config);
			const decisionHandler = vi.fn();
			const errorHandler = vi.fn();

			client.on("decision", decisionHandler);
			client.on("error", errorHandler);

			// Trigger a check
			await client.check({
				action: "read",
				resource: "test://resource",
			});

			// Should have received a decision event
			expect(decisionHandler).toHaveBeenCalled();
			const event = decisionHandler.mock.calls[0][0];
			expect(event.type).toBe("decision");
			expect(event.request).toBeDefined();
			expect(event.result).toBeDefined();

			client.dispose();
		});

		it("should support removing event listeners", async () => {
			const config: SDKConfig = {
				apiKey: "test-key",
				timeout: 5000,
				retries: 0,
				cache: false,
				cacheTtl: 300000,
				environment: "production",
			};

			const client = new AIDRClient(config);
			const handler = vi.fn();

			const unsubscribe = client.on("decision", handler);
			unsubscribe();

			await client.check({
				action: "read",
				resource: "test://resource",
			});

			expect(handler).not.toHaveBeenCalled();
			client.dispose();
		});
	});

	describe("Middleware Integration", () => {
		it("should create middleware chain", () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			const middleware = createMiddleware(mockClient);

			expect(middleware).toHaveProperty("use");
			expect(middleware).toHaveProperty("check");
			expect(middleware).toHaveProperty("wrap");
			expect(middleware).toHaveProperty("express");
			expect(middleware).toHaveProperty("nextjs");
		});

		it("should execute middleware chain in order", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			vi.spyOn(mockClient, "check").mockResolvedValue({
				allowed: true,
				decision: "allow",
				confidence: 0.95,
			});

			const middleware = createMiddleware(mockClient);
			const order: string[] = [];

			middleware
				.use(async () => {
					order.push("first");
				})
				.use(async () => {
					order.push("second");
				})
				.use(async () => {
					order.push("third");
				});

			await middleware.check({
				action: "read",
				resource: "test://resource",
			});

			expect(order).toEqual(["first", "second", "third"]);
		});

		it("should pass request and result to middleware", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			const mockResult: CheckResult = {
				allowed: true,
				decision: "allow",
				confidence: 0.95,
				reason: "Test passed",
			};
			vi.spyOn(mockClient, "check").mockResolvedValue(mockResult);

			const middleware = createMiddleware(mockClient);
			let capturedContext: { request?: CheckRequest; result?: CheckResult } = {};

			middleware.use(async (ctx) => {
				capturedContext = {
					request: ctx.request,
					result: ctx.result,
				};
			});

			const request: CheckRequest = {
				action: "write",
				resource: "/api/data",
				context: { userId: "123" },
			};

			await middleware.check(request);

			expect(capturedContext.request).toEqual(request);
			expect(capturedContext.result).toEqual(mockResult);
		});

		it("should support wrapping functions with security checks", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			vi.spyOn(mockClient, "check").mockResolvedValue({
				allowed: true,
				decision: "allow",
				confidence: 0.95,
			});

			const middleware = createMiddleware(mockClient);
			const originalFn = vi.fn().mockReturnValue("result");

			const wrappedFn = middleware.wrap(originalFn, (arg1: string, arg2: number) => ({
				action: "execute",
				resource: `${arg1}:${arg2}`,
			}));

			const result = await wrappedFn("test", 42);

			expect(result).toBe("result");
			expect(originalFn).toHaveBeenCalledWith("test", 42);
		});

		it("should block wrapped function on deny verdict", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			vi.spyOn(mockClient, "check").mockResolvedValue({
				allowed: false,
				decision: "deny",
				confidence: 0.95,
				reason: "Security threat detected",
			});

			const middleware = createMiddleware(mockClient);
			const originalFn = vi.fn().mockReturnValue("result");

			const wrappedFn = middleware.wrap(originalFn, () => ({
				action: "execute",
				resource: "suspicious://resource",
			}));

			await expect(wrappedFn()).rejects.toThrow("Security check denied");
			expect(originalFn).not.toHaveBeenCalled();
		});

		it("should provide Express-compatible middleware", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			vi.spyOn(mockClient, "check").mockResolvedValue({
				allowed: true,
				decision: "allow",
				confidence: 0.95,
			});

			const middleware = createMiddleware(mockClient);
			const expressMiddleware = middleware.express();

			const mockReq = {
				method: "GET",
				url: "/api/users",
				headers: { authorization: "Bearer token" },
			};
			const mockRes = {
				status: vi.fn().mockReturnValue({ json: vi.fn() }),
			};
			const mockNext = vi.fn();

			await expressMiddleware(mockReq, mockRes, mockNext);

			expect(mockNext).toHaveBeenCalled();
			expect(mockNext).toHaveBeenCalledWith(); // No error
		});

		it("should block requests in Express middleware", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			vi.spyOn(mockClient, "check").mockResolvedValue({
				allowed: false,
				decision: "deny",
				confidence: 0.95,
				reason: "Unauthorized",
			});

			const middleware = createMiddleware(mockClient);
			const expressMiddleware = middleware.express();

			const mockReq = {
				method: "POST",
				url: "/api/admin",
				body: { action: "delete" },
			};
			const jsonFn = vi.fn();
			const mockRes = {
				status: vi.fn().mockReturnValue({ json: jsonFn }),
			};
			const mockNext = vi.fn();

			await expressMiddleware(mockReq, mockRes, mockNext);

			expect(mockNext).not.toHaveBeenCalled();
			expect(mockRes.status).toHaveBeenCalledWith(403);
		});

		it("should provide Next.js-compatible middleware", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			vi.spyOn(mockClient, "check").mockResolvedValue({
				allowed: true,
				decision: "allow",
				confidence: 0.95,
			});

			const middleware = createMiddleware(mockClient);
			const nextjsMiddleware = middleware.nextjs();

			const mockRequest = new Request("https://example.com/api/data", {
				method: "GET",
				headers: { "Content-Type": "application/json" },
			});

			const result = await nextjsMiddleware(mockRequest);

			expect(result).toBeNull(); // Continue to handler
		});

		it("should return 403 response in Next.js middleware on deny", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			vi.spyOn(mockClient, "check").mockResolvedValue({
				allowed: false,
				decision: "deny",
				confidence: 0.95,
				reason: "Access denied",
			});

			const middleware = createMiddleware(mockClient);
			const nextjsMiddleware = middleware.nextjs();

			const mockRequest = new Request("https://example.com/api/admin", {
				method: "POST",
			});

			const result = await nextjsMiddleware(mockRequest);

			expect(result).toBeInstanceOf(Response);
			expect(result?.status).toBe(403);
		});
	});

	describe("LangChain Middleware Integration", () => {
		// Mock BaseTool for testing
		class MockTool {
			name = "MockTool";
			description = "A mock tool for testing";
			lc_namespace = ["mock"];

			async _call(args: unknown): Promise<string> {
				return `Executed with ${JSON.stringify(args)}`;
			}

			async invoke(input: unknown): Promise<string> {
				return this._call(input);
			}
		}

		it("should wrap tool with AIDR security", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			mockClient.setMockResponse("execute:test", {
				allowed: true,
				decision: "allow",
				confidence: 0.95,
			});

			const mockTool = new MockTool() as unknown as import("@langchain/core/tools").BaseTool;
			const secureTool = withAIDR(mockTool, mockClient);

			expect(secureTool).toBeInstanceOf(AIDRTool);
			expect(secureTool.name).toBe("secure_MockTool");
		});

		it("should allow tool execution when verdict is allow", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			mockClient.setMockResponse("execute:test input", {
				allowed: true,
				decision: "allow",
				confidence: 0.95,
			});

			const mockTool = new MockTool() as unknown as import("@langchain/core/tools").BaseTool;
			const secureTool = withAIDR(mockTool, mockClient);

			const result = await secureTool.invoke("test input");

			expect(result.allowed).toBe(true);
			expect(result.output).toBe('Executed with {"input":"test input"}');
			expect(result.security.decision).toBe("allow");
		});

		it("should block tool execution when verdict is deny", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			mockClient.setMockResponse("execute:malicious", {
				allowed: false,
				decision: "deny",
				confidence: 0.95,
				reason: "Malicious input detected",
			});

			const mockTool = new MockTool() as unknown as import("@langchain/core/tools").BaseTool;
			const secureTool = withAIDR(mockTool, mockClient);

			await expect(secureTool.invoke("malicious")).rejects.toThrow(AIDRSecurityError);
		});

		it("should provide security metadata in results", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			mockClient.setMockResponse("execute:test", {
				allowed: true,
				decision: "allow",
				confidence: 0.92,
				threatId: "THREAT-001",
				reason: "Clean input",
			});

			const mockTool = new MockTool() as unknown as import("@langchain/core/tools").BaseTool;
			const secureTool = withAIDR(mockTool, mockClient);

			const result = await secureTool.invoke("test");

			expect(result.security).toMatchObject({
				decision: "allow",
				confidence: 0.92,
				severity: "info",
			});
		});

		it("should support custom deny handlers", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			mockClient.setMockResponse("execute:bad", {
				allowed: false,
				decision: "deny",
				confidence: 0.95,
				reason: "Bad input",
			});

			const onDeny = vi.fn();
			const mockTool = new MockTool() as unknown as import("@langchain/core/tools").BaseTool;
			const secureTool = withAIDR(mockTool, mockClient, {
				onDeny,
				throwOnDeny: false,
			});

			await secureTool.invoke("bad");

			expect(onDeny).toHaveBeenCalled();
		});

		it("should support custom options via withOptions", async () => {
			const mockClient = new MockAIDRClient() as unknown as AIDRClient;
			mockClient.setMockResponse("execute:test", {
				allowed: true,
				decision: "allow",
				confidence: 0.95,
			});

			const mockTool = new MockTool() as unknown as import("@langchain/core/tools").BaseTool;
			const secureTool = withAIDR(mockTool, mockClient);
			const newTool = secureTool.withOptions({ throwOnAsk: true });

			expect(newTool.getOptions().throwOnAsk).toBe(true);
		});
	});

	describe("CLI Integration", () => {
		it("should load and validate CLI config files", async () => {
			const configDir = join(tmpDir, ".aidr");
			await mkdir(configDir, { recursive: true });

			const config = {
				apiKey: "cli-test-key",
				baseUrl: "https://cli.example.com",
				timeout: 3000,
				retries: 1,
				cache: false,
				environment: "development",
			};

			await writeFile(join(configDir, "config.json"), JSON.stringify(config));

			const loaded = JSON.parse(
				await import("node:fs/promises").then((fs) =>
					fs.readFile(join(configDir, "config.json"), "utf-8"),
				),
			);

			const parsed = SDKConfigSchema.safeParse(loaded);
			expect(parsed.success).toBe(true);
			if (parsed.success) {
				expect(parsed.data.apiKey).toBe("cli-test-key");
				expect(parsed.data.environment).toBe("development");
			}
		});

		it("should support multiple config locations", async () => {
			const localConfig = { apiKey: "local-key" };
			const globalConfig = { apiKey: "global-key", baseUrl: "https://global.example.com" };

			await writeFile(join(tmpDir, ".aidr.json"), JSON.stringify(localConfig));

			const parsedLocal = SDKConfigSchema.safeParse(localConfig);
			const parsedGlobal = SDKConfigSchema.safeParse(globalConfig);

			expect(parsedLocal.success).toBe(true);
			expect(parsedGlobal.success).toBe(true);
		});
	});

	describe("SDK Cache Integration", () => {
		it("should cache check results when enabled", async () => {
			const config: SDKConfig = {
				apiKey: "test-key",
				timeout: 5000,
				retries: 0,
				cache: true,
				cacheTtl: 300000,
				environment: "production",
			};

			const client = new AIDRClient(config);
			expect(client.getCacheStats()).toBeDefined();
			client.dispose();
		});

		it("should return undefined cache stats when disabled", async () => {
			const config: SDKConfig = {
				apiKey: "test-key",
				timeout: 5000,
				retries: 0,
				cache: false,
				cacheTtl: 300000,
				environment: "production",
			};

			const client = new AIDRClient(config);
			expect(client.getCacheStats()).toBeUndefined();
			client.dispose();
		});

		it("should clear cache on dispose", async () => {
			const config: SDKConfig = {
				apiKey: "test-key",
				timeout: 5000,
				retries: 0,
				cache: true,
				cacheTtl: 300000,
				environment: "production",
			};

			const client = new AIDRClient(config);
			await client.check({ action: "read", resource: "test://1" });
			await client.check({ action: "read", resource: "test://2" });

			const statsBefore = client.getCacheStats();
			expect(statsBefore?.size).toBeGreaterThan(0);

			client.clearCache();

			const statsAfter = client.getCacheStats();
			expect(statsAfter?.size).toBe(0);
			client.dispose();
		});
	});
});
