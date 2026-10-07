import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	config: vi.fn(),
	invalid: vi.fn(),
	barrier: vi.fn(),
	cacheRead: vi.fn(),
	cacheWrite: vi.fn(),
	network: vi.fn(),
	engine: vi.fn(),
	matches: vi.fn(),
	loader: vi.fn(),
	send: vi.fn(),
	provisionedScan: vi.fn(),
	cachedOutputScan: vi.fn(),
}));

vi.mock("@singularityrd/aidr-core", async () => {
	const { z } = await import("zod");
	return {
		ArtifactSchema: z.object({ type: z.string(), value: z.string() }),
		DecisionEngine: class {
			decide = mocks.engine;
		},
		HeuristicsEngine: class {
			match = mocks.matches;
		},
		UrlCheckClient: class {
			checkUrls = mocks.network;
		},
		VerdictCache: class {
			getUrl = mocks.cacheRead;
			putUrl = mocks.cacheWrite;
		},
		loadConfig: mocks.config,
		isInvalidConfig: mocks.invalid,
		inspectResponseBarrier: mocks.barrier,
		loadManagedState: vi.fn(),
		getEffectiveManagedApiKey: vi.fn(),
		managedStatePath: () => "installed-state",
		loadThreats: vi.fn(),
		loadTrustedDomains: vi.fn(),
		scanModelOutput: () => [],
		scanProvisionedOutput: mocks.provisionedScan,
		scanCachedProvisionedOutput: mocks.cachedOutputScan,
		nullLogger: { debug() {}, info() {}, warn() {}, error() {} },
		extractFromUnknownTool: () => [],
		extractUrls: () => [],
		inspectionLimitsHit: () => [],
		INPUT_NOT_FULLY_INSPECTED: "input_not_fully_inspected",
		checkRunaway: async () => ({ status: "disabled" }),
	};
});
vi.mock("../privacy-text.js", async (importOriginal) => ({
	...(await importOriginal<Record<string, unknown>>()),
	loadPrivacyTextGateway: mocks.loader,
}));

import {
	AIDRMiddlewareError,
	composeMiddleware,
	createMiddlewarePipeline,
	createSyncCompatibleMiddleware,
	createMiddleware as genericMiddleware,
	wrapToolWithMiddleware,
} from "../adapters/generic.js";
import { AIDRClient } from "../client.js";
import { createMiddleware } from "../middleware.js";
import type { PrivacyGatewayOptions } from "../privacy-text.js";

const allow = {
	decision: "allow",
	confidence: 1,
	severity: "info",
	reasons: [],
	source: "heuristics",
	matchedThreatId: null,
};
const installed = () => ({
	privacy: { required: true },
	control_plane: { response_worker_required: false },
	auth: {},
	licensing: { public_keys_pem: [] },
});
const request = {
	action: "fetch",
	resource: "https://raw-provider.example/private?token=PRIVATE-TEXT",
};
function options(): PrivacyGatewayOptions {
	return {
		origin: "https://127.0.0.1:8443",
		destinationId: "approved-provider",
		tls: {
			ca: Buffer.from("PRIVATE-CA"),
			cert: Buffer.from("PRIVATE-CERT"),
			key: Buffer.from("PRIVATE-KEY"),
		},
		credentials: vi.fn(async () => ({
			userToken: "PRIVATE-USER",
			deviceToken: "PRIVATE-DEVICE",
			providerToken: "PRIVATE-PROVIDER",
		})),
	};
}
function client(gateway?: PrivacyGatewayOptions): AIDRClient {
	const sdk = new AIDRClient(
		{ apiKey: "remote-sdk-key", retries: 0, urlReputationEnabled: true },
		gateway ? { privacyGateway: gateway } : undefined,
	);
	const internal = sdk as unknown as {
		initialized: boolean;
		heuristics: { match: typeof mocks.matches };
	};
	internal.initialized = true;
	internal.heuristics = { match: mocks.matches };
	return sdk;
}

beforeEach(() => {
	vi.clearAllMocks();
	mocks.config.mockResolvedValue(installed());
	mocks.invalid.mockReturnValue(false);
	mocks.barrier.mockResolvedValue({ status: "unconfigured" });
	mocks.cacheRead.mockReturnValue({
		verdict: "allow",
		severity: "info",
		reasons: [],
		source: "cache",
	});
	mocks.engine.mockResolvedValue(allow);
	mocks.matches.mockReturnValue([]);
	mocks.provisionedScan.mockResolvedValue([]);
	mocks.cachedOutputScan.mockReturnValue([]);
	mocks.loader.mockResolvedValue({ send: mocks.send });
	mocks.send.mockResolvedValue({ decision: "sent", outputText: "SANITIZED-MODEL-OUTPUT" });
	mocks.network.mockResolvedValue([
		{ url: request.resource, isMalicious: false, findings: [], flags: [] },
	]);
});
afterEach(() => vi.restoreAllMocks());

describe("mandatory SDK privacy routing", () => {
	it.each([true, false])(
		"rechecks after a blocked output observer before exposing raw error context (activate=%s)",
		async (activate) => {
			const config = { ...installed(), privacy: { required: false } };
			mocks.config.mockResolvedValue(config);
			mocks.cachedOutputScan.mockReturnValue([
				{
					type: "secret_leak",
					severity: "critical",
					reason: "Restricted output",
					redactedExcerpt: "[REDACTED]",
					ruleId: "restricted",
				},
			]);
			const afterCheck = vi.fn(async () => {
				await Promise.resolve();
				config.privacy.required = activate;
			});
			const execution = genericMiddleware(client(), { agentRuntime: "cursor", afterCheck })(
				{ tool: "provider", input: "benign" },
				async () => "PRIVATE-OUTPUT",
			);
			if (activate) await expect(execution).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
			else await expect(execution).rejects.toBeInstanceOf(AIDRMiddlewareError);
			expect(afterCheck).toHaveBeenCalledOnce();
		},
	);
	it.each([
		{ kind: "generic", fails: false, activate: true },
		{ kind: "generic", fails: false, activate: false },
		{ kind: "generic", fails: true, activate: true },
		{ kind: "generic", fails: true, activate: false },
		{ kind: "sync", fails: false, activate: true },
		{ kind: "sync", fails: false, activate: false },
		{ kind: "sync", fails: true, activate: true },
		{ kind: "sync", fails: true, activate: false },
	])(
		"rechecks final $kind delivery after afterCheck (fails=$fails, activate=$activate)",
		async ({ kind, fails, activate }) => {
			const config = { ...installed(), privacy: { required: false } };
			mocks.config.mockResolvedValue(config);
			const sdk = client();
			const sentinel = new Error("PRIVATE-OUTPUT-ERROR");
			const next = async () => {
				if (fails) throw sentinel;
				return "PRIVATE-OUTPUT";
			};
			const afterCheck = vi.fn(async () => {
				await Promise.resolve();
				config.privacy.required = activate;
			});
			const context = { tool: "provider", input: "benign" };
			const execution =
				kind === "generic"
					? genericMiddleware(sdk, { afterCheck })(context, next)
					: createSyncCompatibleMiddleware(sdk, { afterCheck }).sync(context, next);
			if (activate) await expect(execution).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
			else if (fails) await expect(execution).rejects.toBe(sentinel);
			else await expect(execution).resolves.toBe("PRIVATE-OUTPUT");
			expect(afterCheck).toHaveBeenCalledOnce();
		},
	);
	it.each(["generic", "sync"])(
		"withholds $s formatter output and raw error context when formatting activates mandatory routing",
		async (kind) => {
			const config = { ...installed(), privacy: { required: false } };
			mocks.config.mockResolvedValue(config);
			mocks.cacheRead.mockReturnValue(undefined);
			mocks.engine.mockResolvedValue({ ...allow, decision: "deny" });
			const formatErrorMessage = vi.fn(() => {
				config.privacy.required = true;
				return "PRIVATE-FORMATTER-ERROR";
			});
			const context = { tool: "provider", input: "benign" };
			const next = vi.fn();
			const execution =
				kind === "generic"
					? genericMiddleware(client(), { formatErrorMessage })(context, next)
					: createSyncCompatibleMiddleware(client(), { formatErrorMessage }).sync(context, next);
			await expect(execution).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
			expect(formatErrorMessage).toHaveBeenCalledOnce();
			expect(next).not.toHaveBeenCalled();
		},
	);
	it.each([
		{ kind: "generic", activate: true },
		{ kind: "generic", activate: false },
		{ kind: "sync", activate: true },
		{ kind: "sync", activate: false },
		{ kind: "wrap", activate: true },
		{ kind: "wrap", activate: false },
	])(
		"withholds failed $kind raw errors after mandatory activation=$activate",
		async ({ kind, activate }) => {
			const config = { ...installed(), privacy: { required: false } };
			mocks.config.mockResolvedValue(config);
			const sdk = client();
			const sentinel = new Error("PRIVATE-OUTPUT-ERROR");
			const next = async () => {
				await Promise.resolve();
				config.privacy.required = activate;
				throw sentinel;
			};
			const context = { tool: "provider", input: "benign" };
			const execution =
				kind === "generic"
					? genericMiddleware(sdk)(context, next)
					: kind === "sync"
						? createSyncCompatibleMiddleware(sdk).sync(context, next)
						: createMiddleware(sdk).wrap(next, () => ({ action: "execute", resource: "benign" }))();
			const error = await execution.catch((value) => value);
			if (activate) {
				expect(error).toHaveProperty("message", "PRIVACY_CALLER_ROUTE_UNSUPPORTED");
				expect(error).not.toBe(sentinel);
			} else expect(error).toBe(sentinel);
		},
	);
	it.each([
		{ kind: "generic", activate: true },
		{ kind: "generic", activate: false },
		{ kind: "sync", activate: true },
		{ kind: "sync", activate: false },
		{ kind: "wrap", activate: true },
		{ kind: "wrap", activate: false },
	])(
		"withholds completed $kind output after in-flight mandatory activation=$activate",
		async ({ kind, activate }) => {
			const config = { ...installed(), privacy: { required: false } };
			mocks.config.mockResolvedValue(config);
			const sdk = client();
			const next = vi.fn(async () => {
				await Promise.resolve();
				config.privacy.required = activate;
				return "PRIVATE-OUTPUT";
			});
			const context = { tool: "provider", input: "benign" };
			const execution =
				kind === "generic"
					? genericMiddleware(sdk)(context, next)
					: kind === "sync"
						? createSyncCompatibleMiddleware(sdk).sync(context, next)
						: createMiddleware(sdk).wrap(next, () => ({ action: "execute", resource: "benign" }))();
			if (activate) await expect(execution).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
			else await expect(execution).resolves.toBe("PRIVATE-OUTPUT");
			expect(next).toHaveBeenCalledOnce();
		},
	);
	it("suppresses afterCheck and output delivery when mandatory routing activates inside a successful tool", async () => {
		const config = { ...installed(), privacy: { required: false } };
		mocks.config.mockResolvedValue(config);
		const afterCheck = vi.fn();
		const next = async () => {
			config.privacy.required = true;
			return "PRIVATE-OUTPUT";
		};
		await expect(
			genericMiddleware(client(), { afterCheck })({ tool: "provider", input: "benign" }, next),
		).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
		expect(afterCheck).not.toHaveBeenCalled();
	});
	it("rechecks mandatory routing after the awaited provisioned output scan before release", async () => {
		const config = { ...installed(), privacy: { required: false } };
		mocks.config.mockResolvedValue(config);
		mocks.provisionedScan.mockImplementation(async () => {
			await Promise.resolve();
			config.privacy.required = true;
			return [];
		});
		const afterCheck = vi.fn();
		await expect(
			genericMiddleware(client(), { agentRuntime: "cursor", afterCheck })(
				{ tool: "provider", input: "benign" },
				async () => "PRIVATE-OUTPUT",
			),
		).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
		expect(mocks.provisionedScan).toHaveBeenCalledOnce();
		expect(afterCheck).not.toHaveBeenCalled();
	});
	it.each([true, false])(
		"guards beforeCheck and provider callbacks while preserving the ordinary twin (required=%s)",
		async (required) => {
			mocks.config.mockResolvedValue({ ...installed(), privacy: { required } });
			const beforeCheck = vi.fn();
			const next = vi.fn(async () => "safe");
			const execution = genericMiddleware(client(), { beforeCheck })(
				{ tool: "provider", input: "PRIVATE-TEXT" },
				next,
			);
			if (required) await expect(execution).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
			else await expect(execution).resolves.toBe("safe");
			expect(beforeCheck).toHaveBeenCalledTimes(required ? 0 : 1);
			expect(next).toHaveBeenCalledTimes(required ? 0 : 1);
		},
	);
	it.each([true, false])(
		"guards custom extractors before they receive arguments (required=%s)",
		async (required) => {
			mocks.config.mockResolvedValue({ ...installed(), privacy: { required } });
			const extractor = vi.fn(() => ({ action: "execute", resource: "benign" }));
			const next = vi.fn(async (_input: unknown) => "safe");
			const execution = createMiddleware(client()).wrap(next, extractor)("PRIVATE-TEXT");
			if (required) await expect(execution).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
			else await expect(execution).resolves.toBe("safe");
			expect(extractor).toHaveBeenCalledTimes(required ? 0 : 1);
			expect(next).toHaveBeenCalledTimes(required ? 0 : 1);
		},
	);
	it.each([true, false])(
		"guards custom middleware observers without skipping the local check (required=%s)",
		async (required) => {
			mocks.config.mockResolvedValue({ ...installed(), privacy: { required } });
			const observer = vi.fn();
			const sdk = client();
			const execution = createMiddleware(sdk)
				.use(observer)
				.check({ action: "execute", resource: "PRIVATE-TEXT" });
			if (required) await expect(execution).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
			else await expect(execution).resolves.toMatchObject({ decision: "allow" });
			expect(observer).toHaveBeenCalledTimes(required ? 0 : 1);
			if (required) expect(mocks.engine).toHaveBeenCalledOnce();
		},
	);
	it("does not run callbacks through composition or an empty pipeline in mandatory mode", async () => {
		const stage = vi.fn();
		const next = vi.fn();
		const context = { tool: "provider", input: "PRIVATE-TEXT" };
		await expect(composeMiddleware([stage])(context, next)).rejects.toThrow(
			"PRIVACY_CALLER_ROUTE_UNSUPPORTED",
		);
		await expect(createMiddlewarePipeline(client(), [])(context, next)).rejects.toThrow(
			"PRIVACY_CALLER_ROUTE_UNSUPPORTED",
		);
		expect(stage).not.toHaveBeenCalled();
		expect(next).not.toHaveBeenCalled();
	});
	it("does not invoke JSON serialization callbacks before the mandatory guard", async () => {
		const toJSON = vi.fn(() => "PRIVATE-TEXT");
		const run = vi.fn();
		await expect(
			wrapToolWithMiddleware({ name: "provider", run }, client()).run({ toJSON }),
		).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
		expect(toJSON).not.toHaveBeenCalled();
		expect(run).not.toHaveBeenCalled();
	});
	it("suppresses denial observers and custom formatters when a beforeCheck wait activates mandatory mode", async () => {
		const config = { ...installed(), privacy: { required: false } };
		mocks.config.mockResolvedValue(config);
		const onDeny = vi.fn();
		const afterCheck = vi.fn();
		const formatErrorMessage = vi.fn();
		const next = vi.fn();
		const beforeCheck = async () => {
			await Promise.resolve();
			config.privacy.required = true;
		};
		await expect(
			genericMiddleware(client(), { beforeCheck, onDeny, afterCheck, formatErrorMessage })(
				{ tool: "provider", input: "PRIVATE-TEXT" },
				next,
			),
		).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
		expect(onDeny).not.toHaveBeenCalled();
		expect(afterCheck).not.toHaveBeenCalled();
		expect(formatErrorMessage).not.toHaveBeenCalled();
		expect(next).not.toHaveBeenCalled();
	});
	it("does not leak raw input to afterCheck when a completed operation activates mandatory mode", async () => {
		const config = { ...installed(), privacy: { required: false } };
		mocks.config.mockResolvedValue(config);
		const afterCheck = vi.fn();
		const next = vi.fn(async () => {
			config.privacy.required = true;
			throw new Error("PRIVATE-TEXT");
		});
		await expect(
			genericMiddleware(client(), { afterCheck })(
				{ tool: "provider", input: "PRIVATE-TEXT" },
				next,
			),
		).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
		expect(next).toHaveBeenCalledOnce();
		expect(afterCheck).not.toHaveBeenCalled();
	});
	it("denies ordinary direct sends before cached allows, reputation or arbitrary callbacks", async () => {
		const sdk = client();
		const result = await sdk.check({
			...request,
			metadata: { privacyApproved: true },
			context: { required: false },
		});
		expect(result).toMatchObject({
			allowed: false,
			decision: "deny",
			metadata: { privacyRoute: "unsupported" },
		});
		const next = vi.fn();
		await expect(
			genericMiddleware(sdk, { onAsk: () => true })(
				{ tool: "provider", input: "PRIVATE-TEXT" },
				next,
			),
		).rejects.toThrow();
		expect(next).not.toHaveBeenCalled();
		expect(mocks.cacheRead).not.toHaveBeenCalled();
		expect(mocks.network).not.toHaveBeenCalled();
	});
	it("retains a stronger local threat but withholds raw request and reason from events", async () => {
		mocks.engine.mockResolvedValue({
			...allow,
			decision: "deny",
			reasons: ["PRIVATE-TEXT"],
			matchedThreatId: "THREAT-1",
		});
		const sdk = client();
		const event = vi.fn();
		sdk.on("decision", event);
		expect(await sdk.check(request)).toMatchObject({ decision: "deny", threatId: "THREAT-1" });
		expect(JSON.stringify(event.mock.calls)).not.toContain("PRIVATE-TEXT");
		expect(event.mock.calls[0]?.[0].request).toEqual({
			action: "privacy-route",
			resource: "[withheld]",
		});
	});
	it("blocks unreadable or malformed installed policy without external requests", async () => {
		mocks.invalid.mockReturnValue(true);
		expect((await client().check(request)).decision).toBe("deny");
		mocks.config.mockRejectedValue(new Error("PRIVATE-POLICY-ERROR"));
		expect((await client().check(request)).decision).toBe("deny");
		expect(mocks.network).not.toHaveBeenCalled();
	});
	it("keeps default ordinary cached detection working", async () => {
		mocks.config.mockResolvedValue({ ...installed(), privacy: undefined });
		expect((await client().check(request)).decision).toBe("allow");
		expect(mocks.cacheRead).toHaveBeenCalledOnce();
	});
	it("catches mandatory activation while a reputation request is pending", async () => {
		const config = { ...installed(), privacy: { required: false } };
		mocks.config.mockResolvedValue(config);
		mocks.cacheRead.mockReturnValue(undefined);
		mocks.network.mockImplementation(async () => {
			config.privacy.required = true;
			return [];
		});
		expect((await client().check(request)).decision).toBe("deny");
		expect(mocks.cacheWrite).not.toHaveBeenCalled();
	});
	it.each(["generic", "sync", "wrap"])(
		"rechecks installed routing after an approval wait (%s)",
		async (kind) => {
			const config = { ...installed(), privacy: { required: false } };
			mocks.config.mockResolvedValue(config);
			mocks.cacheRead.mockReturnValue(undefined);
			mocks.engine.mockResolvedValue({ ...allow, decision: "ask" });
			const sdk = client();
			const next = vi.fn();
			const onAsk = async () => {
				await Promise.resolve();
				config.privacy.required = true;
				return true;
			};
			const execution =
				kind === "generic"
					? genericMiddleware(sdk, { onAsk })({ tool: "local", input: "benign" }, next)
					: kind === "sync"
						? createSyncCompatibleMiddleware(sdk, { onAsk }).sync(
								{ tool: "local", input: "benign" },
								next,
							)
						: createMiddleware(sdk, { onAsk }).wrap(next, () => ({
								action: "execute",
								resource: "benign",
							}))();
			await expect(execution).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
			expect(next).not.toHaveBeenCalled();
		},
	);
	it("rechecks after a middleware hook changes installed controls", async () => {
		const config = { ...installed(), privacy: { required: false } };
		mocks.config.mockResolvedValue(config);
		const next = vi.fn();
		const wrapped = createMiddleware(client())
			.use(async () => {
				config.privacy.required = true;
			})
			.wrap(next, () => ({ action: "execute", resource: "benign" }));
		await expect(wrapped()).rejects.toThrow("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
		expect(next).not.toHaveBeenCalled();
	});
});

describe("SDK owned final text send", () => {
	it("sends once through the bound gateway and returns only its sanitized output", async () => {
		const gateway = options();
		const sdk = client(gateway);
		const event = vi.fn();
		sdk.on("decision", event);
		sdk.on("error", event);
		gateway.tls.key.fill(0);
		gateway.tls.ca.fill(0);
		gateway.destinationId = "caller-mutated";
		expect(await sdk.sendText("PRIVATE-TEXT", { requestId: "stable-request" })).toBe(
			"SANITIZED-MODEL-OUTPUT",
		);
		expect(mocks.send).toHaveBeenCalledExactlyOnceWith("PRIVATE-TEXT", {
			requestId: "stable-request",
			reviewCaseId: undefined,
			signal: undefined,
		});
		expect(mocks.loader.mock.calls[0]?.[0]).toMatchObject({
			destinationId: "approved-provider",
			tls: { key: Buffer.from("PRIVATE-KEY"), ca: Buffer.from("PRIVATE-CA") },
		});
		expect(mocks.network).not.toHaveBeenCalled();
		expect(mocks.cacheRead).not.toHaveBeenCalled();
		expect(event).not.toHaveBeenCalled();
		expect(JSON.stringify(sdk)).not.toContain("PRIVATE-");
	});
	it("requires real gateway configuration rather than caller metadata or a send callback", async () => {
		await expect(client().sendText("text")).rejects.toThrow("PRIVACY_GATEWAY_REQUIRED");
		expect(mocks.loader).not.toHaveBeenCalled();
	});
	it("rejects unsupported streaming, files and destination overrides rather than silently dropping them", async () => {
		await expect(client(options()).sendText("text", { stream: true } as never)).rejects.toThrow(
			"PRIVACY_TEXT_OPTIONS_INVALID",
		);
		expect(mocks.send).not.toHaveBeenCalled();
	});
	it.each(["", "€".repeat(166_667)])(
		"rejects empty or over-limit UTF-8 input before dispatch",
		async (text) => {
			await expect(client(options()).sendText(text)).rejects.toThrow("PRIVACY_TEXT_INVALID");
			expect(mocks.loader).not.toHaveBeenCalled();
			expect(mocks.send).not.toHaveBeenCalled();
		},
	);
	it.each(["deny", "ask"])("does not dispatch a local %s verdict", async (decision) => {
		mocks.engine.mockResolvedValue({ ...allow, decision });
		await expect(client(options()).sendText("text")).rejects.toThrow("PRIVACY_SEND_BLOCKED");
		expect(mocks.send).not.toHaveBeenCalled();
	});
	it("fails closed on missing installed package without retrying or leaking its error", async () => {
		mocks.loader.mockRejectedValue(new Error("PRIVATE-INSTALL-ERROR"));
		await expect(client(options()).sendText("text")).rejects.toThrow(
			"PRIVACY_SEND_OUTCOME_UNAVAILABLE",
		);
		expect(mocks.loader).toHaveBeenCalledOnce();
		expect(mocks.send).not.toHaveBeenCalled();
	});
	it.each(["blocked", "review", "unknown"])(
		"withholds a %s receipt without fallback",
		async (decision) => {
			mocks.send.mockResolvedValue({ decision, outputText: "RAW-UNAPPROVED" });
			await expect(client(options()).sendText("text")).rejects.toThrow(
				"PRIVACY_MODEL_OUTPUT_UNAVAILABLE",
			);
			expect(mocks.send).toHaveBeenCalledOnce();
		},
	);
	it.each([null, Buffer.from("opaque"), "x".repeat(2 * 1024 * 1024 + 1)])(
		"withholds null, opaque or oversized output",
		async (outputText) => {
			mocks.send.mockResolvedValue({ decision: "sent", outputText });
			await expect(client(options()).sendText("text")).rejects.toThrow(
				"PRIVACY_MODEL_OUTPUT_UNAVAILABLE",
			);
			expect(mocks.send).toHaveBeenCalledOnce();
		},
	);
	it("does not retry unknown dispatch outcomes or expose credential errors", async () => {
		mocks.send.mockRejectedValue(new Error("PRIVATE-TOKEN-ERROR"));
		await expect(client(options()).sendText("text")).rejects.toThrow(
			"PRIVACY_SEND_OUTCOME_UNAVAILABLE",
		);
		expect(mocks.send).toHaveBeenCalledOnce();
	});
	it("honors installed controls after asynchronous credential resolution, before transport", async () => {
		const gateway = options();
		gateway.credentials = async () => {
			await Promise.resolve();
			mocks.barrier.mockResolvedValue({ status: "paused" });
			return { userToken: "u", deviceToken: "d", providerToken: "p" };
		};
		mocks.loader.mockImplementation(async (configured) => ({
			send: async () => {
				await configured.credentials();
				return mocks.send();
			},
		}));
		await expect(client(gateway).sendText("text")).rejects.toThrow(
			"PRIVACY_SEND_OUTCOME_UNAVAILABLE",
		);
		expect(mocks.send).not.toHaveBeenCalled();
	});
	it("withholds a completed response when the installed worker pauses while sending", async () => {
		mocks.send.mockImplementation(async () => {
			mocks.barrier.mockResolvedValue({ status: "paused" });
			return { decision: "sent", outputText: "safe" };
		});
		await expect(client(options()).sendText("text")).rejects.toThrow(
			"PRIVACY_MODEL_OUTPUT_UNAVAILABLE",
		);
		expect(mocks.send).toHaveBeenCalledOnce();
	});
	it("rejects already-aborted sends before package loading", async () => {
		await expect(
			client(options()).sendText("text", { signal: AbortSignal.abort() }),
		).rejects.toThrow();
		expect(mocks.loader).not.toHaveBeenCalled();
	});
});
