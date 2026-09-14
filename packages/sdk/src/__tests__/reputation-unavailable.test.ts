import { describe, expect, it, vi } from "vitest";
import { AIDRClient } from "../client.js";
import type { SDKConfig } from "../config.js";

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
});
