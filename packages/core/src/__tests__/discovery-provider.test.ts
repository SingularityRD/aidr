import { describe, expect, it, vi } from "vitest";
import type { AigInfraTargetResult } from "../aig-infra-scan.js";
import {
	createDiscoveryProvider,
	discoveryFreshnessForInventory,
	LocalDiscoveryProvider,
	UnconfiguredDiscoveryProvider,
} from "../discovery-provider.js";
import type { FleetFreshness, FleetInventoryEntry } from "../fleet-inventory.js";

function scanResult(
	url: string,
	reachable: boolean,
	error: string | null = null,
): AigInfraTargetResult {
	return { url, reachable, matched: [], cves: [], error, requestsMade: 1 };
}

const request = {
	tenantId: "tenant-a",
	collectorId: "collector-a",
	targets: ["http://127.0.0.1:8080"],
};

describe("fleet discovery providers", () => {
	it("selects local by default and never falls back for an external or unknown provider", async () => {
		expect(createDiscoveryProvider()).toBeInstanceOf(LocalDiscoveryProvider);
		expect(createDiscoveryProvider("local")).toBeInstanceOf(LocalDiscoveryProvider);

		for (const name of ["cloud", "mdm", "vendor", ""]) {
			const provider = createDiscoveryProvider(name);
			expect(provider).toBeInstanceOf(UnconfiguredDiscoveryProvider);
			expect(provider.configured).toBe(false);
			const result = await provider.collect(request);
			expect(result).toMatchObject({
				provider: name.trim().toLowerCase() || "unknown",
				status: "unconfigured",
				freshness: "unknown",
				inventory: null,
				failClosed: true,
				reason: "provider_not_configured",
			});
		}
	});

	it("returns fresh local evidence without claiming failure", async () => {
		const provider = new LocalDiscoveryProvider();
		const result = await provider.collect({
			...request,
			options: {
				now: () => 1_000_000,
				scanTargetImpl: async ({ url }) => scanResult(url, true),
			},
		});

		expect(result).toMatchObject({
			provider: "local",
			status: "ready",
			freshness: "fresh",
			failClosed: false,
			reason: null,
		});
		expect(result.inventory?.items[0]?.freshness).toBe("fresh");
	});

	it("keeps stale and never-seen states explicit", async () => {
		const provider = new LocalDiscoveryProvider();
		const first = await provider.collect({
			...request,
			options: {
				now: () => 1_000_000,
				staleAfterMs: 1_000,
				scanTargetImpl: async ({ url }) => scanResult(url, true),
			},
		});
		if (!first.inventory) throw new Error("expected first inventory");

		const stale = await provider.collect({
			...request,
			previous: first.inventory,
			options: {
				now: () => 1_001_001,
				staleAfterMs: 1_000,
				maxAttempts: 1,
				scanTargetImpl: async ({ url }) => scanResult(url, false, "timeout"),
			},
		});
		expect(stale).toMatchObject({ status: "degraded", freshness: "stale", failClosed: false });
		expect(stale.inventory?.items[0]?.lastSeenAt).toBe(first.inventory.items[0]?.lastSeenAt);

		const unseen = await provider.collect({
			...request,
			options: {
				now: () => 1_000_000,
				maxAttempts: 1,
				scanTargetImpl: async ({ url }) => scanResult(url, false, "target_not_allowed"),
			},
		});
		expect(unseen).toMatchObject({
			status: "degraded",
			freshness: "never_seen",
			failClosed: false,
		});
	});

	it("marks provider failures unavailable and sanitizes arbitrary error text", async () => {
		const result = await new LocalDiscoveryProvider().collect({
			...request,
			options: {
				now: () => {
					throw new Error("secret=do-not-export");
				},
				scanTargetImpl: async ({ url }) => scanResult(url, true),
			},
		});

		expect(result).toMatchObject({
			status: "unavailable",
			freshness: "unknown",
			inventory: null,
			failClosed: true,
			reason: "collection_failed",
		});
		expect(JSON.stringify(result)).not.toContain("do-not-export");
	});

	it("does not turn an absent target source into a successful empty inventory", async () => {
		const scanTargetImpl = vi.fn();
		const result = await new LocalDiscoveryProvider().collect({
			...request,
			targets: [],
			options: { scanTargetImpl },
		});
		expect(result).toMatchObject({
			status: "unconfigured",
			freshness: "unknown",
			inventory: null,
			failClosed: true,
			reason: "collector_targets_required",
		});
		expect(scanTargetImpl).not.toHaveBeenCalled();
	});

	it("distinguishes a reachable endpoint with no product matches from failed probes", async () => {
		const provider = new LocalDiscoveryProvider();
		const first = await provider.collect({
			...request,
			options: { now: () => 1_000_000, scanTargetImpl: async ({ url }) => scanResult(url, true) },
		});
		expect(first.status).toBe("ready");
		expect(first.inventory?.items).toHaveLength(1);
		expect(first.inventory?.items[0]?.scan.matched).toEqual([]);

		const failed = await provider.collect({
			...request,
			previous: first.inventory,
			options: {
				now: () => 1_000_500,
				maxAttempts: 1,
				scanTargetImpl: async () => {
					throw new Error("private credential");
				},
			},
		});
		expect(failed).toMatchObject({
			status: "degraded",
			freshness: "fresh",
			failClosed: false,
			reason: "targets_unreachable",
		});
		expect(failed.inventory?.items).toHaveLength(1);
		expect(failed.inventory?.items[0]).toMatchObject({
			lastSeenAt: first.inventory?.items[0]?.lastSeenAt,
			reachability: "unreachable",
			scan: { error: "collector_exception:Error" },
		});
		expect(JSON.stringify(failed)).not.toContain("private credential");
	});

	it("keeps partial probe failures degraded even when the endpoint responded", async () => {
		const result = await new LocalDiscoveryProvider().collect({
			...request,
			targets: [...request.targets, "http://127.0.0.1:8081"],
			options: {
				now: () => 1_000_000,
				scanTargetImpl: async ({ url }) =>
					scanResult(url, true, url.includes(":8081") ? "deadline_exceeded" : null),
			},
		});
		expect(result).toMatchObject({
			status: "degraded",
			freshness: "fresh",
			failClosed: false,
			reason: "target_scan_incomplete",
		});
		expect(result.inventory?.items).toHaveLength(2);
	});

	it("returns an explicit failure rather than empty inventory on invalid input or tenant mismatch", async () => {
		const provider = new LocalDiscoveryProvider();
		const scanTargetImpl = vi.fn(async ({ url }: { url: string }) => scanResult(url, true));
		const badTarget = await provider.collect({
			...request,
			targets: ["https://user:password@example.test"],
			options: { scanTargetImpl },
		});
		expect(badTarget).toMatchObject({
			status: "unavailable",
			inventory: null,
			failClosed: true,
			reason: "fleet_target_contains_private_components",
		});
		expect(scanTargetImpl).not.toHaveBeenCalled();
		const first = await provider.collect({ ...request, options: { scanTargetImpl } });
		scanTargetImpl.mockClear();
		const wrongTenant = await provider.collect({
			...request,
			tenantId: "tenant-b",
			previous: first.inventory,
			options: { scanTargetImpl },
		});
		expect(wrongTenant).toMatchObject({
			status: "unavailable",
			inventory: null,
			failClosed: true,
			reason: "fleet_inventory_scope_mismatch",
		});
		expect(scanTargetImpl).not.toHaveBeenCalled();
	});

	it("does not pass token-shaped exception messages through as reason codes", async () => {
		const result = await new LocalDiscoveryProvider().collect({
			...request,
			options: {
				now: () => {
					throw new Error("secret_token_abc123");
				},
				scanTargetImpl: async ({ url }) => scanResult(url, true),
			},
		});
		expect(result.reason).toBe("collection_failed");
	});

	it("aggregates age evidence worst-first without treating unknown as fresh", () => {
		const item = (freshness: FleetFreshness): FleetInventoryEntry => ({
			id: "a".repeat(64),
			kind: "ai_infrastructure",
			target: "http://127.0.0.1:8080/",
			firstSeenAt: new Date(1_000_000).toISOString(),
			lastSeenAt: null,
			lastAttemptAt: new Date(1_000_000).toISOString(),
			freshness,
			reachability: "not_checked",
			consecutiveFailures: 0,
			attempts: 0,
			nextRetryAt: null,
			scan: scanResult("http://127.0.0.1:8080/", false, "not_checked"),
		});
		expect(discoveryFreshnessForInventory({ items: [item("fresh")] })).toBe("fresh");
		expect(discoveryFreshnessForInventory({ items: [item("fresh"), item("stale")] })).toBe("stale");
		expect(discoveryFreshnessForInventory({ items: [item("stale"), item("never_seen")] })).toBe(
			"never_seen",
		);
		expect(discoveryFreshnessForInventory({ items: [] })).toBe("never_seen");
	});
});
