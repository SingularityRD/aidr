import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { AigInfraTargetResult } from "../aig-infra-scan.js";
import {
	collectFleetInventory,
	fleetInventoryEntryId,
	loadFleetInventory,
	normalizeFleetTarget,
	refreshFleetInventoryFreshness,
	saveFleetInventory,
} from "../fleet-inventory.js";

function result(
	url: string,
	reachable: boolean,
	error: string | null = null,
): AigInfraTargetResult {
	return {
		url,
		reachable,
		matched: [],
		cves: [],
		error,
		requestsMade: 1,
	};
}

describe("tenant fleet inventory", () => {
	it("normalizes and de-duplicates stable target identities without retaining private URL components", async () => {
		expect(normalizeFleetTarget("HTTP://LOCALHOST:80/console/")).toBe("http://localhost/console");
		expect(() => normalizeFleetTarget("https://user:secret@example.test/")).toThrow(
			"fleet_target_contains_private_components",
		);
		expect(() => normalizeFleetTarget("https://example.test/?token=secret")).toThrow(
			"fleet_target_contains_private_components",
		);

		const scanTargetImpl = vi.fn(async ({ url }: { url: string }) => result(url, true));
		const inventory = await collectFleetInventory(
			"tenant-a",
			"collector-a",
			["HTTP://LOCALHOST:80/console/", "http://localhost/console"],
			null,
			{ now: () => 1_000_000, scanTargetImpl },
		);
		expect(inventory.items).toHaveLength(1);
		expect(scanTargetImpl).toHaveBeenCalledTimes(1);
		expect(inventory.items[0]?.id).toBe(
			fleetInventoryEntryId("tenant-a", "http://localhost/console"),
		);
		expect(fleetInventoryEntryId("tenant-b", "http://localhost/console")).not.toBe(
			inventory.items[0]?.id,
		);
	});

	it("does not refresh last-seen evidence when a target becomes unreachable", async () => {
		const first = await collectFleetInventory(
			"tenant-a",
			"collector-a",
			["http://127.0.0.1:8080"],
			null,
			{
				now: () => 1_000_000,
				staleAfterMs: 1_000,
				scanTargetImpl: async ({ url }) => result(url, true),
			},
		);
		const lastSeenAt = first.items[0]?.lastSeenAt;
		const second = await collectFleetInventory(
			"tenant-a",
			"collector-a",
			["http://127.0.0.1:8080"],
			first,
			{
				now: () => 1_000_500,
				staleAfterMs: 1_000,
				maxAttempts: 1,
				baseRetryDelayMs: 10,
				scanTargetImpl: async ({ url }) => result(url, false, "connection_refused"),
			},
		);
		expect(second.items[0]).toMatchObject({
			lastSeenAt,
			freshness: "fresh",
			reachability: "unreachable",
			consecutiveFailures: 1,
			attempts: 1,
		});
		const stale = refreshFleetInventoryFreshness(second, 1_001_001);
		expect(stale.items[0]?.freshness).toBe("stale");
	});

	it("keeps the exact freshness boundary fresh and rejects future or invalid evidence", async () => {
		const inventory = await collectFleetInventory(
			"tenant-a",
			"collector-a",
			["http://127.0.0.1:8080"],
			null,
			{ now: () => 1_000_000, staleAfterMs: 1_000, scanTargetImpl: async ({ url }) => result(url, true) },
		);
		const entry = inventory.items[0];
		if (!entry) throw new Error("test inventory is missing its entry");
		expect(refreshFleetInventoryFreshness(inventory, 1_001_000).items[0]?.freshness).toBe("fresh");
		expect(refreshFleetInventoryFreshness(inventory, 1_001_001).items[0]?.freshness).toBe("stale");
		expect(
			refreshFleetInventoryFreshness(
				{ ...inventory, items: [{ ...entry, lastSeenAt: new Date(1_001_000).toISOString() }] },
				1_000_000,
			).items[0]?.freshness,
		).toBe("stale");
		expect(
			refreshFleetInventoryFreshness(
				{ ...inventory, items: [{ ...entry, lastSeenAt: "not-a-timestamp" }] },
				1_000_000,
			).items[0]?.freshness,
		).toBe("never_seen");
	});

	it("bounds transient retries and exponential delays", async () => {
		const delays: number[] = [];
		let calls = 0;
		const inventory = await collectFleetInventory(
			"tenant-a",
			"collector-a",
			["http://127.0.0.1:8080"],
			null,
			{
				now: () => 1_000_000,
				maxAttempts: 3,
				baseRetryDelayMs: 10,
				maxRetryDelayMs: 15,
				sleep: async (delay) => {
					delays.push(delay);
				},
				scanTargetImpl: async ({ url }) => {
					calls++;
					return result(url, calls === 3, calls === 3 ? null : "timeout");
				},
			},
		);
		expect(calls).toBe(3);
		expect(delays).toEqual([10, 15]);
		expect(inventory.items[0]).toMatchObject({
			attempts: 3,
			reachability: "reachable",
			consecutiveFailures: 0,
			nextRetryAt: null,
		});
	});

	it("caps caller-supplied retry attempts at five", async () => {
		const scanTargetImpl = vi.fn(async ({ url }: { url: string }) => result(url, false, "timeout"));
		const inventory = await collectFleetInventory(
			"tenant-a",
			"collector-a",
			["http://127.0.0.1:8080"],
			null,
			{
				maxAttempts: 99,
				baseRetryDelayMs: 0,
				sleep: async () => {},
				scanTargetImpl,
			},
		);
		expect(scanTargetImpl).toHaveBeenCalledTimes(5);
		expect(inventory.items[0]?.attempts).toBe(5);
	});

	it("does not retry terminal scope failures", async () => {
		const scanTargetImpl = vi.fn(async ({ url }: { url: string }) =>
			result(url, false, "target_not_allowed"),
		);
		const inventory = await collectFleetInventory(
			"tenant-a",
			"collector-a",
			["https://public.example.test"],
			null,
			{ maxAttempts: 5, scanTargetImpl },
		);
		expect(scanTargetImpl).toHaveBeenCalledTimes(1);
		expect(inventory.items[0]).toMatchObject({
			freshness: "never_seen",
			reachability: "unreachable",
			attempts: 1,
			nextRetryAt: null,
		});
	});

	it("refuses to merge an inventory from a different tenant", async () => {
		const previous = await collectFleetInventory(
			"tenant-a",
			"collector-a",
			["http://127.0.0.1:8080"],
			null,
			{ scanTargetImpl: async ({ url }) => result(url, true) },
		);
		await expect(
			collectFleetInventory("tenant-b", "collector-a", ["http://127.0.0.1:8080"], previous, {
				scanTargetImpl: async ({ url }) => result(url, true),
			}),
		).rejects.toThrow("fleet_inventory_scope_mismatch");
	});

	it("persists inventory atomically and reads it back", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-fleet-"));
		try {
			const path = join(dir, "inventory.json");
			const inventory = await collectFleetInventory(
				"tenant-a",
				"collector-a",
				["http://127.0.0.1:8080"],
				null,
				{ scanTargetImpl: async ({ url }) => result(url, true) },
			);
			await saveFleetInventory(path, inventory);
			expect(await loadFleetInventory(path)).toEqual(inventory);
			expect(await loadFleetInventory(join(dir, "missing.json"))).toBeNull();
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});
