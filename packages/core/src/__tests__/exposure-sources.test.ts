import { describe, expect, it } from "vitest";
import {
	createSha256HasherContext,
	type ExposureGraph,
	exposureCoverage,
	exposureStaleness,
	exposureStalenessReport,
	foldExposureObservations,
} from "../exposure-graph.js";
import {
	exposureObservationsFromFleetInventory,
	exposureObservationsFromMcpInventory,
	exposureSourcesFromFleetInventory,
	mcpServerNaturalKey,
	mergeExposureObservationBatches,
} from "../exposure-sources.js";
import type { FleetInventory } from "../fleet-inventory.js";
import type { McpInventoryReport } from "../mcp-inventory.js";

const hash = createSha256HasherContext();
const TENANT = "11111111-1111-4111-8111-111111111111";
const BASE = Date.parse("2026-09-13T00:00:00.000Z");
const WINDOW = 15 * 60 * 1000;

function mcpReport(overrides: Partial<McpInventoryReport> = {}): McpInventoryReport {
	return {
		items: [
			{
				name: "tool-server",
				command: "npx",
				url: null,
				args: ["-y", "tool-server"],
				sourcePath: "~/.cursor/mcp.json",
				riskHints: ["shell_wrapper_command"],
				status: "unknown",
			},
		],
		sources: [{ path: "~/.cursor/mcp.json", status: "read" }],
		...overrides,
	};
}

function fleetInventory(overrides: Partial<FleetInventory> = {}): FleetInventory {
	return {
		schemaVersion: 1,
		tenantId: TENANT,
		collectorId: "collector-1",
		generatedAt: new Date(BASE).toISOString(),
		staleAfterMs: WINDOW,
		items: [
			{
				id: "entry-1",
				kind: "ai_infrastructure",
				target: "https://infra.example.test/",
				firstSeenAt: new Date(BASE - 60_000).toISOString(),
				lastSeenAt: new Date(BASE).toISOString(),
				lastAttemptAt: new Date(BASE).toISOString(),
				freshness: "fresh",
				reachability: "reachable",
				consecutiveFailures: 0,
				attempts: 1,
				nextRetryAt: null,
				scan: { url: "https://infra.example.test/", reachable: true, matched: [], cves: [], error: null, requestsMade: 1 },
			},
		],
		...overrides,
	};
}

describe("MCP inventory adapter", () => {
	it("maps a readable inventory into a server node with its source status", () => {
		const batch = exposureObservationsFromMcpInventory(mcpReport(), {
			tenantId: TENANT,
			observationId: "obs-mcp-1",
			observedAtMs: BASE,
			sourceRef: "~/.cursor/mcp.json",
			hostNaturalKey: "host-1",
			agentNaturalKey: "agent-install-1",
			context: hash,
		});
		expect(batch.sources).toEqual([
			{ sourceRef: "~/.cursor/mcp.json", source: "mcp_inventory", status: "read" },
		]);
		const observation = batch.observations[0];
		expect(observation?.nodes.map((node) => node.kind)).toEqual(["host", "agent", "mcp_server"]);
		expect(observation?.edges?.map((edge) => edge.kind).sort()).toEqual(["runs_on", "uses"]);

		const result = foldExposureObservations(mergeExposureObservationBatches([batch.observations]), {
			...hash,
			tenantId: TENANT,
		});
		expect(result.coverage.unobservedKinds).not.toContain("mcp_server");
		expect(result.graph.nodes.find((node) => node.kind === "mcp_server")?.label).toBe("tool-server");
	});

	it("keeps the same server configured for two clients as two distinct nodes", () => {
		const first = exposureObservationsFromMcpInventory(mcpReport(), {
			tenantId: TENANT,
			observationId: "obs-a",
			observedAtMs: BASE,
			sourceRef: "~/.cursor/mcp.json",
			context: hash,
		});
		const second = exposureObservationsFromMcpInventory(
			mcpReport({ items: [{ ...mcpReport().items[0]!, sourcePath: "~/.claude.json" }] }),
			{
				tenantId: TENANT,
				observationId: "obs-b",
				observedAtMs: BASE,
				sourceRef: "~/.claude.json",
				context: hash,
			},
		);
		expect(mcpServerNaturalKey(mcpReport().items[0]!)).toBe("mcp:~/.cursor/mcp.json#tool-server");
		expect(mcpServerNaturalKey({ sourcePath: "~/.claude.json", name: "tool-server" })).not.toBe(
			mcpServerNaturalKey(mcpReport().items[0]!),
		);
		const result = foldExposureObservations(
			mergeExposureObservationBatches([first.observations, second.observations]),
			{ ...hash, tenantId: TENANT },
		);
		expect(result.graph.nodes.filter((node) => node.kind === "mcp_server")).toHaveLength(2);
	});

	it("reports an unreadable inventory as a coverage gap, not as an empty inventory", () => {
		const batch = exposureObservationsFromMcpInventory(
			mcpReport({
				items: [],
				sources: [
					{ path: "~/.cursor/mcp.json", status: "invalid" },
					{ path: "~/.claude.json", status: "missing" },
				],
			}),
			{
				tenantId: TENANT,
				observationId: "obs-mcp-2",
				observedAtMs: BASE,
				sourceRef: "~/.cursor/mcp.json",
				hostNaturalKey: "host-1",
				context: hash,
			},
		);
		const result = foldExposureObservations(mergeExposureObservationBatches([batch.observations]), {
			...hash,
			tenantId: TENANT,
		});
		const coverage = exposureCoverage(result.graph, batch.sources);
		expect(coverage.unreadableSources).toEqual([
			{ sourceRef: "~/.cursor/mcp.json", source: "mcp_inventory", detail: "inventory_unreadable" },
		]);
		// The host is still visible even though no config could be read.
		expect(result.graph.nodes.map((node) => node.kind)).toEqual(["host"]);
		expect(coverage.unobservedKinds).toContain("mcp_server");
	});

	it("produces no observation when it has nothing at all to report", () => {
		const batch = exposureObservationsFromMcpInventory(
			mcpReport({ items: [], sources: [] }),
			{
				tenantId: TENANT,
				observationId: "obs-empty",
				observedAtMs: BASE,
				sourceRef: "~/.cursor/mcp.json",
				context: hash,
			},
		);
		expect(batch.observations).toEqual([]);
	});
});

describe("fleet inventory adapter", () => {
	it("advances the last-seen edge only for a reachable target", () => {
		const reachable = exposureObservationsFromFleetInventory(fleetInventory(), {
			tenantId: TENANT,
			observationId: "cycle-1",
			context: hash,
		});
		expect(reachable[0]?.observed).toBe(true);
		expect(reachable[0]?.observedAtMs).toBe(BASE);

		const unreachable = exposureObservationsFromFleetInventory(
			fleetInventory({
				items: [
					{
						...fleetInventory().items[0]!,
						reachability: "unreachable",
						freshness: "stale",
						lastSeenAt: null,
						consecutiveFailures: 3,
					},
				],
			}),
			{ tenantId: TENANT, observationId: "cycle-2", context: hash },
		);
		expect(unreachable[0]?.observed).toBe(false);
	});

	it("keeps a target that stopped reporting stale in the folded graph", () => {
		const first = exposureObservationsFromFleetInventory(fleetInventory(), {
			tenantId: TENANT,
			observationId: "cycle-1",
			context: hash,
		});
		const second = exposureObservationsFromFleetInventory(
			fleetInventory({
				items: [
					{
						...fleetInventory().items[0]!,
						reachability: "unreachable",
						freshness: "stale",
						lastSeenAt: null,
						lastAttemptAt: new Date(BASE + WINDOW + 1).toISOString(),
						consecutiveFailures: 1,
					},
				],
			}),
			{ tenantId: TENANT, observationId: "cycle-2", context: hash },
		);
		const result = foldExposureObservations(
			mergeExposureObservationBatches([first, second]),
			{ ...hash, tenantId: TENANT },
		);
		const node = result.graph.nodes.find((entry) => entry.kind === "data_source");
		expect(node?.lastSeenAtMs).toBe(BASE);
		expect(exposureStaleness(node?.lastSeenAtMs ?? null, BASE, WINDOW)).toBe("fresh");
		expect(exposureStaleness(node?.lastSeenAtMs ?? null, BASE + WINDOW + 1, WINDOW)).toBe("stale");

		// The twin that never reported at all stays unknown, never fresh.
		const neverSeen = foldExposureObservations(
			mergeExposureObservationBatches([
				exposureObservationsFromFleetInventory(
					fleetInventory({
						items: [
							{
								...fleetInventory().items[0]!,
								reachability: "not_checked",
								freshness: "never_seen",
								lastSeenAt: null,
							},
						],
					}),
					{ tenantId: TENANT, observationId: "cycle-3", context: hash },
				),
			]),
			{ ...hash, tenantId: TENANT },
		);
		const report = exposureStalenessReport(neverSeen.graph, BASE, WINDOW);
		expect(report.fresh).toBe(0);
		expect(report.unknown).toBe(1);
	});

	it("reports a reachable target's source as read", () => {
		expect(exposureSourcesFromFleetInventory(fleetInventory())).toEqual([
			{ sourceRef: "https://infra.example.test/", source: "fleet_inventory", status: "read" },
		]);
	});

	it("folds the two adapters into one graph without duplicates", () => {
		const mcp = exposureObservationsFromMcpInventory(mcpReport(), {
			tenantId: TENANT,
			observationId: "obs-mcp",
			observedAtMs: BASE,
			sourceRef: "~/.cursor/mcp.json",
			hostNaturalKey: "host-1",
			context: hash,
		});
		const fleet = exposureObservationsFromFleetInventory(fleetInventory(), {
			tenantId: TENANT,
			observationId: "cycle-1",
			context: hash,
		});
		const batch = mergeExposureObservationBatches([mcp.observations, fleet]);
		const once = foldExposureObservations(batch, { ...hash, tenantId: TENANT });
		const twice = foldExposureObservations([...batch, ...batch], { ...hash, tenantId: TENANT });
		expect(twice.duplicates).toEqual(once.accepted);
		expect(twice.graph.nodes).toHaveLength(once.graph.nodes.length);
		expect((twice.graph as ExposureGraph).nodes.length).toBe(3);
	});
});
