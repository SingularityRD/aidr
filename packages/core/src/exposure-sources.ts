/**
 * Adapters from the product's existing discovery records into exposure
 * observations (MKT-01).
 *
 * `exposure-graph.ts` deliberately knows nothing about how inventories are
 * collected. This module is the only place that maps an existing record shape
 * onto graph nodes, so a new source is added by writing one small function here
 * instead of teaching the graph about it:
 *
 *   - MCP servers from `mcp-inventory.ts` / `mcp-discovery.ts` — a readable
 *     config yields an `mcp_server` observation; a missing file is reported
 *     `missing`; a file that exists but cannot be parsed is `unreadable`, which
 *     the graph surfaces as a coverage gap rather than as "no MCP servers".
 *   - AI infrastructure from `fleet-inventory.ts` — a reachable target with a
 *     `lastSeenAt` yields a source observation; an unreachable or never-seen
 *     target advances the attempt without advancing the last-seen edge, so a
 *     collector that stops reporting goes stale instead of staying current.
 *
 * Nothing here performs I/O: callers pass records they already collected.
 * These functions do not claim any cloud, IdP or MDM coverage.
 */

import type {
	ExposureNodeKind,
	ExposureObservationEdge,
	ExposureObservationInput,
	ExposureObservationNode,
	ExposureSourceStatus,
	HasherContext,
} from "./exposure-graph.js";
import { exposureNodeId } from "./exposure-graph.js";
import type { FleetInventory, FleetInventoryEntry } from "./fleet-inventory.js";
import type { McpInventoryItem, McpInventoryReport } from "./mcp-inventory.js";

/**
 * Kinds this adapter maps onto. `host` covers an endpoint the agent runs on;
 * `data_source` covers a reachable AI service origin. They are kept distinct so
 * a service origin is never mistaken for the host that happens to run it.
 */
export type ExposureSourceKind = Extract<
	ExposureNodeKind,
	"agent" | "host" | "user" | "mcp_server" | "tool" | "credential" | "data_source"
>;

export interface ExposureMcpInventoryOptions {
	tenantId: string;
	/** Collector identity, so two agents relaying the same inventory dedupe. */
	observationId: string;
	/** Observation time in ms. Required: the graph never reads the host clock. */
	observedAtMs: number;
	sourceRef: string;
	/** Identity of the endpoint the inventory was read on, when known. */
	hostNaturalKey?: string;
	/** Identity of the agent that read the inventory, when known. */
	agentNaturalKey?: string;
	context: HasherContext;
}

export interface ExposureMcpInventoryBatch {
	observations: ExposureObservationInput[];
	sources: ExposureSourceStatus[];
}

/** Host and agent nodes for the endpoint the inventory was read on, when known. */
function endpointNodes(options: ExposureMcpInventoryOptions): {
	nodes: ExposureObservationNode[];
	hostNodeId: string | null;
	agentNodeId: string | null;
} {
	const nodes: ExposureObservationNode[] = [];
	let hostNodeId: string | null = null;
	if (options.hostNaturalKey) {
		hostNodeId = exposureNodeId(options.tenantId, "host", options.hostNaturalKey, options.context);
		nodes.push({ kind: "host", naturalKey: options.hostNaturalKey });
	}
	let agentNodeId: string | null = null;
	if (options.agentNaturalKey) {
		agentNodeId = exposureNodeId(
			options.tenantId,
			"agent",
			options.agentNaturalKey,
			options.context,
		);
		nodes.push({ kind: "agent", naturalKey: options.agentNaturalKey });
	}
	return { nodes, hostNodeId, agentNodeId };
}

/**
 * Map one MCP inventory report into an exposure observation plus source statuses.
 *
 * A server entry is one `mcp_server` node; `riskHints` become metadata, not a
 * verdict. The `sourcePath` is part of the server's natural key, matching the
 * inventory identity the discovery contract already publishes, so the same
 * server configured for two clients is two nodes rather than a false merge.
 */
export function exposureObservationsFromMcpInventory(
	report: McpInventoryReport,
	options: ExposureMcpInventoryOptions,
): ExposureMcpInventoryBatch {
	const endpoint = endpointNodes(options);
	const nodes: ExposureObservationNode[] = [...endpoint.nodes];
	const edges: ExposureObservationEdge[] = [];

	for (const item of report.items) {
		const serverNodeId = exposureNodeId(
			options.tenantId,
			"mcp_server",
			mcpServerNaturalKey(item),
			options.context,
		);
		nodes.push({
			kind: "mcp_server",
			naturalKey: mcpServerNaturalKey(item),
			label: item.name,
			metadata: {
				transport: item.url ? "remote" : "stdio",
				status: item.status,
				risk_hints: item.riskHints.join(","),
			},
		});
		if (endpoint.hostNodeId) {
			edges.push({ kind: "runs_on", fromNodeId: serverNodeId, toNodeId: endpoint.hostNodeId });
		}
		if (endpoint.agentNodeId) {
			edges.push({ kind: "uses", fromNodeId: endpoint.agentNodeId, toNodeId: serverNodeId });
		}
	}

	const sources: ExposureSourceStatus[] = report.sources.map((source) => ({
		sourceRef: source.path,
		source: "mcp_inventory",
		// `invalid` is the inventory layer's "present but unreadable": it is a
		// coverage gap, whereas a genuinely absent file is only `missing`.
		status:
			source.status === "invalid" ? ("unreadable" as const) : (source.status as "read" | "missing"),
		...(source.status === "invalid" ? { detail: "inventory_unreadable" } : {}),
	}));

	// A report with no readable source still produces the host/agent observation,
	// so an agent that could not read any config is visible rather than absent.
	const observations: ExposureObservationInput[] = [];
	if (nodes.length > 0) {
		observations.push({
			tenantId: options.tenantId,
			observationId: options.observationId,
			source: "mcp_inventory",
			sourceRef: options.sourceRef,
			observedAtMs: options.observedAtMs,
			nodes,
			...(edges.length === 0 ? {} : { edges }),
		});
	}
	return { observations, sources };
}

/** Stable natural key for an MCP server entry: its source path and configured name. */
export function mcpServerNaturalKey(item: Pick<McpInventoryItem, "sourcePath" | "name">): string {
	return `mcp:${item.sourcePath}#${item.name}`;
}

export interface ExposureFleetInventoryOptions {
	tenantId: string;
	/** Cycling identity; the last-seen timestamp decides whether it advances. */
	observationId: string;
	context: HasherContext;
}

/**
 * Map a fleet inventory into exposure observations.
 *
 * One observation is produced per inventory item, so an unreachable target
 * records `observed: false` on its own and cannot advance the last-seen edge of
 * a reachable one. A target that was never reachable reports `missing` — the
 * graph then shows it as `unknown`, never as current.
 */
export function exposureObservationsFromFleetInventory(
	inventory: FleetInventory,
	options: ExposureFleetInventoryOptions,
): ExposureObservationInput[] {
	return inventory.items.map((item) =>
		exposureObservationFromFleetEntry(item, {
			tenantId: options.tenantId,
			observationId: `${options.observationId}:${item.id.slice(0, 16)}`,
			context: options.context,
		}),
	);
}

function exposureObservationFromFleetEntry(
	entry: FleetInventoryEntry,
	options: { tenantId: string; observationId: string; context: HasherContext },
): ExposureObservationInput {
	const lastSeenAtMs = entry.lastSeenAt ? Date.parse(entry.lastSeenAt) : Number.NaN;
	// Only a reachable probe with a recorded last-seen time advances the edge.
	const observed = entry.reachability === "reachable" && Number.isFinite(lastSeenAtMs);
	const observedAtMs = observed
		? lastSeenAtMs
		: Number.isFinite(Date.parse(entry.lastAttemptAt))
			? Date.parse(entry.lastAttemptAt)
			: 0;
	return {
		tenantId: options.tenantId,
		observationId: options.observationId,
		source: "fleet_inventory",
		sourceRef: entry.target,
		observedAtMs,
		observed,
		nodes: [
			{
				kind: "data_source",
				naturalKey: `origin:${entry.target}`,
				label: entry.target,
				metadata: {
					freshness: entry.freshness,
					reachability: entry.reachability,
					consecutive_failures: String(entry.consecutiveFailures),
				},
			},
		],
	};
}

/** Per-item fleet observations also carry their own source status. */
export function exposureSourcesFromFleetInventory(
	inventory: FleetInventory,
): ExposureSourceStatus[] {
	return inventory.items.map((item) => ({
		sourceRef: item.target,
		source: "fleet_inventory",
		// An unreachable target is not an unreadable source: the collector ran and
		// reported. Only a malformed report would be unreadable, and that is
		// rejected before it becomes an inventory.
		status: "read",
	}));
}

/**
 * Convenience: fold MCP inventory and fleet inventory together for one tenant.
 * Kept in this module so a caller never has to import the graph and the
 * inventory shapes at once.
 */
export function mergeExposureObservationBatches(
	batches: readonly ExposureObservationInput[][],
): ExposureObservationInput[] {
	const out: ExposureObservationInput[] = [];
	for (const batch of batches) out.push(...batch);
	return out;
}
