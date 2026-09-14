import { describe, expect, it } from "vitest";
import {
	canonicalExposureGraphJson,
	createSha256HasherContext,
	EXPOSURE_NODE_KINDS,
	type ExposureGraph,
	type ExposureNode,
	type ExposureNodeKind,
	type ExposureObservationInput,
	type ExposureSourceStatus,
	exposureCoverage,
	exposureEdgeId,
	exposureEdgesTouching,
	exposureNodeId,
	exposureObservationDigest,
	exposureStaleness,
	exposureStalenessReport,
	foldExposureObservations,
} from "../exposure-graph.js";

const hash = createSha256HasherContext();

const TENANT = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT = "22222222-2222-4222-8222-222222222222";
const BASE = Date.parse("2026-09-13T00:00:00.000Z");

function nodeId(kind: ExposureNodeKind, naturalKey: string): string {
	return exposureNodeId(TENANT, kind, naturalKey, hash);
}

/** A benign observation: one agent on one host, the host's user, and an MCP server. */
function baseObservation(overrides: Partial<ExposureObservationInput> = {}): ExposureObservationInput {
	return {
		tenantId: TENANT,
		observationId: "obs-1",
		source: "mcp_inventory",
		sourceRef: "~/.cursor/mcp.json",
		observedAtMs: BASE,
		nodes: [
			{ kind: "agent", naturalKey: "agent-install-1", label: "Cursor agent" },
			{ kind: "host", naturalKey: "host-1" },
			{ kind: "user", naturalKey: "user-1" },
		],
		edges: [
			{
				kind: "runs_on",
				fromNodeId: nodeId("agent", "agent-install-1"),
				toNodeId: nodeId("host", "host-1"),
			},
		],
		...overrides,
	};
}

function graphOf(records: ExposureObservationInput[]): ExposureGraph {
	return foldExposureObservations(records, { ...hash, tenantId: TENANT }).graph;
}

function nodeOf(graph: ExposureGraph, kind: ExposureNodeKind, naturalKey: string): ExposureNode | undefined {
	return graph.nodes.find((node) => node.nodeId === nodeId(kind, naturalKey));
}

describe("exposure graph identity", () => {
	it("derives a stable opaque node id from the source record but not from wall-clock order", () => {
		const graph = graphOf([baseObservation({ observedAtMs: BASE + 60_000 })]);
		const agent = nodeOf(graph, "agent", "agent-install-1");
		expect(agent?.nodeId).toBe(nodeId("agent", "agent-install-1"));
		expect(agent?.nodeId).toMatch(/^xnode_[0-9a-f]{64}$/);
		expect(agent?.label).toBe("Cursor agent");
		// A second observation of the same agent after a restart must reconcile to
		// the same identity instead of creating a new node.
		const later = graphOf([
			baseObservation({ observedAtMs: BASE + 60_000 }),
			baseObservation({ observationId: "obs-2", observedAtMs: BASE + 120_000 }),
		]);
		expect(later.nodes).toHaveLength(graph.nodes.length);
	});

	it("gives different tenants different ids for the same natural key", () => {
		expect(exposureNodeId(TENANT, "host", "host-1", hash)).not.toBe(
			exposureNodeId(OTHER_TENANT, "host", "host-1", hash),
		);
	});

	it("rejects a malformed identity input rather than minting an id for it", () => {
		expect(() => exposureNodeId(TENANT, "host", "", hash)).toThrow(/exposure_natural_key_invalid/);
		expect(() => exposureNodeId("bad tenant id", "host", "host-1", hash)).toThrow(
			/exposure_tenant_id_invalid/,
		);
		expect(() => exposureEdgeId(TENANT, "runs_on", "not-a-node", "not-a-node", hash)).toThrow(
			/exposure_edge_endpoint_invalid/,
		);
	});
});

describe("exposure graph folding", () => {
	it("is order-independent: a permuted batch folds to the same graph", () => {
		const a = baseObservation();
		const b = baseObservation({
			observationId: "obs-2",
			source: "fleet_inventory",
			sourceRef: "https://infra.example.test/",
			observedAtMs: BASE + 30_000,
			nodes: [
				{ kind: "mcp_server", naturalKey: "inventory:tool-server", label: "tool-server" },
				{ kind: "tool", naturalKey: "inventory:tool-server.read_file" },
			],
			edges: [
				{
					kind: "uses",
					fromNodeId: nodeId("agent", "agent-install-1"),
					toNodeId: nodeId("mcp_server", "inventory:tool-server"),
				},
			],
		});
		const c = baseObservation({
			observationId: "obs-3",
			source: "operator",
			sourceRef: "operator:allowlist",
			observedAtMs: BASE + 15_000,
			nodes: [{ kind: "credential", naturalKey: "credential-ref-1" }],
			edges: [
				{
					kind: "can_reach",
					fromNodeId: nodeId("tool", "inventory:tool-server.read_file"),
					toNodeId: nodeId("credential", "credential-ref-1"),
				},
			],
		});
		const forward = foldExposureObservations([a, b, c], { ...hash, tenantId: TENANT });
		const shuffled = foldExposureObservations([c, a, b], { ...hash, tenantId: TENANT });
		expect(canonicalExposureGraphJson(shuffled.graph)).toBe(canonicalExposureGraphJson(forward.graph));
		expect(shuffled.accepted).toEqual(forward.accepted);
	});

	it("is idempotent: a repeated observation is a duplicate and changes nothing", () => {
		const record = baseObservation();
		const first = foldExposureObservations([record], { ...hash, tenantId: TENANT });
		const replay = foldExposureObservations([record, record], { ...hash, tenantId: TENANT });
		expect(replay.duplicates).toEqual(["obs-1"]);
		expect(replay.accepted).toEqual(["obs-1"]);
		expect(replay.rejections).toEqual([]);
		expect(canonicalExposureGraphJson(replay.graph)).toBe(
			canonicalExposureGraphJson(first.graph),
		);
		expect(replay.graph.nodes[0]?.observationIds).toEqual(["obs-1"]);
	});

	it("refuses a replay whose content changed instead of letting the newer copy win", () => {
		const original = baseObservation();
		const rewritten = baseObservation({ nodes: [{ kind: "host", naturalKey: "host-2" }], edges: [] });
		const result = foldExposureObservations([original, rewritten], { ...hash, tenantId: TENANT });
		expect(result.rejections.map((rejection) => rejection.code)).toEqual([
			"conflicting_observation",
		]);
		expect(result.graph.nodes.some((node) => node.kind === "host" && node.naturalKey === "host-2")).toBe(
			false,
		);
	});
});

describe("exposure graph tenant boundary", () => {
	it("refuses a cross-tenant record with cross_tenant_record and merges nothing", () => {
		const result = foldExposureObservations(
			[
				baseObservation(),
				baseObservation({
					tenantId: OTHER_TENANT,
					observationId: "obs-foreign",
					nodes: [{ kind: "host", naturalKey: "host-foreign" }],
					edges: [],
				}),
			],
			{ ...hash, tenantId: TENANT },
		);
		expect(result.rejections).toHaveLength(1);
		expect(result.rejections[0]).toMatchObject({
			observationId: "obs-foreign",
			tenantId: OTHER_TENANT,
			code: "cross_tenant_record",
		});
		expect(result.graph.tenantId).toBe(TENANT);
		expect(result.graph.nodes.some((node) => node.naturalKey === "host-foreign")).toBe(false);
		expect(result.accepted).toEqual(["obs-1"]);
	});

	it("establishes the tenant from the first record and refuses the other direction too", () => {
		const result = foldExposureObservations(
			[
				baseObservation({ tenantId: OTHER_TENANT, observationId: "obs-foreign" }),
				baseObservation(),
			],
			{ ...hash, tenantId: OTHER_TENANT },
		);
		expect(result.rejections[0]?.code).toBe("cross_tenant_record");
		expect(result.graph.tenantId).toBe(OTHER_TENANT);
		expect(result.graph.nodes).toHaveLength(3);
	});

	it("refuses an unreadable record as data instead of throwing away the whole batch", () => {
		const result = foldExposureObservations(
			[baseObservation(), { tenantId: TENANT, observationId: "obs-broken" }, 42],
			{ ...hash, tenantId: TENANT },
		);
		expect(result.accepted).toEqual(["obs-1"]);
		expect(result.rejections.map((rejection) => rejection.code)).toEqual([
			"invalid_record",
			"invalid_record",
		]);
		expect(result.graph.nodes).toHaveLength(3);
	});

	it("refuses an edge whose endpoints are not in the graph", () => {
		const result = foldExposureObservations(
			[
				baseObservation({
					edges: [
						{
							kind: "uses",
							fromNodeId: nodeId("agent", "agent-install-1"),
							toNodeId: nodeId("mcp_server", "never-observed"),
						},
					],
				}),
			],
			{ ...hash, tenantId: TENANT },
		);
		expect(result.rejections.map((rejection) => rejection.code)).toEqual(["dangling_edge"]);
		expect(result.graph.edges).toEqual([]);
	});
});

describe("exposure staleness", () => {
	const WINDOW = 15 * 60 * 1000;

	it("treats the window as inclusive: exactly-at-window is fresh", () => {
		expect(exposureStaleness(BASE, BASE + WINDOW, WINDOW)).toBe("fresh");
	});

	it("is fresh just inside the window and stale just outside it", () => {
		expect(exposureStaleness(BASE, BASE + WINDOW - 1, WINDOW)).toBe("fresh");
		expect(exposureStaleness(BASE, BASE + WINDOW + 1, WINDOW)).toBe("stale");
		expect(exposureStaleness(BASE, BASE + 24 * 60 * 60 * 1000, WINDOW)).toBe("stale");
	});

	it("reports unknown for a missing clock, a bad window or a future timestamp — never fresh", () => {
		expect(exposureStaleness(null, BASE, WINDOW)).toBe("unknown");
		expect(exposureStaleness(undefined, BASE, WINDOW)).toBe("unknown");
		expect(exposureStaleness(Number.NaN, BASE, WINDOW)).toBe("unknown");
		expect(exposureStaleness(BASE, Number.NaN, WINDOW)).toBe("unknown");
		expect(exposureStaleness(BASE, BASE, Number.NaN)).toBe("unknown");
		expect(exposureStaleness(BASE, BASE - 1, WINDOW)).toBe("unknown");
	});

	it("marks a source that stopped reporting stale instead of current", () => {
		const record = baseObservation();
		const graph = graphOf([record]);
		const atArrival = exposureStalenessReport(graph, BASE, WINDOW);
		expect(atArrival.hasStaleOrUnknown).toBe(false);
		expect(atArrival.fresh).toBe(3);

		const muchLater = exposureStalenessReport(graph, BASE + WINDOW + 1, WINDOW);
		expect(muchLater.stale).toBe(3);
		expect(muchLater.fresh).toBe(0);
		expect(muchLater.hasStaleOrUnknown).toBe(true);
	});

	it("does not advance the last-seen edge for an attempt that observed nothing", () => {
		const graph = graphOf([
			baseObservation(),
			baseObservation({
				observationId: "obs-failed",
				observedAtMs: BASE + 5 * 60 * 1000,
				observed: false,
			}),
		]);
		const host = nodeOf(graph, "host", "host-1");
		expect(host?.lastSeenAtMs).toBe(BASE);
		expect(host?.firstSeenAtMs).toBe(BASE);
		expect(host?.observationIds).toEqual(["obs-1", "obs-failed"]);
		expect(exposureStaleness(host?.lastSeenAtMs ?? null, BASE + 5 * 60 * 1000, WINDOW)).toBe("fresh");
		expect(exposureStaleness(host?.lastSeenAtMs ?? null, BASE + WINDOW + 1, WINDOW)).toBe("stale");
	});

	it("reports a never-current node as unknown, never as fresh", () => {
		const graph = graphOf([
			baseObservation({ observed: false }),
		]);
		const report = exposureStalenessReport(graph, BASE, WINDOW);
		expect(report.unknown).toBe(3);
		expect(report.fresh).toBe(0);
		expect(report.entries.every((entry) => entry.staleness === "unknown")).toBe(true);
	});

	it("applies the caller's clock to authorization edges", () => {
		const record = baseObservation();
		const graph = graphOf([record]);
		const edge = graph.edges[0];
		expect(edge).toBeDefined();
		const now = exposureEdgesTouching(graph, {
			nodeId: nodeId("agent", "agent-install-1"),
			kind: "runs_on",
			nowMs: BASE + WINDOW,
			freshnessWindowMs: WINDOW,
		});
		expect(now).toHaveLength(1);
		expect(now[0]?.staleness).toBe("fresh");

		const later = exposureEdgesTouching(graph, {
			nodeId: nodeId("agent", "agent-install-1"),
			kind: "runs_on",
			nowMs: BASE + WINDOW + 1,
			freshnessWindowMs: WINDOW,
		});
		expect(later[0]?.staleness).toBe("stale");

		const unrelated = exposureEdgesTouching(graph, {
			nodeId: nodeId("agent", "agent-install-1"),
			kind: "authorizes",
			nowMs: BASE,
			freshnessWindowMs: WINDOW,
		});
		expect(unrelated).toEqual([]);
	});
});

describe("exposure coverage gaps", () => {
	it("reports expected kinds with no node as data, not as an empty finding list", () => {
		const graph = graphOf([baseObservation()]);
		const coverage = exposureCoverage(graph);
		expect(coverage.observedKinds).toEqual(["agent", "host", "user"]);
		expect(coverage.unobservedKinds).toEqual(["mcp_server", "tool", "credential", "data_source"]);
		expect(coverage.nodeCountsByKind.mcp_server).toBe(0);
		expect(coverage.scope).toContain("coverage gap");
	});

	it("reports an unreadable source and keeps a missing source out of the gaps", () => {
		const graph = graphOf([baseObservation()]);
		const sources: ExposureSourceStatus[] = [
			{ sourceRef: "~/.cursor/mcp.json", source: "mcp_inventory", status: "read" },
			{ sourceRef: "~/.claude.json", source: "mcp_inventory", status: "missing" },
			{
				sourceRef: "https://idp.example.test/",
				source: "idp",
				status: "unreadable",
				detail: "EACCES",
			},
		];
		const coverage = exposureCoverage(graph, sources);
		expect(coverage.unreadableSources).toEqual([
			{ sourceRef: "https://idp.example.test/", source: "idp", detail: "EACCES" },
		]);
		expect(coverage.unreadableSources.some((source) => source.source === "mcp_inventory")).toBe(false);
	});

	it("leaves a fully covered graph with no gaps", () => {
		const nodes = EXPOSURE_NODE_KINDS.map((kind) => ({ kind, naturalKey: `k-${kind}` }));
		const result = foldExposureObservations(
			[baseObservation({ nodes, edges: [] })],
			{ ...hash, tenantId: TENANT },
		);
		expect(result.coverage.unobservedKinds).toEqual([]);
		expect(result.coverage.unreadableSources).toEqual([]);
	});

	it("narrows the gap list when the caller declares which kinds it covers", () => {
		const result = foldExposureObservations([baseObservation()], {
			...hash,
			tenantId: TENANT,
			expectedKinds: ["agent", "host", "user"],
		});
		expect(result.coverage.unobservedKinds).toEqual([]);
		expect(result.graph.expectedKinds).toEqual(["agent", "host", "user"]);
	});
});

describe("exposure observation digest", () => {
	it("is stable for equal content and changes when the observation changes", () => {
		const record = baseObservation();
		expect(exposureObservationDigest(record, hash)).toBe(exposureObservationDigest({ ...record }, hash));
		expect(exposureObservationDigest(record, hash)).not.toBe(
			exposureObservationDigest({ ...record, observedAtMs: BASE + 1 }, hash),
		);
		expect(exposureObservationDigest(record, hash)).toMatch(/^[0-9a-f]{64}$/);
	});
});
