/**
 * Tenant-scoped AI exposure graph (MKT-01).
 *
 * Discovery already produces per-source records (MCP inventory/discovery, the
 * AIG fleet inventory, runtime verdicts), but each record was only meaningful in
 * the report that produced it: the same host seen from two collectors was two
 * rows, and a source that stopped reporting simply vanished. This module gives
 * every agent, host, user, MCP server, tool, credential and data source a
 * persistent opaque identity and folds observations into one graph per tenant.
 *
 * The invariants are the point:
 *
 *   - **Tenant boundary first.** A record carrying another tenant's id is
 *     refused with `cross_tenant_record` and never merged. A graph that only
 *     ever holds one tenant's records is the only cheap isolation proof this
 *     layer can offer, and pretending otherwise would be worse than refusing.
 *   - **Order-independent and idempotent.** Folding the same observation twice
 *     is a no-op; folding a permuted batch produces the same graph, so two
 *     collectors relaying the same inventory cannot inflate it.
 *   - **Staleness is explicit.** Freshness is computed from an injected clock
 *     and a caller-supplied window. Nothing here reads `Date.now()`: a caller
 *     that cannot supply a clock gets `unknown`, never a silent "fresh".
 *   - **No evidence is absence.** Unobserved node kinds and sources that could
 *     not be read are reported as data. "We saw nothing" and "we could not
 *     look" are different results and must never collapse into a clean graph.
 *
 * Nothing here performs I/O. The caller reads the sources and passes records in.
 */

import { createHash } from "node:crypto";

export const EXPOSURE_GRAPH_SCHEMA_VERSION = 1;

/** Node kinds the graph gives a persistent identity to. */
export const EXPOSURE_NODE_KINDS = [
	"agent",
	"host",
	"user",
	"mcp_server",
	"tool",
	"credential",
	"data_source",
] as const;
export type ExposureNodeKind = (typeof EXPOSURE_NODE_KINDS)[number];

/** How an observation reached the product. Never a trust assertion by itself. */
export type ExposureObservationSource =
	| "mcp_inventory"
	| "mcp_discovery"
	| "fleet_inventory"
	| "runtime_verdict"
	| "operator"
	| "idp"
	| "cloud"
	| "mdm";

export type ExposureEdgeKind = "authorizes" | "runs_on" | "uses" | "can_reach" | "last_seen_at";

export type ExposureStaleness = "fresh" | "stale" | "unknown";

export interface ExposureNode {
	/** Opaque, stable id derived from (kind, natural key). Never a raw identifier. */
	nodeId: string;
	kind: ExposureNodeKind;
	/** Tenant-scoped canonical key the id was derived from. */
	naturalKey: string;
	label: string;
	firstSeenAtMs: number;
	lastSeenAtMs: number | null;
	observationIds: string[];
	metadata: Record<string, string>;
}

export interface ExposureEdge {
	edgeId: string;
	kind: ExposureEdgeKind;
	fromNodeId: string;
	toNodeId: string;
	firstSeenAtMs: number;
	lastSeenAtMs: number | null;
	observationIds: string[];
}

export interface ExposureGraph {
	schemaVersion: typeof EXPOSURE_GRAPH_SCHEMA_VERSION;
	tenantId: string;
	/** Node kinds this tenant's coverage claims to include. */
	expectedKinds: ExposureNodeKind[];
	nodes: ExposureNode[];
	edges: ExposureEdge[];
}

export interface ExposureObservationNode {
	kind: ExposureNodeKind;
	/** Canonical, tenant-scoped natural key (installation id, origin, subject…). */
	naturalKey: string;
	label?: string;
	metadata?: Record<string, string>;
}

export interface ExposureObservationEdge {
	kind: ExposureEdgeKind;
	fromNodeId: string;
	toNodeId: string;
}

export interface ExposureObservationInput {
	tenantId: string;
	observationId: string;
	source: ExposureObservationSource;
	sourceRef: string;
	observedAtMs: number;
	/** A `false` value records the attempt without advancing the last-seen edge. */
	observed?: boolean;
	nodes: ExposureObservationNode[];
	edges?: ExposureObservationEdge[];
}

/**
 * Status of a collection source. `missing` means the source was not present (a
 * normal, uninteresting state); `unreadable` means it exists but could not be
 * read or parsed, which is a coverage gap and is always reported.
 */
export interface ExposureSourceStatus {
	sourceRef: string;
	source: ExposureObservationSource;
	status: "read" | "missing" | "unreadable";
	detail?: string;
}

export interface ExposureUnreadableSource {
	sourceRef: string;
	source: ExposureObservationSource;
	detail: string;
}

export type ExposureObservationRejectionCode =
	| "cross_tenant_record"
	| "invalid_record"
	| "conflicting_observation"
	| "dangling_edge";

export interface ExposureObservationRejection {
	observationId: string;
	tenantId: string;
	sourceRef: string;
	code: ExposureObservationRejectionCode;
	detail: string;
}

export interface ExposureCoverageReport {
	expectedKinds: ExposureNodeKind[];
	observedKinds: ExposureNodeKind[];
	/** Expected kinds with no node in the graph. */
	unobservedKinds: ExposureNodeKind[];
	/** Requested sources that exist but could not be read or parsed. */
	unreadableSources: ExposureUnreadableSource[];
	nodeCountsByKind: Record<ExposureNodeKind, number>;
	scope?: string;
}

export interface FoldExposureGraphResult {
	graph: ExposureGraph;
	/** Observation ids merged into the graph (the first occurrence of each). */
	accepted: string[];
	/** Observation ids that were already present and changed nothing. */
	duplicates: string[];
	rejections: ExposureObservationRejection[];
	coverage: ExposureCoverageReport;
}

export interface HasherContext {
	hash: (value: string) => string;
}

/** SHA-256 context for callers that do not already have one. */
export function createSha256HasherContext(): HasherContext {
	return { hash: (value: string) => createHash("sha256").update(value).digest("hex") };
}

export type ExposureGraphOptions = HasherContext & {
	/** Tenant the graph is being built for. Set on the first fold. */
	tenantId?: string;
	/**
	 * Kinds this tenant's coverage claims to include. Defaults to every kind; an
	 * unobserved expected kind is then reported rather than assumed absent.
	 */
	expectedKinds?: readonly ExposureNodeKind[];
	previous?: ExposureGraph | null;
};

export type ExposureParseResult<T> = { ok: true; value: T } | { ok: false; error: string };

function accept<T>(value: T): ExposureParseResult<T> {
	return { ok: true, value };
}

function fail<T>(error: string): ExposureParseResult<T> {
	return { ok: false, error };
}

const NODE_ID = /^xnode_[0-9a-f]{64}$/;
const EDGE_ID = /^xedge_[0-9a-f]{64}$/;
const NATURAL_KEY = /^[^\u0000-\u001f\u007f]{1,400}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;
const KIND_SET = new Set<string>(EXPOSURE_NODE_KINDS);
const EDGE_KIND_SET = new Set<string>([
	"authorizes",
	"runs_on",
	"uses",
	"can_reach",
	"last_seen_at",
]);
const SOURCE_SET = new Set<string>([
	"mcp_inventory",
	"mcp_discovery",
	"fleet_inventory",
	"runtime_verdict",
	"operator",
	"idp",
	"cloud",
	"mdm",
]);

/**
 * Canonical digest input for a node identity. Fixed field order, explicit
 * separators, and no wall clock: the same source record must always produce the
 * same id on every host and every run.
 */
function nodeDigestInput(tenantId: string, kind: ExposureNodeKind, naturalKey: string): string {
	return ["aidr.exposure.node.v1", tenantId, kind, naturalKey].join("\n");
}

function edgeDigestInput(
	tenantId: string,
	kind: ExposureEdgeKind,
	fromNodeId: string,
	toNodeId: string,
): string {
	return ["aidr.exposure.edge.v1", tenantId, kind, fromNodeId, toNodeId].join("\n");
}

/** Stable opaque identity for a node. The raw natural key never leaves the caller's tenant scope. */
export function exposureNodeId(
	tenantId: string,
	kind: ExposureNodeKind,
	naturalKey: string,
	context: HasherContext,
): string {
	if (!IDENTIFIER.test(tenantId)) throw new Error("exposure_tenant_id_invalid");
	if (!KIND_SET.has(kind)) throw new Error("exposure_kind_invalid");
	if (!NATURAL_KEY.test(naturalKey)) throw new Error("exposure_natural_key_invalid");
	return `xnode_${context.hash(nodeDigestInput(tenantId, kind, naturalKey))}`;
}

/** Stable opaque identity for a typed edge. */
export function exposureEdgeId(
	tenantId: string,
	kind: ExposureEdgeKind,
	fromNodeId: string,
	toNodeId: string,
	context: HasherContext,
): string {
	if (!IDENTIFIER.test(tenantId)) throw new Error("exposure_tenant_id_invalid");
	if (!EDGE_KIND_SET.has(kind)) throw new Error("exposure_edge_kind_invalid");
	if (!NODE_ID.test(fromNodeId) || !NODE_ID.test(toNodeId)) {
		throw new Error("exposure_edge_endpoint_invalid");
	}
	return `xedge_${context.hash(edgeDigestInput(tenantId, kind, fromNodeId, toNodeId))}`;
}

function observationDigestInput(record: {
	tenantId: string;
	observationId: string;
	source: ExposureObservationSource;
	sourceRef: string;
	observedAtMs: number;
	observed: boolean;
	nodes: ExposureObservationNode[];
	edges: ExposureObservationEdge[];
}): string {
	const nodes = [...record.nodes]
		.map((node) => [
			node.kind,
			node.naturalKey,
			node.label ?? "",
			JSON.stringify(node.metadata ?? {}),
		])
		.sort((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));
	const edges = [...record.edges]
		.map((edge) => [edge.kind, edge.fromNodeId, edge.toNodeId])
		.sort((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));
	return [
		"aidr.exposure.observation.v1",
		record.tenantId,
		record.observationId,
		record.source,
		record.sourceRef,
		String(record.observedAtMs),
		String(record.observed),
		JSON.stringify(nodes),
		JSON.stringify(edges),
	].join("\n");
}

/** Content digest of a normalized observation, used to tell a replay from a conflict. */
export function exposureObservationDigest(
	record: ExposureObservationInput,
	context: HasherContext,
): string {
	return context.hash(
		observationDigestInput({
			tenantId: record.tenantId,
			observationId: record.observationId,
			source: record.source,
			sourceRef: record.sourceRef,
			observedAtMs: record.observedAtMs,
			observed: record.observed !== false,
			nodes: record.nodes,
			edges: record.edges ?? [],
		}),
	);
}

interface NormalizedObservation {
	tenantId: string;
	observationId: string;
	source: ExposureObservationSource;
	sourceRef: string;
	observedAtMs: number;
	observed: boolean;
	nodes: ExposureObservationNode[];
	edges: ExposureObservationEdge[];
	digest: string;
}

function parseObservationNode(value: unknown): ExposureParseResult<ExposureObservationNode> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return fail("invalid_node");
	const node = value as Record<string, unknown>;
	if (typeof node.kind !== "string" || !KIND_SET.has(node.kind)) return fail("invalid_node_kind");
	if (typeof node.naturalKey !== "string" || !NATURAL_KEY.test(node.naturalKey)) {
		return fail("invalid_node_natural_key");
	}
	if (node.label !== undefined && (typeof node.label !== "string" || node.label.length > 200)) {
		return fail("invalid_node_label");
	}
	if (node.metadata === undefined) {
		return accept({
			kind: node.kind as ExposureNodeKind,
			naturalKey: node.naturalKey,
			...(node.label === undefined ? {} : { label: node.label as string }),
		});
	}
	if (!node.metadata || typeof node.metadata !== "object" || Array.isArray(node.metadata)) {
		return fail("invalid_node_metadata");
	}
	const metadata: Record<string, string> = {};
	for (const [key, entry] of Object.entries(node.metadata as Record<string, unknown>)) {
		if (typeof entry !== "string" || entry.length > 200 || key.length > 64) {
			return fail("invalid_node_metadata");
		}
		metadata[key] = entry;
	}
	return accept({
		kind: node.kind as ExposureNodeKind,
		naturalKey: node.naturalKey,
		...(node.label === undefined ? {} : { label: node.label as string }),
		metadata,
	});
}

function parseObservationEdge(value: unknown): ExposureParseResult<ExposureObservationEdge> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return fail("invalid_edge");
	const edge = value as Record<string, unknown>;
	if (typeof edge.kind !== "string" || !EDGE_KIND_SET.has(edge.kind))
		return fail("invalid_edge_kind");
	if (typeof edge.fromNodeId !== "string" || !NODE_ID.test(edge.fromNodeId)) {
		return fail("invalid_edge_from");
	}
	if (typeof edge.toNodeId !== "string" || !NODE_ID.test(edge.toNodeId))
		return fail("invalid_edge_to");
	if (edge.fromNodeId === edge.toNodeId) return fail("self_edge");
	return accept({
		kind: edge.kind as ExposureEdgeKind,
		fromNodeId: edge.fromNodeId,
		toNodeId: edge.toNodeId,
	});
}

function parseObservationNodes(value: unknown[]): ExposureParseResult<ExposureObservationNode[]> {
	if (value.length === 0) return fail("invalid_nodes");
	const nodes: ExposureObservationNode[] = [];
	const seen = new Set<string>();
	for (const entry of value) {
		const parsed = parseObservationNode(entry);
		if (!parsed.ok) return fail(parsed.error);
		const dedupeKey = `${parsed.value.kind}\0${parsed.value.naturalKey}`;
		if (seen.has(dedupeKey)) continue;
		seen.add(dedupeKey);
		nodes.push(parsed.value);
	}
	return nodes.length === 0 ? fail("invalid_nodes") : accept(nodes);
}

function parseObservationEdges(value: unknown[]): ExposureParseResult<ExposureObservationEdge[]> {
	const edges: ExposureObservationEdge[] = [];
	const seen = new Set<string>();
	for (const entry of value) {
		const parsed = parseObservationEdge(entry);
		if (!parsed.ok) return fail(parsed.error);
		const edge = parsed.value;
		const dedupeKey = `${edge.kind}\0${edge.fromNodeId}\0${edge.toNodeId}`;
		if (seen.has(dedupeKey)) continue;
		seen.add(dedupeKey);
		edges.push(edge);
	}
	return accept(edges);
}

function parseObservation(
	value: unknown,
	context: HasherContext,
): ExposureParseResult<NormalizedObservation> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return fail("not_an_object");
	const raw = value as Record<string, unknown>;
	if (typeof raw.tenantId !== "string" || !IDENTIFIER.test(raw.tenantId))
		return fail("invalid_tenant_id");
	if (typeof raw.observationId !== "string" || !IDENTIFIER.test(raw.observationId)) {
		return fail("invalid_observation_id");
	}
	if (typeof raw.source !== "string" || !SOURCE_SET.has(raw.source)) return fail("invalid_source");
	if (typeof raw.sourceRef !== "string" || !NATURAL_KEY.test(raw.sourceRef))
		return fail("invalid_source_ref");
	if (!Number.isSafeInteger(raw.observedAtMs) || (raw.observedAtMs as number) < 0) {
		return fail("invalid_observed_at");
	}
	if (raw.observed !== undefined && typeof raw.observed !== "boolean")
		return fail("invalid_observed");
	if (!Array.isArray(raw.nodes)) return fail("invalid_nodes");
	if (raw.edges !== undefined && !Array.isArray(raw.edges)) return fail("invalid_edges");

	const nodes = parseObservationNodes(raw.nodes);
	if (!nodes.ok) return fail(nodes.error);
	const edges = parseObservationEdges(raw.edges ?? []);
	if (!edges.ok) return fail(edges.error);

	const normalized: NormalizedObservation = {
		tenantId: raw.tenantId,
		observationId: raw.observationId,
		source: raw.source as ExposureObservationSource,
		sourceRef: raw.sourceRef,
		observedAtMs: raw.observedAtMs as number,
		observed: raw.observed !== false,
		nodes: nodes.value,
		edges: edges.value,
		digest: "",
	};
	normalized.digest = exposureObservationDigest(normalized, context);
	return accept(normalized);
}

function emptyKindCounts(): Record<ExposureNodeKind, number> {
	const counts = {} as Record<ExposureNodeKind, number>;
	for (const kind of EXPOSURE_NODE_KINDS) counts[kind] = 0;
	return counts;
}

function validatePreviousGraph(previous: ExposureGraph | null | undefined): ExposureGraph | null {
	if (!previous) return null;
	if (previous.schemaVersion !== EXPOSURE_GRAPH_SCHEMA_VERSION) {
		throw new Error("exposure_graph_schema_mismatch");
	}
	if (!IDENTIFIER.test(previous.tenantId)) throw new Error("exposure_graph_tenant_invalid");
	if (!Array.isArray(previous.nodes) || !Array.isArray(previous.edges)) {
		throw new Error("exposure_graph_invalid");
	}
	return previous;
}

function normalizeExpectedKinds(
	kinds: readonly ExposureNodeKind[] | undefined,
	previous: ExposureGraph | null,
): ExposureNodeKind[] {
	const source = kinds ?? previous?.expectedKinds ?? EXPOSURE_NODE_KINDS;
	const seen = new Set<ExposureNodeKind>();
	for (const kind of source) {
		if (!KIND_SET.has(kind)) throw new Error("exposure_expected_kind_invalid");
		seen.add(kind);
	}
	return [...seen].sort();
}

function sortNodes(nodes: ExposureNode[]): ExposureNode[] {
	return [...nodes].sort((a, b) => (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0));
}

function sortEdges(edges: ExposureEdge[]): ExposureEdge[] {
	return [...edges].sort((a, b) => (a.edgeId < b.edgeId ? -1 : a.edgeId > b.edgeId ? 1 : 0));
}

interface NodeObservation {
	observationId: string;
	source: ExposureObservationSource;
	observedAtMs: number;
	observed: boolean;
	label?: string;
	metadata?: Record<string, string>;
}

function observationRank(a: NodeObservation, b: NodeObservation): number {
	if (a.observedAtMs !== b.observedAtMs) return b.observedAtMs - a.observedAtMs;
	return a.observationId < b.observationId ? -1 : a.observationId > b.observationId ? 1 : 0;
}

/** Mutable fold state, threaded through the helpers below. */
interface ExposureFoldState {
	nodes: Map<string, ExposureNode>;
	nodeObservations: Map<string, NodeObservation[]>;
	edges: Map<string, ExposureEdge>;
	digestByObservationId: Map<string, string>;
	nodeIdSet: Set<string>;
	edgeProvenance: Map<string, { observationId: string; tenantId: string; sourceRef: string }>;
	rejections: ExposureObservationRejection[];
	accepted: string[];
	duplicates: string[];
	effectiveTenantId: string | undefined;
}

function addObservationId(current: string[], observationId: string): string[] {
	if (current.includes(observationId)) return current;
	return [...current, observationId].sort();
}

function createFoldState(previous: ExposureGraph | null): ExposureFoldState {
	const state: ExposureFoldState = {
		nodes: new Map(),
		nodeObservations: new Map(),
		edges: new Map(),
		digestByObservationId: new Map(),
		nodeIdSet: new Set(),
		edgeProvenance: new Map(),
		rejections: [],
		accepted: [],
		duplicates: [],
		effectiveTenantId: previous?.tenantId,
	};
	for (const node of previous?.nodes ?? []) {
		if (!NODE_ID.test(node.nodeId)) throw new Error("exposure_graph_node_invalid");
		state.nodes.set(node.nodeId, { ...node, observationIds: [...node.observationIds] });
		state.nodeIdSet.add(node.nodeId);
	}
	for (const edge of previous?.edges ?? []) {
		if (!EDGE_ID.test(edge.edgeId)) throw new Error("exposure_graph_edge_invalid");
		state.edges.set(edge.edgeId, { ...edge, observationIds: [...edge.observationIds] });
	}
	return state;
}

/** Merge one node observation. Returns false when a record rewrote its identity. */
function mergeNodeObservation(
	state: ExposureFoldState,
	nodeId: string,
	observation: NodeObservation,
	kind: ExposureNodeKind,
	naturalKey: string,
): boolean {
	const existing = state.nodes.get(nodeId);
	if (existing && (existing.kind !== kind || existing.naturalKey !== naturalKey)) {
		// A different source record claiming an existing opaque id means the
		// caller rewrote the identity behind the digest. Refuse it.
		return false;
	}
	const list = state.nodeObservations.get(nodeId) ?? [];
	list.push(observation);
	state.nodeObservations.set(nodeId, list);

	const observedAt = observation.observed ? observation.observedAtMs : null;
	const next: ExposureNode = existing ?? {
		nodeId,
		kind,
		naturalKey,
		label: naturalKey,
		firstSeenAtMs: observation.observedAtMs,
		lastSeenAtMs: observedAt,
		observationIds: [],
		metadata: {},
	};
	next.firstSeenAtMs = Math.min(next.firstSeenAtMs, observation.observedAtMs);
	if (observedAt !== null) {
		next.lastSeenAtMs =
			next.lastSeenAtMs === null ? observedAt : Math.max(next.lastSeenAtMs, observedAt);
	}
	next.observationIds = addObservationId(next.observationIds, observation.observationId);
	state.nodes.set(nodeId, next);
	state.nodeIdSet.add(nodeId);
	return true;
}

function mergeObservationNodes(
	state: ExposureFoldState,
	observation: NormalizedObservation,
	options: ExposureGraphOptions,
): void {
	for (const node of observation.nodes) {
		const nodeId = exposureNodeId(observation.tenantId, node.kind, node.naturalKey, options);
		const merged = mergeNodeObservation(
			state,
			nodeId,
			{
				observationId: observation.observationId,
				source: observation.source,
				observedAtMs: observation.observedAtMs,
				observed: observation.observed,
				...(node.label === undefined ? {} : { label: node.label }),
				...(node.metadata === undefined ? {} : { metadata: node.metadata }),
			},
			node.kind,
			node.naturalKey,
		);
		if (!merged) {
			state.rejections.push({
				observationId: observation.observationId,
				tenantId: observation.tenantId,
				sourceRef: observation.sourceRef,
				code: "conflicting_observation",
				detail: `node_identity_conflict:${nodeId}`,
			});
		}
	}
}

/**
 * Merge an observation's edges without validating endpoints yet.
 *
 * Validating during the pass would make the result depend on arrival order: an
 * edge whose nodes arrive in a later record is not dangling, only early.
 */
function mergeObservationEdges(
	state: ExposureFoldState,
	observation: NormalizedObservation,
	options: ExposureGraphOptions,
): void {
	for (const edge of observation.edges) {
		const edgeId = exposureEdgeId(
			observation.tenantId,
			edge.kind,
			edge.fromNodeId,
			edge.toNodeId,
			options,
		);
		const existing = state.edges.get(edgeId);
		const observedAt = observation.observed ? observation.observedAtMs : null;
		const next: ExposureEdge = existing ?? {
			edgeId,
			kind: edge.kind,
			fromNodeId: edge.fromNodeId,
			toNodeId: edge.toNodeId,
			firstSeenAtMs: observation.observedAtMs,
			lastSeenAtMs: observedAt,
			observationIds: [],
		};
		next.firstSeenAtMs = Math.min(next.firstSeenAtMs, observation.observedAtMs);
		if (observedAt !== null) {
			next.lastSeenAtMs =
				next.lastSeenAtMs === null ? observedAt : Math.max(next.lastSeenAtMs, observedAt);
		}
		next.observationIds = addObservationId(next.observationIds, observation.observationId);
		state.edges.set(edgeId, next);
		if (!state.edgeProvenance.has(edgeId)) {
			state.edgeProvenance.set(edgeId, {
				observationId: observation.observationId,
				tenantId: observation.tenantId,
				sourceRef: observation.sourceRef,
			});
		}
	}
}

/** Record an `invalid_record` rejection with whatever the raw record exposed. */
function rejectUnreadableRecord(state: ExposureFoldState, record: unknown, detail: string): void {
	const raw =
		record && typeof record === "object" && !Array.isArray(record)
			? (record as Record<string, unknown>)
			: {};
	state.rejections.push({
		observationId: typeof raw.observationId === "string" ? raw.observationId : "unknown",
		tenantId: typeof raw.tenantId === "string" ? raw.tenantId : "",
		sourceRef: typeof raw.sourceRef === "string" ? raw.sourceRef : "",
		code: "invalid_record",
		detail,
	});
}

/** Merge one observation, refusing cross-tenant, replayed and missing records. */
function foldOneObservation(
	state: ExposureFoldState,
	observation: NormalizedObservation,
	options: ExposureGraphOptions,
): void {
	// Cross-tenant records are refused before anything can be merged. The first
	// well-formed record establishes the graph's tenant.
	if (state.effectiveTenantId === undefined) {
		state.effectiveTenantId = observation.tenantId;
	} else if (observation.tenantId !== state.effectiveTenantId) {
		state.rejections.push({
			observationId: observation.observationId,
			tenantId: observation.tenantId,
			sourceRef: observation.sourceRef,
			code: "cross_tenant_record",
			detail: `graph_tenant:${state.effectiveTenantId}`,
		});
		return;
	}

	const seenDigest = state.digestByObservationId.get(observation.observationId);
	if (seenDigest !== undefined) {
		if (seenDigest === observation.digest) {
			state.duplicates.push(observation.observationId);
		} else {
			state.rejections.push({
				observationId: observation.observationId,
				tenantId: observation.tenantId,
				sourceRef: observation.sourceRef,
				code: "conflicting_observation",
				detail: "observation_id_reused_with_different_content",
			});
		}
		return;
	}
	state.digestByObservationId.set(observation.observationId, observation.digest);

	mergeObservationNodes(state, observation, options);
	mergeObservationEdges(state, observation, options);
	state.accepted.push(observation.observationId);
}

/**
 * Drop edges whose endpoints never appeared, reporting each as a dangling edge.
 * A phantom node is never materialized to make an edge valid.
 */
function pruneDanglingEdges(state: ExposureFoldState): void {
	for (const [edgeId, edge] of [...state.edges]) {
		if (state.nodeIdSet.has(edge.fromNodeId) && state.nodeIdSet.has(edge.toNodeId)) continue;
		state.edges.delete(edgeId);
		const provenance = state.edgeProvenance.get(edgeId);
		state.rejections.push({
			observationId: provenance?.observationId ?? "unknown",
			tenantId: provenance?.tenantId ?? state.effectiveTenantId ?? "",
			sourceRef: provenance?.sourceRef ?? "",
			code: "dangling_edge",
			detail: `${edge.kind}:${edge.fromNodeId}->${edge.toNodeId}`,
		});
	}
}

/**
 * Resolve descriptive fields from the ranked observations last, so arrival order
 * cannot decide which label or metadata a node ends up with.
 */
function resolveNodeDescriptions(state: ExposureFoldState): void {
	for (const [nodeId, observations] of state.nodeObservations) {
		const node = state.nodes.get(nodeId);
		if (!node) continue;
		const ranked = [...observations].sort(observationRank);
		const best = ranked[0];
		if (!best) continue;
		node.label = best.label ?? node.naturalKey;
		const metadata: Record<string, string> = {};
		for (const entry of [...ranked].reverse()) Object.assign(metadata, entry.metadata ?? {});
		node.metadata = metadata;
	}
}

function sortRejections(
	rejections: readonly ExposureObservationRejection[],
): ExposureObservationRejection[] {
	return [...rejections].sort((a, b) => {
		if (a.observationId !== b.observationId) return a.observationId < b.observationId ? -1 : 1;
		return a.code < b.code ? -1 : a.code > b.code ? 1 : 0;
	});
}

/**
 * Fold a batch of inventory/observation records into one tenant graph.
 *
 * The result is identical for any permutation of `records` and for any number of
 * exact replays: node and edge `lastSeenAtMs` are maxima, `firstSeenAtMs` are
 * minima, and descriptive metadata is resolved by a deterministic ranking that
 * does not depend on arrival order. A record from another tenant, an unreadable
 * record, a replay whose content changed, and an edge whose endpoints are not in
 * the graph are each refused with a code instead of being merged.
 */
export function foldExposureObservations(
	records: readonly unknown[],
	options: ExposureGraphOptions,
): FoldExposureGraphResult {
	const previous = validatePreviousGraph(options.previous);
	const expectedKinds = normalizeExpectedKinds(options.expectedKinds, previous);
	if (options.tenantId !== undefined && !IDENTIFIER.test(options.tenantId)) {
		throw new Error("exposure_tenant_id_invalid");
	}
	const tenantId = options.tenantId ?? previous?.tenantId;
	if (tenantId !== undefined && previous && previous.tenantId !== tenantId) {
		throw new Error("exposure_graph_tenant_mismatch");
	}

	const state = createFoldState(previous);
	for (const record of records) {
		const parsed = parseObservation(record, options);
		if (!parsed.ok) {
			rejectUnreadableRecord(state, record, parsed.error);
			continue;
		}
		foldOneObservation(state, parsed.value, options);
	}
	pruneDanglingEdges(state);
	resolveNodeDescriptions(state);

	const graph: ExposureGraph = {
		schemaVersion: EXPOSURE_GRAPH_SCHEMA_VERSION,
		tenantId: state.effectiveTenantId ?? "",
		expectedKinds,
		nodes: sortNodes([...state.nodes.values()]),
		edges: sortEdges([...state.edges.values()]),
	};

	return {
		graph,
		// Sorted, because the result of a fold must not depend on arrival order.
		accepted: [...state.accepted].sort(),
		duplicates: [...state.duplicates].sort(),
		rejections: sortRejections(state.rejections),
		coverage: exposureCoverage(graph, []),
	};
}

/**
 * Coverage as data. Missing kinds and unreadable sources are returned, never
 * implied by an empty finding list.
 */
export function exposureCoverage(
	graph: ExposureGraph,
	sources: readonly ExposureSourceStatus[] = [],
): ExposureCoverageReport {
	const nodeCountsByKind = emptyKindCounts();
	for (const node of graph.nodes) nodeCountsByKind[node.kind] += 1;
	const observedKinds = EXPOSURE_NODE_KINDS.filter((kind) => nodeCountsByKind[kind] > 0);
	const expected = graph.expectedKinds.length > 0 ? graph.expectedKinds : [...EXPOSURE_NODE_KINDS];
	const unobservedKinds = EXPOSURE_NODE_KINDS.filter(
		(kind) => expected.includes(kind) && nodeCountsByKind[kind] === 0,
	);
	const unreadableSources: ExposureUnreadableSource[] = sources
		.filter((source) => source.status === "unreadable")
		.map((source) => ({
			sourceRef: source.sourceRef,
			source: source.source,
			detail: source.detail ?? "source_unreadable",
		}))
		.sort((a, b) =>
			a.sourceRef === b.sourceRef
				? a.source < b.source
					? -1
					: 1
				: a.sourceRef < b.sourceRef
					? -1
					: 1,
		);
	return {
		expectedKinds: expected,
		observedKinds,
		unobservedKinds,
		unreadableSources,
		nodeCountsByKind,
		scope:
			"Locally reported observations only; absence of a kind is a coverage gap, not evidence the kind is unused",
	};
}

/**
 * Staleness of one last-seen edge.
 *
 * `window` is inclusive: an entry exactly `freshnessWindowMs` old is still
 * fresh. A missing or non-finite timestamp is `unknown`, never `fresh`; a
 * timestamp in the future relative to the injected clock is also `unknown`,
 * because a clock that has not happened yet is not evidence of currency.
 */
export function exposureStaleness(
	lastSeenAtMs: number | null | undefined,
	nowMs: number,
	freshnessWindowMs: number,
): ExposureStaleness {
	if (lastSeenAtMs === null || lastSeenAtMs === undefined) return "unknown";
	if (!Number.isFinite(lastSeenAtMs) || !Number.isFinite(nowMs)) return "unknown";
	if (!Number.isFinite(freshnessWindowMs) || freshnessWindowMs < 0) return "unknown";
	if (lastSeenAtMs > nowMs) return "unknown";
	return nowMs - lastSeenAtMs <= freshnessWindowMs ? "fresh" : "stale";
}

export interface ExposureStalenessEntry {
	nodeId: string;
	kind: ExposureNodeKind;
	lastSeenAtMs: number | null;
	staleness: ExposureStaleness;
}

export interface ExposureStalenessReport {
	nowMs: number;
	freshnessWindowMs: number;
	entries: ExposureStalenessEntry[];
	fresh: number;
	stale: number;
	unknown: number;
	/**
	 * True when at least one source that should be reporting is not current.
	 * A graph is never reported as "current" while anything in it is stale.
	 */
	hasStaleOrUnknown: boolean;
}

/**
 * Freshness of every node, from an injected clock and a caller-supplied window.
 * Nothing in this module reads the host clock, so a stale collector cannot be
 * rendered as current by a caller that forgot to pass the time.
 */
export function exposureStalenessReport(
	graph: ExposureGraph,
	nowMs: number,
	freshnessWindowMs: number,
): ExposureStalenessReport {
	const entries: ExposureStalenessEntry[] = graph.nodes.map((node) => ({
		nodeId: node.nodeId,
		kind: node.kind,
		lastSeenAtMs: node.lastSeenAtMs,
		staleness: exposureStaleness(node.lastSeenAtMs, nowMs, freshnessWindowMs),
	}));
	let fresh = 0;
	let stale = 0;
	let unknown = 0;
	for (const entry of entries) {
		if (entry.staleness === "fresh") fresh += 1;
		else if (entry.staleness === "stale") stale += 1;
		else unknown += 1;
	}
	return {
		nowMs,
		freshnessWindowMs,
		entries,
		fresh,
		stale,
		unknown,
		hasStaleOrUnknown: stale > 0 || unknown > 0,
	};
}

export interface ExposureAuthorizationQuery {
	nodeId: string;
	kind: ExposureEdgeKind;
	nowMs: number;
	freshnessWindowMs: number;
}

/**
 * Edges of one kind touching a node, each carrying its own explicit staleness.
 *
 * This is the view an analyst reads to answer "what can this agent reach, and is
 * that view current?" — so the clock and window are required, not defaulted, and
 * an unreported edge is `unknown` rather than assumed live.
 */
export function exposureEdgesTouching(
	graph: ExposureGraph,
	query: ExposureAuthorizationQuery,
): Array<ExposureEdge & { staleness: ExposureStaleness }> {
	return graph.edges
		.filter(
			(edge) =>
				edge.kind === query.kind &&
				(edge.fromNodeId === query.nodeId || edge.toNodeId === query.nodeId),
		)
		.sort((a, b) => (a.edgeId < b.edgeId ? -1 : a.edgeId > b.edgeId ? 1 : 0))
		.map((edge) => ({
			...edge,
			staleness: exposureStaleness(edge.lastSeenAtMs, query.nowMs, query.freshnessWindowMs),
		}));
}

/** Canonical, key-sorted JSON for a graph, so two equal folds serialize identically. */
export function canonicalExposureGraphJson(graph: ExposureGraph): string {
	return JSON.stringify({
		schemaVersion: graph.schemaVersion,
		tenantId: graph.tenantId,
		expectedKinds: [...graph.expectedKinds].sort(),
		nodes: sortNodes(graph.nodes).map((node) => ({
			nodeId: node.nodeId,
			kind: node.kind,
			naturalKey: node.naturalKey,
			label: node.label,
			firstSeenAtMs: node.firstSeenAtMs,
			lastSeenAtMs: node.lastSeenAtMs,
			observationIds: [...node.observationIds].sort(),
			metadata: Object.fromEntries(
				Object.entries(node.metadata).sort(([a], [b]) => (a < b ? -1 : 1)),
			),
		})),
		edges: sortEdges(graph.edges).map((edge) => ({
			edgeId: edge.edgeId,
			kind: edge.kind,
			fromNodeId: edge.fromNodeId,
			toNodeId: edge.toNodeId,
			firstSeenAtMs: edge.firstSeenAtMs,
			lastSeenAtMs: edge.lastSeenAtMs,
			observationIds: [...edge.observationIds].sort(),
		})),
	});
}
