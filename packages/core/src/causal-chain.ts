/**
 * Causal agent chain (MKT-02).
 *
 * The incident correlator groups normalized signals into an endpoint-scoped
 * incident, and `incidents/evidence-receipt.ts` binds a decision to the build,
 * policy, device, actor and incident that produced it. What was missing is the
 * ordered causal path across an agent's turn:
 *
 *   message -> retrieval -> tool description/response -> authorization ->
 *   action -> side effect -> intervention
 *
 * This module records those links against the correlation identifiers the
 * incident and evidence modules already use, and does three things the product
 * must not get wrong:
 *
 *   - **Deterministic order under out-of-order arrival and duplicates.** Links
 *     carry a position and a receipt-style logical clock; ordering is by
 *     position, then wall clock, then link id, so the same set of records
 *     produces the same chain no matter how it arrived. An exact replay is a
 *     no-op; a replay whose content changed is a finding, not a silent win.
 *   - **A missing link is a gap, never a splice.** A link that names a successor
 *     which is not in the chain produces an explicit `chain_gap`. The chain
 *     never quietly joins the neighbours, so "we have no evidence of the tool
 *     description" cannot be rendered as "the tool description was fine".
 *   - **One hashing scheme.** Tamper-evident binding reuses
 *     `evidence-receipt.ts` (`appendEvidenceReceipt` / `verifyEvidenceReceipt`)
 *     rather than introducing a second, divergent digest.
 */

import { createHash } from "node:crypto";

import {
	appendEvidenceReceipt,
	type EvidenceBinding,
	type EvidenceClock,
	type EvidenceHashContext,
	type EvidenceParseResult,
	type EvidenceReceiptV1,
	parseEvidenceReceipt,
	verifyEvidenceReceipt,
} from "./incidents/evidence-receipt.js";

export const CAUSAL_CHAIN_SCHEMA_VERSION = 1;

/** Causal order an agent turn is expected to follow. */
export const CAUSAL_CHAIN_ORDER = [
	"message",
	"retrieval",
	"tool_description",
	"tool_response",
	"authorization",
	"action",
	"side_effect",
	"intervention",
] as const;
type CausalLinkKind = (typeof CAUSAL_CHAIN_ORDER)[number];

/** Rank of a kind in the canonical order; lower runs earlier. */
export function causalKindRank(kind: CausalLinkKind): number {
	return CAUSAL_CHAIN_ORDER.indexOf(kind);
}

/**
 * Correlation identifiers, deliberately the same field names the incident
 * normalizer emits (`NormalizedSignal.session_id` / `agent_iid` / `connector`).
 * `handoffFromAgentIid` carries an agent-to-agent handoff: the receiving agent
 * records which agent handed the turn over, so a two-agent chain stays one chain
 * without inventing a new identity scheme.
 */
export interface CausalCorrelationIds {
	sessionId: string;
	agentIid: string;
	connector: string;
	incidentId: string;
	traceId: string;
	spanId: string;
	handoffFromAgentIid?: string;
}

export interface CausalChainLinkInput {
	linkId: string;
	kind: CausalLinkKind;
	/** Authoritative ordering key inside the chain. */
	position: number;
	/** Host wall clock, ISO-8601 UTC. Untrusted; a tie-breaker only. */
	wallClockUtc: string;
	correlation: CausalCorrelationIds;
	/** Causal predecessor this record names. Omitted means "start of chain". */
	previousLinkIds?: string[];
	/** Causal successor this record names. A name absent from the chain is a gap. */
	nextLinkIds?: string[];
	/** Redacted, bounded summary. Never a raw prompt, response or secret. */
	payloadSummary: string;
	severity: "info" | "warning" | "high" | "critical";
}

export interface CausalChainLink extends CausalChainLinkInput {
	/** Digest over the canonical link form; a rewrite changes it. */
	linkDigest: string;
	/** Receipt id when this link was bound to an evidence receipt. */
	receiptId: string | null;
}

export type CausalChainFindingCode =
	| "chain_gap"
	| "duplicate_link_conflict"
	| "link_digest_mismatch"
	| "position_conflict"
	| "link_unreadable"
	| "correlation_mismatch"
	| "cycle_detected"
	| "receipt_unavailable"
	| "receipt_not_intact";

export interface CausalChainFinding {
	code: CausalChainFindingCode;
	linkId?: string;
	/** Kind the gap refers to, when the finding is an absent expected kind. */
	missingKind?: CausalLinkKind;
	detail?: string;
}

export type CausalChainReceiptOutcome =
	| { status: "bound"; receipts: number; headReceiptId: string | null }
	| { status: "not_requested" }
	| { status: "unavailable"; reason: string };

export interface CausalChain {
	schemaVersion: typeof CAUSAL_CHAIN_SCHEMA_VERSION;
	correlation: CausalCorrelationIds;
	links: CausalChainLink[];
	/** Present only when the chain verified: the newest link, not a spliced one. */
	head: { linkId: string; linkDigest: string; position: number } | null;
	findings: CausalChainFinding[];
	duplicates: string[];
	/** Node kinds expected for this chain, used to detect a kind entirely absent. */
	expectedKinds: CausalLinkKind[];
	/** Kinds present in the chain. */
	observedKinds: CausalLinkKind[];
	/** Correlation ids that disagreed with the chain scope and were refused. */
	refused: string[];
	receipts: EvidenceReceiptV1[];
	receiptOutcome: CausalChainReceiptOutcome;
}

export interface CausalChainOptions extends EvidenceHashContext {
	/** Kinds this chain claims to cover; a kind with no link is reported. */
	expectedKinds?: readonly CausalLinkKind[];
	/**
	 * Evidence binding, so a decision can be traced to the build, policy, device,
	 * actor and incident that produced it. Omit to record links without receipts
	 * — the chain then says `not_requested` rather than pretending to be bound.
	 */
	binding?: EvidenceBinding;
	/** Logical-clock base, so a caller can continue a device's existing counter. */
	logicalCounterBase?: number;
}

const LINK_ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;
const KIND_SET = new Set<string>(CAUSAL_CHAIN_ORDER);
const SEVERITY_SET = new Set<string>(["info", "warning", "high", "critical"]);

function isIsoUtc(value: unknown): value is string {
	if (typeof value !== "string") return false;
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) && parsed > 0;
}

function sha256(input: string): string {
	return createHash("sha256").update(input).digest("hex");
}

/**
 * Canonical digest input for a link. Field order is fixed and every causal field
 * is included, so a link cannot be re-pointed at another position, successor,
 * correlation scope or payload without changing its digest.
 */
export function causalLinkDigestInput(link: CausalChainLinkInput): string {
	const c = link.correlation;
	return [
		"aidr.causal.link.v1",
		link.linkId,
		link.kind,
		String(causalKindRank(link.kind)),
		String(link.position),
		link.wallClockUtc,
		c.sessionId,
		c.agentIid,
		c.connector,
		c.incidentId,
		c.traceId,
		c.spanId,
		c.handoffFromAgentIid ?? "-",
		[...(link.previousLinkIds ?? [])].sort().join(","),
		[...(link.nextLinkIds ?? [])].sort().join(","),
		link.severity,
		link.payloadSummary,
	].join("\n");
}

export function causalLinkDigest(link: CausalChainLinkInput, context: EvidenceHashContext): string {
	return context.hash(causalLinkDigestInput(link));
}

function parseLink(
	value: unknown,
	context: EvidenceHashContext,
): { ok: true; value: CausalChainLinkInput } | { ok: false; error: string } {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return { ok: false, error: "not_an_object" };
	}
	const raw = value as Record<string, unknown>;
	if (typeof raw.linkId !== "string" || !LINK_ID.test(raw.linkId)) {
		return { ok: false, error: "invalid_link_id" };
	}
	if (typeof raw.kind !== "string" || !KIND_SET.has(raw.kind)) {
		return { ok: false, error: "invalid_link_kind" };
	}
	if (!Number.isSafeInteger(raw.position) || (raw.position as number) < 0) {
		return { ok: false, error: "invalid_position" };
	}
	if (!isIsoUtc(raw.wallClockUtc)) return { ok: false, error: "invalid_wall_clock" };
	if (!raw.correlation || typeof raw.correlation !== "object" || Array.isArray(raw.correlation)) {
		return { ok: false, error: "invalid_correlation" };
	}
	const correlationRaw = raw.correlation as Record<string, unknown>;
	const required = [
		"sessionId",
		"agentIid",
		"connector",
		"incidentId",
		"traceId",
		"spanId",
	] as const;
	for (const key of required) {
		if (typeof correlationRaw[key] !== "string" || !LINK_ID.test(correlationRaw[key] as string)) {
			return { ok: false, error: `invalid_correlation_${key}` };
		}
	}
	if (
		correlationRaw.handoffFromAgentIid !== undefined &&
		(typeof correlationRaw.handoffFromAgentIid !== "string" ||
			!LINK_ID.test(correlationRaw.handoffFromAgentIid))
	) {
		return { ok: false, error: "invalid_handoff_from" };
	}
	if (typeof raw.payloadSummary !== "string" || raw.payloadSummary.length > 4096) {
		return { ok: false, error: "invalid_payload_summary" };
	}
	if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(raw.payloadSummary)) {
		return { ok: false, error: "invalid_payload_summary" };
	}
	if (typeof raw.severity !== "string" || !SEVERITY_SET.has(raw.severity)) {
		return { ok: false, error: "invalid_severity" };
	}

	const parseLinkIds = (entry: unknown, label: string): string[] | string => {
		if (entry === undefined) return [];
		if (!Array.isArray(entry)) return `invalid_${label}`;
		const out: string[] = [];
		for (const item of entry) {
			if (typeof item !== "string" || !LINK_ID.test(item)) return `invalid_${label}`;
			if (item === raw.linkId) return `self_${label}`;
			if (!out.includes(item)) out.push(item);
		}
		return out.sort();
	};
	const previous = parseLinkIds(raw.previousLinkIds, "previous_link_ids");
	if (typeof previous === "string") return { ok: false, error: previous };
	const next = parseLinkIds(raw.nextLinkIds, "next_link_ids");
	if (typeof next === "string") return { ok: false, error: next };

	const correlation: CausalCorrelationIds = {
		sessionId: correlationRaw.sessionId as string,
		agentIid: correlationRaw.agentIid as string,
		connector: correlationRaw.connector as string,
		incidentId: correlationRaw.incidentId as string,
		traceId: correlationRaw.traceId as string,
		spanId: correlationRaw.spanId as string,
		...(correlationRaw.handoffFromAgentIid === undefined
			? {}
			: { handoffFromAgentIid: correlationRaw.handoffFromAgentIid as string }),
	};
	const link: CausalChainLinkInput = {
		linkId: raw.linkId,
		kind: raw.kind as CausalLinkKind,
		position: raw.position as number,
		wallClockUtc: new Date(Date.parse(raw.wallClockUtc)).toISOString(),
		correlation,
		...(previous.length === 0 ? {} : { previousLinkIds: previous }),
		...(next.length === 0 ? {} : { nextLinkIds: next }),
		payloadSummary: raw.payloadSummary,
		severity: raw.severity as CausalChainLinkInput["severity"],
	};
	// Fail closed on an unhashable link: a chain never holds a link whose digest
	// cannot be produced, because that link could never be verified later.
	try {
		void causalLinkDigest(link, context);
	} catch {
		return { ok: false, error: "hash_unavailable" };
	}
	return { ok: true, value: link };
}

function sameCorrelationScope(a: CausalCorrelationIds, b: CausalCorrelationIds): boolean {
	return (
		a.sessionId === b.sessionId &&
		a.agentIid === b.agentIid &&
		a.connector === b.connector &&
		a.incidentId === b.incidentId &&
		a.traceId === b.traceId &&
		a.spanId === b.spanId &&
		(a.handoffFromAgentIid ?? null) === (b.handoffFromAgentIid ?? null)
	);
}

function compareLinks(a: CausalChainLink, b: CausalChainLink): number {
	if (a.position !== b.position) return a.position - b.position;
	const aTime = Date.parse(a.wallClockUtc);
	const bTime = Date.parse(b.wallClockUtc);
	if (aTime !== bTime) return aTime < bTime ? -1 : 1;
	return a.linkId < b.linkId ? -1 : a.linkId > b.linkId ? 1 : 0;
}

function detectCycle(links: readonly CausalChainLink[]): string[] | null {
	const byId = new Map(links.map((link) => [link.linkId, link]));
	const state = new Map<string, 0 | 1 | 2>();
	let cycle: string[] | null = null;
	const visit = (linkId: string, path: string[]): void => {
		if (cycle) return;
		const current = state.get(linkId) ?? 0;
		if (current === 1) {
			cycle = [...path, linkId];
			return;
		}
		if (current === 2) return;
		state.set(linkId, 1);
		for (const successor of byId.get(linkId)?.nextLinkIds ?? []) {
			if (byId.has(successor)) visit(successor, [...path, linkId]);
			if (cycle) return;
		}
		state.set(linkId, 2);
	};
	for (const link of [...links].sort(compareLinks)) visit(link.linkId, []);
	return cycle;
}

/**
 * Receipt id for a link: a deterministic UUID-shaped id derived from the link
 * id, so a replayed link cannot mint a second receipt and the binding stays
 * stable across devices.
 */
export function causalLinkReceiptId(linkId: string): string {
	if (!LINK_ID.test(linkId)) throw new Error("causal_link_id_invalid");
	const digest = sha256(`aidr.causal.receipt-id.v1\n${linkId}`);
	return [
		digest.slice(0, 8),
		digest.slice(8, 12),
		`4${digest.slice(13, 16)}`,
		`8${digest.slice(17, 20)}`,
		digest.slice(20, 32),
	].join("-");
}

function sortFindings(findings: CausalChainFinding[]): CausalChainFinding[] {
	return [...findings].sort((a, b) => {
		if ((a.linkId ?? "") !== (b.linkId ?? "")) return (a.linkId ?? "") < (b.linkId ?? "") ? -1 : 1;
		if (a.code !== b.code) return a.code < b.code ? -1 : 1;
		const aDetail = a.detail ?? "";
		const bDetail = b.detail ?? "";
		return aDetail < bDetail ? -1 : aDetail > bDetail ? 1 : 0;
	});
}

/**
 * Record a causal chain from a batch of links.
 *
 * Ordering is deterministic (position, wall clock, link id) and a repeated
 * identical link is a no-op. A link naming a successor or predecessor that is
 * absent produces a `chain_gap` finding; when `expectedKinds` is given, a kind
 * with no link at all is also reported as a gap. Nothing is spliced.
 */
export function recordCausalChain(
	inputs: readonly unknown[],
	options: CausalChainOptions,
): CausalChain {
	const expectedKinds = (() => {
		const source = options.expectedKinds ?? CAUSAL_CHAIN_ORDER;
		const seen = new Set<CausalLinkKind>();
		for (const kind of source) {
			if (!KIND_SET.has(kind)) throw new Error("causal_expected_kind_invalid");
			seen.add(kind);
		}
		return [...seen].sort((a, b) => causalKindRank(a) - causalKindRank(b));
	})();

	const findings: CausalChainFinding[] = [];
	const duplicates: string[] = [];
	const refused: string[] = [];
	const byId = new Map<string, CausalChainLink>();
	const digestById = new Map<string, string>();
	const positionOwner = new Map<number, string>();
	let correlation: CausalCorrelationIds | null = null;

	for (const input of inputs) {
		const parsed = parseLink(input, options);
		if (!parsed.ok) {
			findings.push({ code: "link_unreadable", detail: parsed.error });
			continue;
		}
		const link = parsed.value;

		if (correlation === null) {
			correlation = link.correlation;
		} else if (!sameCorrelationScope(correlation, link.correlation)) {
			// A link from another session/agent/incident/trace is a different
			// chain; refusing it keeps the causal path honest about its scope.
			refused.push(link.linkId);
			findings.push({
				code: "correlation_mismatch",
				linkId: link.linkId,
				detail: "link_belongs_to_another_correlation_scope",
			});
			continue;
		}

		const digest = causalLinkDigest(link, options);
		const existingDigest = digestById.get(link.linkId);
		if (existingDigest !== undefined) {
			if (existingDigest === digest) {
				duplicates.push(link.linkId);
			} else {
				findings.push({
					code: "duplicate_link_conflict",
					linkId: link.linkId,
					detail: "link_id_reused_with_different_content",
				});
			}
			continue;
		}
		const owner = positionOwner.get(link.position);
		if (owner !== undefined && owner !== link.linkId) {
			findings.push({
				code: "position_conflict",
				linkId: link.linkId,
				detail: `position_${link.position}_claimed_by:${owner}`,
			});
		} else {
			positionOwner.set(link.position, link.linkId);
		}
		digestById.set(link.linkId, digest);
		byId.set(link.linkId, { ...link, linkDigest: digest, receiptId: null });
	}

	const links = [...byId.values()].sort(compareLinks);
	const linkIds = new Set(links.map((link) => link.linkId));

	// A named successor or predecessor that is not in the chain is the gap. The
	// chain is not re-joined: the finding names the absent link id and direction.
	for (const link of links) {
		for (const successor of link.nextLinkIds ?? []) {
			if (linkIds.has(successor)) continue;
			findings.push({
				code: "chain_gap",
				linkId: link.linkId,
				detail: `missing_successor:${successor}`,
			});
		}
		for (const predecessor of link.previousLinkIds ?? []) {
			if (linkIds.has(predecessor)) continue;
			findings.push({
				code: "chain_gap",
				linkId: link.linkId,
				detail: `missing_predecessor:${predecessor}`,
			});
		}
	}

	const observedKinds = CAUSAL_CHAIN_ORDER.filter((kind) =>
		links.some((link) => link.kind === kind),
	);
	for (const kind of expectedKinds) {
		if (observedKinds.includes(kind)) continue;
		findings.push({ code: "chain_gap", missingKind: kind, detail: `no_link_for_kind:${kind}` });
	}

	const cycle = detectCycle(links);
	if (cycle) findings.push({ code: "cycle_detected", detail: cycle.join("->") });

	// A position gap alone is not a gap: a step with no causal successor naming
	// it may legitimately not have happened. Only a named-but-absent link and an
	// absent expected kind are gaps, so a benign flow stays clean.
	const head = links[links.length - 1];
	const chain: CausalChain = {
		schemaVersion: CAUSAL_CHAIN_SCHEMA_VERSION,
		correlation:
			correlation ??
			({
				sessionId: "unknown",
				agentIid: "unknown",
				connector: "unknown",
				incidentId: "unknown",
				traceId: "unknown",
				spanId: "unknown",
			} as CausalCorrelationIds),
		links,
		head: head
			? { linkId: head.linkId, linkDigest: head.linkDigest, position: head.position }
			: null,
		findings: sortFindings(findings),
		duplicates: [...duplicates].sort(),
		expectedKinds,
		observedKinds,
		refused: [...refused].sort(),
		receipts: [],
		receiptOutcome: { status: "not_requested" },
	};

	const binding = options.binding;
	return binding ? bindCausalChainReceipts(chain, binding, options) : chain;
}

/**
 * Bind every link to an evidence receipt, using the incident module's
 * `appendEvidenceReceipt`. The link digest is inside the receipt payload, so
 * rewriting a link invalidates the receipt that documents it.
 */
function bindCausalChainReceipts(
	chain: CausalChain,
	binding: EvidenceBinding,
	options: CausalChainOptions,
): CausalChain {
	const receipts: EvidenceReceiptV1[] = [];
	const links = chain.links.map((link) => ({ ...link }));
	const base = options.logicalCounterBase ?? 0;
	const findings = [...chain.findings];
	for (let index = 0; index < links.length; index += 1) {
		const link = links[index];
		if (!link) continue;
		let receiptId: string;
		try {
			receiptId = causalLinkReceiptId(link.linkId);
		} catch {
			findings.push({
				code: "receipt_unavailable",
				linkId: link.linkId,
				detail: "receipt_id_unavailable",
			});
			continue;
		}
		const clock: EvidenceClock = {
			// The logical counter is authoritative and follows chain order, so a
			// host with a wrong wall clock still produces a verifiable order.
			wallClockUtc: link.wallClockUtc,
			logicalCounter: base + index,
			observedSkewMs: null,
		};
		const appended: EvidenceParseResult<EvidenceReceiptV1> = appendEvidenceReceipt(
			{
				receiptId,
				binding,
				clock,
				dataClass: "audit",
				payloadSummary: [
					`causal=${link.kind}`,
					`position=${link.position}`,
					`link=${link.linkId}`,
					`link_digest=${link.linkDigest}`,
				]
					.join(" ")
					.slice(0, 4096),
			},
			receipts[receipts.length - 1] ?? null,
			options,
		);
		if (!appended.ok) {
			findings.push({ code: "receipt_unavailable", linkId: link.linkId, detail: appended.error });
			continue;
		}
		link.receiptId = appended.value.receiptId;
		receipts.push(appended.value);
	}
	chain.links = links;
	chain.receipts = receipts;
	chain.findings = sortFindings(findings);
	const lastReceipt = receipts[receipts.length - 1];
	chain.receiptOutcome = {
		status: "bound",
		receipts: receipts.length,
		headReceiptId: lastReceipt ? lastReceipt.receiptId : null,
	};
	const head = chain.links[chain.links.length - 1];
	chain.head =
		head && receipts.length === chain.links.length
			? { linkId: head.linkId, linkDigest: head.linkDigest, position: head.position }
			: null;
	return chain;
}

export interface CausalChainVerification {
	valid: boolean;
	checkedLinks: number;
	checkedReceipts: number;
	findings: CausalChainFinding[];
	/** Receipt ids that verified, in chain order. */
	intactReceiptIds: string[];
	headReceiptHash: string | null;
}

/**
 * Verify one link and the receipt that documents it, appending every reason it
 * fails rather than stopping at the first.
 *
 * Returns the receipt id when the link is intact, so the caller can list the
 * verified receipts in chain order.
 */
function verifyCausalLink(
	link: CausalChainLink,
	receiptById: Map<string, unknown>,
	context: EvidenceHashContext,
	findings: CausalChainFinding[],
): string | null {
	const { linkDigest, receiptId, ...input } = link;
	let expected: string;
	try {
		expected = causalLinkDigest(input, context);
	} catch {
		findings.push({ code: "receipt_unavailable", linkId: link.linkId, detail: "hash_unavailable" });
		return null;
	}
	const digestMatches = expected === linkDigest;
	if (!digestMatches) {
		findings.push({
			code: "link_digest_mismatch",
			linkId: link.linkId,
			detail: "link_digest_mismatch",
		});
	}
	if (!receiptId) {
		findings.push({
			code: "receipt_unavailable",
			linkId: link.linkId,
			detail: "link_has_no_receipt",
		});
		return null;
	}
	const receipt = receiptById.get(receiptId);
	if (!receipt) {
		findings.push({ code: "receipt_unavailable", linkId: link.linkId, detail: "receipt_missing" });
		return null;
	}
	const parsed = parseEvidenceReceipt(receipt);
	if (!parsed.ok) {
		findings.push({ code: "receipt_unavailable", linkId: link.linkId, detail: parsed.error });
		return null;
	}
	const verification = verifyEvidenceReceipt(parsed.value, context);
	if (verification.status !== "intact") {
		findings.push({ code: "receipt_not_intact", linkId: link.linkId, detail: verification.reason });
		return null;
	}
	// The receipt must document *this* link. A rewritten link no longer matches
	// the digest its receipt attests, even though both were re-hashed.
	if (!digestMatches || !parsed.value.payloadSummary.includes(`link_digest=${linkDigest}`)) {
		findings.push({
			code: "receipt_not_intact",
			linkId: link.linkId,
			detail: "receipt_does_not_document_this_link",
		});
		return null;
	}
	return parsed.value.receiptId;
}

/**
 * Re-verify a recorded chain: every link's digest, every receipt's integrity,
 * and the link digest each receipt claims to document. Anything but fully intact
 * is `valid: false` with the reason named — an unverifiable chain is not
 * evidence.
 */
export function verifyCausalChainEvidence(
	chain: CausalChain,
	context: EvidenceHashContext,
): CausalChainVerification {
	const findings: CausalChainFinding[] = [];
	const intactReceiptIds: string[] = [];
	const receiptById = new Map<string, unknown>();
	for (const receipt of chain.receipts) receiptById.set(receipt.receiptId, receipt);
	const linkIds = new Set(chain.links.map((link) => link.linkId));
	const positions = new Map<number, string>();
	const observedKinds = new Set(chain.links.map((link) => link.kind));
	for (const link of chain.links) {
		for (const successor of link.nextLinkIds ?? []) {
			if (!linkIds.has(successor)) {
				findings.push({
					code: "chain_gap",
					linkId: link.linkId,
					detail: `missing_successor:${successor}`,
				});
			}
		}
		for (const predecessor of link.previousLinkIds ?? []) {
			if (!linkIds.has(predecessor)) {
				findings.push({
					code: "chain_gap",
					linkId: link.linkId,
					detail: `missing_predecessor:${predecessor}`,
				});
			}
		}
		const positionOwner = positions.get(link.position);
		if (positionOwner && positionOwner !== link.linkId) {
			findings.push({
				code: "position_conflict",
				linkId: link.linkId,
				detail: `position_${link.position}_claimed_by:${positionOwner}`,
			});
		} else {
			positions.set(link.position, link.linkId);
		}
	}
	for (const kind of chain.expectedKinds) {
		if (!observedKinds.has(kind)) {
			findings.push({ code: "chain_gap", missingKind: kind, detail: `no_link_for_kind:${kind}` });
		}
	}
	const cycle = detectCycle(chain.links);
	if (cycle) findings.push({ code: "cycle_detected", detail: cycle.join("->") });
	// Stored findings are evidence too: never upgrade a recorded refusal or gap
	// to valid merely because its links and receipts still hash correctly.
	findings.push(...chain.findings);

	for (const link of chain.links) {
		const intactId = verifyCausalLink(link, receiptById, context, findings);
		if (intactId !== null) intactReceiptIds.push(intactId);
	}

	// Chain continuity: receipt N must hash-point at receipt N-1.
	for (let index = 1; index < chain.receipts.length; index += 1) {
		const previous = chain.receipts[index - 1];
		const current = chain.receipts[index];
		if (!previous || !current) continue;
		if (current.previousHash !== previous.receiptHash) {
			findings.push({
				code: "receipt_not_intact",
				detail: `chain_link_mismatch:${current.receiptId}`,
			});
		}
	}

	const headReceipt = chain.receipts[chain.receipts.length - 1];
	return {
		valid: findings.length === 0,
		checkedLinks: chain.links.length,
		checkedReceipts: chain.receipts.length,
		findings: sortFindings(findings),
		intactReceiptIds,
		headReceiptHash: headReceipt ? headReceipt.receiptHash : null,
	};
}

/** Canonical JSON for a chain, so two equal records serialize identically. */
export function canonicalCausalChainJson(chain: CausalChain): string {
	return JSON.stringify({
		schemaVersion: chain.schemaVersion,
		correlation: chain.correlation,
		links: chain.links.map((link) => ({
			linkId: link.linkId,
			kind: link.kind,
			position: link.position,
			wallClockUtc: link.wallClockUtc,
			linkDigest: link.linkDigest,
			receiptId: link.receiptId,
			previousLinkIds: [...(link.previousLinkIds ?? [])].sort(),
			nextLinkIds: [...(link.nextLinkIds ?? [])].sort(),
			payloadSummary: link.payloadSummary,
			severity: link.severity,
			correlation: link.correlation,
		})),
		head: chain.head,
		findings: chain.findings,
		duplicates: chain.duplicates,
		expectedKinds: chain.expectedKinds,
		observedKinds: chain.observedKinds,
	});
}
